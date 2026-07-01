"""HTTP/3 backend via the bundled neqo-client (Firefox's real QUIC/h3 stack,
linked against the same NSS 3.126 as the TLS engine).

The body is retrieved with neqo-client's ``--output-dir`` (writing the response
to a file); the older ``--output-read-data`` only logs to stderr and never
reaches stdout, which is why earlier builds returned empty h3 bodies. Any failure
(missing binary, UDP/443 blocked, IdleTimeout, non-zero exit) raises, and the
caller silently falls back to HTTP/2 — so h3 can never break a request.

Status/headers are best-effort for now (a cdylib upgrade is planned); the body is
correct. Request bodies (POST/PUT) are not yet supported over this CLI path and
fall back to h2.
"""
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))

# neqo-client: bundled in the wheel (never_fox/_lib/), else the dev source tree.
_BIN_CANDS = [
    os.path.join(_HERE, "_lib", "neqo-client"),
    os.path.join(_HERE, "_lib", "neqo-client.exe"),
    os.path.join(_HERE, "..", "native", "neqo", "target", "release", "neqo-client"),
]
NEQO_BIN = next((p for p in _BIN_CANDS if os.path.exists(p)), _BIN_CANDS[0])


def _lib_dirs():
    """Directories holding the NSS/NSPR runtime the neqo binary links against."""
    cands = [
        os.path.join(_HERE, "_lib", "vendor"),          # wheel: bundled NSS 3.126
        os.path.join(_HERE, "_lib"),
        os.path.join(_HERE, "..", "native", "vendor"),  # dev: staged NSS
        "/opt/homebrew/opt/nss/lib", "/opt/homebrew/opt/nspr/lib",
    ]
    # dev: neqo's own NSS build output
    cands += glob.glob(os.path.join(
        _HERE, "..", "native", "neqo", "target", "release", "build",
        "nss-rs-*", "out", "dist", "Release", "lib"))
    return [os.path.abspath(p) for p in cands if os.path.isdir(p)]


def _env():
    env = dict(os.environ)
    dirs = _lib_dirs()
    if dirs:
        key = "DYLD_LIBRARY_PATH" if sys.platform == "darwin" else "LD_LIBRARY_PATH"
        env[key] = os.pathsep.join(dirs + ([env[key]] if env.get(key) else []))
    return env


def available():
    return os.path.exists(NEQO_BIN)


def _sniff_encoding(body):
    """neqo-client returns only the body, not the response headers, so we can't read
    Content-Encoding directly. Firefox-style `accept-encoding` is still sent, so the
    body may be compressed; sniff it so the Response can decode it. gzip/zstd have
    reliable magic bytes; a cleanly-UTF-8 body is treated as identity; otherwise try
    brotli then deflate. (Proper headers come with the planned cdylib upgrade.)"""
    if not body:
        return None
    if body[:2] == b"\x1f\x8b":
        return "gzip"
    if body[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    try:
        body.decode("utf-8")
        return None                                  # clean text -> identity
    except UnicodeDecodeError:
        pass
    try:
        import brotli
        brotli.decompress(body)
        return "br"
    except Exception:
        pass
    try:
        import zlib
        try:
            zlib.decompress(body)
        except zlib.error:
            zlib.decompress(body, -zlib.MAX_WBITS)
        return "deflate"
    except Exception:
        return None


_HDR_RE = re.compile(
    r'name:\s*"((?:[^"\\]|\\.)*)"\s*,\s*value:\s*(\[[^\]]*\]|"(?:[^"\\]|\\.)*")')


def _parse_response(stderr):
    """Recover the real (status, headers) from neqo-client's debug log. neqo logs the
    response headers at debug level:
        READ HEADERS[<sid>]: fin=<bool> [Header { name: ":status", value: ... }, ...]
    A Header's value is either a quoted string or a byte list (Vec<u8> Debug); handle
    both. Returns (status:int|None, headers:list[(name,value)]). None status => caller
    must fall back to h2 rather than inventing a status.

    NOTE: this parses a Rust {:?} debug format, so it is validated against a real
    neqo-client build (CI); until then a parse miss simply routes the request to h2."""
    if isinstance(stderr, (bytes, bytearray)):
        stderr = stderr.decode("utf-8", "replace")
    status, out = None, []
    for line in stderr.splitlines():
        if "READ HEADERS" not in line:
            continue
        line_status, line_headers = None, []
        for name, rawval in _HDR_RE.findall(line):
            name = name.encode().decode("unicode_escape").lower()
            if rawval.startswith("["):                       # value: [104, 105, ...] (bytes)
                try:
                    val = bytes(int(x) for x in rawval[1:-1].split(",") if x.strip()
                                ).decode("utf-8", "replace")
                except ValueError:
                    val = ""
            else:                                            # value: "..." (string)
                val = rawval[1:-1].encode().decode("unicode_escape")
            if name == ":status":
                try: line_status = int(val)
                except ValueError: pass
            elif not name.startswith(":"):
                line_headers.append((name, val))
        if line_status is not None and line_status >= 200:   # final response (skip 1xx)
            status, out = line_status, line_headers
    return status, out


def request(method, url, headers, body=b"", timeout=15):
    """One HTTP/3 request via neqo. Returns the REAL (status, headers, body) or raises
    (the caller then falls back to h2). We no longer fabricate a 200: a response whose
    status/headers we cannot read is treated as an h3 failure so status codes and
    Set-Cookie are never silently lost."""
    if not available():
        raise RuntimeError("neqo-client not bundled")
    if body:                                              # CLI path can't upload a body yet
        raise RuntimeError("h3 request body not supported; fall back to h2")

    if not os.access(NEQO_BIN, os.X_OK):                  # pip drops the exec bit on data files
        try:
            os.chmod(NEQO_BIN, 0o755)
        except OSError:
            pass

    idle = max(2, min(int(timeout) - 1, 8))              # give up quickly on a dead UDP path
    outdir = tempfile.mkdtemp(prefix="nf_h3_")
    try:
        args = [NEQO_BIN, "--idle", str(idle), "--output-dir", outdir, "-m", method.upper()]
        for k, v in (headers or []):
            if str(k).startswith(":"):                   # neqo emits the pseudo-headers itself
                continue
            args += ["-H", f"{k}: {v}"]
        args.append(url)

        env = _env()
        # ask neqo to log the response headers so we can read the true status + Set-Cookie
        env.setdefault("RUST_LOG", "neqo_bin=debug,neqo_http3=info,neqo_transport=info")
        proc = subprocess.run(args, capture_output=True, timeout=timeout, env=env)

        status, rh = _parse_response(proc.stderr)
        if status is None:                               # unknown status -> fall back to h2
            tail = proc.stderr[-200:] if proc.stderr else b""
            raise RuntimeError(f"h3: could not read response status (exit={proc.returncode}): {tail!r}")

        # neqo writes the body to a file named after the URL path (possibly nested).
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(outdir) for f in fs]
        data = b""
        if files:
            with open(max(files, key=os.path.getmtime), "rb") as fh:
                data = fh.read()

        if data and not any(k == "content-encoding" for k, _ in rh):
            enc = _sniff_encoding(data)                  # headers lacked it -> sniff the body
            if enc:
                rh.append(("content-encoding", enc))
        return status, rh, data
    finally:
        shutil.rmtree(outdir, ignore_errors=True)

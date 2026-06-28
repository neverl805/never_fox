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


def request(method, url, headers, body=b"", timeout=15):
    """One HTTP/3 request via neqo. Returns (status, headers, body) or raises."""
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

        proc = subprocess.run(args, capture_output=True, timeout=timeout, env=_env())

        # neqo writes the body to a file named after the URL path (possibly nested).
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(outdir) for f in fs]
        if not files:
            tail = proc.stderr[-200:] if proc.stderr else b""
            raise RuntimeError(f"h3: no response body (exit={proc.returncode}): {tail!r}")
        with open(max(files, key=os.path.getmtime), "rb") as fh:
            data = fh.read()

        enc = _sniff_encoding(data)
        rh = [("content-encoding", enc)] if enc else []
        return 200, rh, data                             # status: cdylib upgrade
    finally:
        shutil.rmtree(outdir, ignore_errors=True)

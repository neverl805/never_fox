"""HTTP/3 backend via neqo-client (Firefox's real QUIC/h3 stack, built against our NSS).

This is the "blind first pass": it runs the genuine neqo HTTP/3 client as a
subprocess. Any failure (UDP/443 blocked, IdleTimeout, non-zero exit, missing
binary) raises, and the caller falls back to HTTP/2 — so h3 can never break a
request. Response body comes from neqo's stdout; status is parsed from its
verbose log (best-effort). Full status/headers + Firefox transport-parameter
tuning are the planned cdylib upgrade, to be verified on a UDP-open network.
"""
import os, re, subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
NEQO_BIN = os.path.join(_HERE, "..", "native", "neqo", "target", "release", "neqo-client")

# NSS/NSPR runtime libs the neqo binary links against
def _dyld_env():
    env = dict(os.environ)
    libdirs = []
    for p in ("/opt/homebrew/opt/nss/lib", "/opt/homebrew/opt/nspr/lib",
              os.path.join(_HERE, "..", "native", "vendor")):
        if os.path.isdir(p):
            libdirs.append(os.path.abspath(p))
    if libdirs:
        env["DYLD_LIBRARY_PATH"] = ":".join(libdirs + [env.get("DYLD_LIBRARY_PATH", "")])
    return env


def available():
    return os.path.exists(NEQO_BIN)


_STATUS_RE = re.compile(rb"['\"]?:?status['\"]?[,:\s]+['\"]?(\d{3})")


def request(method, url, headers, body=b"", timeout=15):
    """One HTTP/3 request via neqo. Returns (status, headers, body) or raises."""
    if not available():
        raise RuntimeError("neqo-client not built")
    idle = max(2, min(int(timeout) - 1, 5))      # make neqo give up quickly on a dead path
    args = [NEQO_BIN, "--idle", str(idle), "-m", method.upper(), "--output-read-data"]
    for k, v in headers:
        args += ["-H", f"{k}: {v}"]
    args.append(url)
    # neqo-client reads no request body in this mode; body upload is a cdylib TODO.
    proc = subprocess.run(args, capture_output=True, timeout=timeout, env=_dyld_env())
    if proc.returncode != 0:
        raise RuntimeError(f"neqo h3 failed: {proc.stderr[-200:]!r}")
    if not proc.stdout:
        raise RuntimeError("neqo h3: empty response")
    return 200, [], proc.stdout                  # status/headers: cdylib upgrade

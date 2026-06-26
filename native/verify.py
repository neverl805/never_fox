#!/usr/bin/env python3
"""CI fingerprint gate: build a ClientHello with the freshly-built engine and
assert it is byte-for-byte Firefox 152. Exits non-zero on any drift (e.g. a
platform's NSS version produces different bytes), so CI fails loudly.

Cross-platform: uses the local ClientHello sink + the native engine, all Python.
"""
import os, sys, json, socket, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "harness"))

EXPECT = {
    "ja3": "6447ab086255d194909d4013b1a89e87",
    "ja4": "t13d1617h2_86a278354501_3cbfd9057e0d",
    "ech_len": 281,
}


def _wait_port(port, deadline=8):
    t0 = time.time()
    while time.time() - t0 < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    port = int(os.environ.get("FXTLS_VERIFY_PORT", "8479"))
    out = os.path.join(HERE, "_verify_ch.json")
    if os.path.exists(out):
        os.remove(out)
    sink = subprocess.Popen([sys.executable, os.path.join(ROOT, "harness", "hello_sink.py"),
                             "--out", out, "--label", "verify", "--port", str(port),
                             "--count", "1", "--timeout", "15"])
    if not _wait_port(port):
        sink.terminate(); sys.exit("sink did not open")

    # load the ctypes binding directly (no package __init__ -> no hpack/etc. needed)
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_fxtls_native", os.path.join(ROOT, "never_fox", "_native.py"))
    _native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_native)
    try:
        _native.Transport("localhost", port, 6, verify=False)   # sends the ClientHello
    except Exception:
        pass                                                    # sink closes -> handshake error, expected
    sink.wait(timeout=20)

    if not os.path.exists(out):
        sys.exit("FAIL: engine produced no ClientHello")
    p = json.load(open(out))
    from hello_sink import parse_client_hello
    rp = parse_client_hello(bytes.fromhex(p["raw_hex"]))
    ech = rp["_offsets"].get("ech", [])
    got = {"ja3": p["ja3"], "ja4": p["ja4"], "ech_len": (ech[0][1] if ech else None)}
    os.remove(out)

    ok = True
    for k, exp in EXPECT.items():
        mark = "OK" if got[k] == exp else "MISMATCH"
        if got[k] != exp:
            ok = False
        print(f"  {k:8} = {got[k]}   (expect {exp})  [{mark}]")
    print("\n✅ engine fingerprint == Firefox 152" if ok
          else "\n❌ FINGERPRINT DRIFT — this platform's NSS does not match Firefox 152")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

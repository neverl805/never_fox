#!/usr/bin/env python3
"""CI fingerprint gate — exhaustive low-level handshake check.

Builds a ClientHello with the freshly-built engine and compares it to the
authoritative Firefox 152 reference (native/firefox152_reference.json), field by
field AND byte for byte (random / session_id / key_share keys / ECH payload
masked, since those are legitimately per-connection). Any drift fails CI loudly.
"""
import os, sys, json, socket, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "harness"))

REF = json.load(open(os.path.join(HERE, "firefox152_reference.json")))

# field-by-field assertions over the whole ClientHello
FIELDS = ["ja3", "ja3_nogrease", "ja4", "legacy_version", "session_id_len",
          "cipher_suites", "extensions", "supported_groups", "key_share_groups",
          "signature_algorithms", "supported_versions", "ec_point_formats", "alpn",
          "psk_key_exchange_modes", "record_size_limit", "cert_compression_algs", "ech_len"]


def _wait_port(port, deadline=8):
    t0 = time.time()
    while time.time() - t0 < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _capture():
    port = int(os.environ.get("FXTLS_VERIFY_PORT", "8479"))
    out = os.path.join(HERE, "_verify_ch.json")
    if os.path.exists(out):
        os.remove(out)
    sink = subprocess.Popen([sys.executable, os.path.join(ROOT, "harness", "hello_sink.py"),
                             "--out", out, "--label", "verify", "--port", str(port),
                             "--count", "1", "--timeout", "15"])
    if not _wait_port(port):
        sink.terminate(); sys.exit("sink did not open")
    import importlib.util                              # load _native without the package (no hpack)
    spec = importlib.util.spec_from_file_location(
        "_fxtls_native", os.path.join(ROOT, "never_fox", "_native.py"))
    nat = importlib.util.module_from_spec(spec); spec.loader.exec_module(nat)
    err = None
    try:
        nat.Transport("localhost", port, 6, verify=False)
    except Exception as e:
        err = e                                          # normal (sink closes) OR a real init failure
    sink.wait(timeout=20)
    if not os.path.exists(out):
        try:
            code = nat._lib.fxtls_last_error()
            name = (nat._lib.fxtls_last_error_name() or b"").decode()
            stage = (nat._lib.fxtls_last_stage() or b"").decode()
            roots = nat._lib.fxtls_have_roots()
            print(f"  failed at stage: {stage} | NSS error: {code} ({name}) | have_roots={roots}")
            try:                                         # which NSS libs are actually loaded?
                paths = set()
                for ln in open("/proc/self/maps"):
                    p = ln.split()[-1] if len(ln.split()) >= 6 else ""
                    if any(t in p for t in ("libssl3", "libnss3", "libnssutil3",
                                            "libsoftokn3", "libfreebl3", "libnspr4")):
                        paths.add(p)
                for p in sorted(paths):
                    print(f"    loaded: {p}")
            except OSError:
                pass
        except Exception as e:
            print(f"  (could not read NSS error: {e!r})")
        sys.exit(f"FAIL: engine produced no ClientHello (Transport error: {err!r})")
    p = json.load(open(out)); os.remove(out)
    return p


def main():
    p = _capture()
    from hello_sink import parse_client_hello, normalized_hex
    rp = parse_client_hello(bytes.fromhex(p["raw_hex"]))
    d = rp["details"]
    got = {
        "ja3": rp["ja3"], "ja3_nogrease": rp["ja3_nogrease"], "ja4": rp["ja4"],
        "legacy_version": rp["legacy_version"],
        "session_id_len": rp["_offsets"]["session_id"][1],
        "cipher_suites": rp["cipher_suites"], "extensions": rp["extensions"],
        "supported_groups": d.get("supported_groups"),
        "key_share_groups": d.get("key_share_groups"),
        "signature_algorithms": d.get("signature_algorithms"),
        "supported_versions": d.get("supported_versions"),
        "ec_point_formats": d.get("ec_point_formats"), "alpn": d.get("alpn"),
        "psk_key_exchange_modes": d.get("psk_key_exchange_modes"),
        "record_size_limit": d.get("record_size_limit"),
        "cert_compression_algs": d.get("cert_compression_algs"),
        "ech_len": rp["_offsets"]["ech"][0][1] if rp["_offsets"].get("ech") else None,
    }
    ok = True
    print("== ClientHello field-by-field vs Firefox 152 ==")
    for f in FIELDS:
        match = REF.get(f) == got.get(f)
        ok &= match
        print(f"  [{'OK' if match else 'FAIL'}] {f}")
        if not match:
            print(f"        expect: {REF.get(f)}")
            print(f"        got   : {got.get(f)}")

    print("== structural bytes (random/session_id/key_share/ECH masked) ==")
    a, b = REF["normalized_hex"], normalized_hex(rp)
    nb = a == b
    ok &= nb
    print(f"  [{'OK' if nb else 'FAIL'}] normalized ClientHello: {len(b)//2}B (FF152 {len(a)//2}B)")
    if not nb:
        i = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]), min(len(a), len(b)))
        lo = max(0, i - 8)
        print(f"        first diff at byte {i//2}: ff…{a[lo:i+16]}  got…{b[lo:i+16]}")

    print("\nPASS: engine ClientHello == Firefox 152 (all fields + structural bytes)" if ok
          else "\nFAIL: handshake drift -- this platform's NSS does not match Firefox 152")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

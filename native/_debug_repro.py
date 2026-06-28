"""Reproduce the Windows "peer close -> retry/reconnect segfaults" crash on CI
(can't be reproduced on macOS). Uses the Session pool + retry path (the tester's
actual crash path: _get_conn / _reap / retry), NOT a bare H2Connection.

Local TLS+h2 server completes the handshake, reads the request, then closes the
connection (so the client's write succeeds and its reader sees EOF -> a clean
ConnectionError "connection closed by peer", matching the report). Then:
  - Session(retries=2).get  -> attempt0 closed, internal retry reconnects  <- crash point
  - Session(retries=1) x3   -> get0 closed clean, get1 reconnects           <- crash point
Run with FXTLS_DEBUG=1; the last "[fxtls] ..." line before the crash pinpoints the
dying native call. Exit 0 = clean; large/139 = segfault.
"""
import os, sys, ssl, socket, struct, threading, time, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
MODE = os.environ.get("FXTLS_REPRO_MODE", "fin")        # 'fin' or 'rst'


def _make_cert():
    d = tempfile.mkdtemp()
    crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                    "-out", crt, "-days", "1", "-nodes", "-subj", "/CN=localhost", "-batch"],
                   check=True, capture_output=True)
    return crt, key


def _server(port, crt, key, ready):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(16); ready.set()
    while True:
        conn, _ = srv.accept()
        try:
            ss = ctx.wrap_socket(conn, server_side=True)   # complete the TLS handshake
            ss.settimeout(2)
            try: ss.recv(65536)                            # read the request (lets client's write finish)
            except Exception: pass
            if MODE == "rst":
                ss.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            ss.close()                                     # peer closes -> client reader sees EOF
        except Exception:
            pass


def main():
    # Point this at YOUR crashing target on a machine where it reproduces (real
    # cert validation + real/GFW resets), e.g.:
    #   FXTLS_DEBUG=1 FXTLS_REPRO_URL=https://httpbin.org/get python native/_debug_repro.py
    # With no URL it uses a local self-signed server (verify off) for CI.
    url = os.environ.get("FXTLS_REPRO_URL")
    verify = bool(url)                                   # real target -> verify=True (matches the report)
    if not url:
        crt, key = os.environ.get("FXTLS_REPRO_CERT"), os.environ.get("FXTLS_REPRO_KEY")
        if not crt:
            crt, key = _make_cert()
        port = 9443
        ready = threading.Event()
        threading.Thread(target=_server, args=(port, crt, key, ready), daemon=True).start()
        ready.wait(5); time.sleep(0.3)
        url = f"https://localhost:{port}/"
    import never_fox as nf
    print(f"target={url} verify={verify} mode={MODE}", flush=True)

    print(f"=== A: Session(retries=2).get (internal retry -> reconnect) ===", flush=True)
    s = nf.Session(verify=verify, retries=2)
    try: s.get(url, timeout=5)
    except Exception as e: print(f"  A raised {type(e).__name__}", flush=True)
    print("  A survived the retry-reconnect", flush=True)
    s.close()

    print("=== B: Session(retries=1) x3 sequential gets ===", flush=True)
    s2 = nf.Session(verify=verify, retries=1)
    for i in range(3):
        try: s2.get(url, timeout=5)
        except Exception as e: print(f"  B get{i} raised {type(e).__name__}", flush=True)
        print(f"  B get{i} survived", flush=True)
    s2.close()

    print("DONE no crash", flush=True)


if __name__ == "__main__":
    main()

"""Reproduce the Windows "peer RST -> next fxtls_connect segfaults" crash, with
FXTLS_DEBUG traces, on CI (since it can't be reproduced on macOS).

Starts a local TLS+h2 server that RSTs right after reading the request, then runs:
  req0: connect + request  -> peer RST (a clean ConnectionError is expected)
  req1: a fresh fxtls_connect -> this is where Windows faults (0xC0000005)
Run with FXTLS_DEBUG=1; the last "[fxtls] ..." line before the crash pinpoints the
exact native step that dies. Exit code 0 = no crash; large/negative = segfault.
"""
import os, sys, ssl, socket, struct, threading, time, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _make_cert():
    d = tempfile.mkdtemp()
    crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                    "-out", crt, "-days", "1", "-nodes", "-subj", "/CN=localhost", "-batch"],
                   check=True, capture_output=True)
    return crt, key


def _rst_server(port, crt, key, ready):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(8); ready.set()
    while True:
        conn, _ = srv.accept()
        try:
            ss = ctx.wrap_socket(conn, server_side=True)
            try: ss.recv(4096)
            except Exception: pass
            ss.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # RST on close
            ss.close()
        except Exception:
            pass


def main():
    crt, key = os.environ.get("FXTLS_REPRO_CERT"), os.environ.get("FXTLS_REPRO_KEY")
    if not crt:
        crt, key = _make_cert()
    port = 9443
    ready = threading.Event()
    threading.Thread(target=_rst_server, args=(port, crt, key, ready), daemon=True).start()
    ready.wait(5); time.sleep(0.3)

    from never_fox import _native, h2conn
    from never_fox.client import DEFAULT_HEADERS
    for i in range(3):
        print(f"=== req{i}: connect ===", flush=True)
        tp = _native.Transport("localhost", port, 8, False, None)
        c = h2conn.H2Connection(tp); c.acquire()
        try:
            c.request("GET", "/", "localhost", DEFAULT_HEADERS, b"", timeout=5)
        except Exception as e:
            print(f"  req{i} raised {type(e).__name__}", flush=True)
        c.close()
        print(f"  req{i} done (peer_eof={getattr(tp, '_peer_eof', None)})", flush=True)
    print("DONE no crash", flush=True)


if __name__ == "__main__":
    main()

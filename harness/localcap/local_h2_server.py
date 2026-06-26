#!/usr/bin/env python3
"""Local HTTPS/HTTP-2 capture server.

Terminates TLS with a locally-trusted cert (so a real Firefox completes the
handshake) while ALSO capturing the raw ClientHello bytes via MemoryBIO. Then
reads the HTTP/2 client flight (SETTINGS / WINDOW_UPDATE / PRIORITY / HEADERS)
and HPACK-decodes the full header list. Writes one JSON record describing the
COMPLETE handshake + h2 + headers, so Firefox and fxreq can be diffed end to end.
"""
import argparse, json, os, ssl, struct, socket, sys
from hpack import Decoder

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))           # harness/
from hello_sink import parse_client_hello           # reuse TLS ClientHello parser

CERTS = os.path.join(HERE, "certs")

# ---- HTTP/2 ----
DATA, HEADERS, PRIORITY, RST, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = 0,1,2,3,4,6,7,8,9
SETTING_NAMES = {1:"HEADER_TABLE_SIZE",2:"ENABLE_PUSH",3:"MAX_CONCURRENT_STREAMS",
                 4:"INITIAL_WINDOW_SIZE",5:"MAX_FRAME_SIZE",6:"MAX_HEADER_LIST_SIZE"}
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def read_full_record(sock):
    """Read exactly one TLS record (used to grab the whole ClientHello)."""
    hdr = b""
    while len(hdr) < 5:
        c = sock.recv(5 - len(hdr))
        if not c: return None
        hdr += c
    ln = (hdr[3] << 8) | hdr[4]
    body = b""
    while len(body) < ln:
        c = sock.recv(ln - len(body))
        if not c: return None
        body += c
    return hdr + body


def clienthello_handshake(record_bytes):
    """Extract the ClientHello handshake message from TLS record bytes."""
    # record: type(1) ver(2) len(2) | handshake...
    return record_bytes[5:]


class TlsConn:
    """Decrypted I/O over an ssl.SSLObject driven with MemoryBIOs."""
    def __init__(self, sock, tls, inb, outb):
        self.sock, self.tls, self.inb, self.outb = sock, tls, inb, outb
    def _flush(self):
        d = self.outb.read()
        if d: self.sock.sendall(d)
    def recvn(self, n):
        out = b""
        while len(out) < n:
            try:
                d = self.tls.read(n - len(out))
                if not d: break
                out += d
            except ssl.SSLWantReadError:
                self._flush()
                more = self.sock.recv(65535)
                if not more: break
                self.inb.write(more)
        return out
    def write(self, data):
        self.tls.write(data); self._flush()


def drive_handshake(sock, tls, inb, outb, initial):
    inb.write(initial)
    while True:
        try:
            tls.do_handshake()
            d = outb.read()
            if d: sock.sendall(d)
            return
        except ssl.SSLWantReadError:
            d = outb.read()
            if d: sock.sendall(d)
            more = sock.recv(65535)
            if not more: raise ConnectionError("eof during handshake")
            inb.write(more)


def read_h2_request(tc):
    """Read client preface + frames until the request HEADERS; return the record."""
    pre = tc.recvn(len(PREFACE))
    rec = {"preface_ok": pre == PREFACE, "settings": [], "settings_order": [],
           "window_update": None, "priority_frames": [], "pseudo_header_order": [],
           "headers": []}
    dec = Decoder(); dec.max_allowed_table_size = 65536
    hbuf = bytearray(); hend = False
    while True:
        hdr = tc.recvn(9)
        if len(hdr) < 9: break
        length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
        ftype, flags = hdr[3], hdr[4]
        sid = struct.unpack(">I", hdr[5:9])[0] & 0x7fffffff
        payload = tc.recvn(length) if length else b""
        if ftype == SETTINGS and not (flags & 0x1):
            for i in range(0, len(payload), 6):
                k = (payload[i] << 8) | payload[i+1]
                v = struct.unpack(">I", payload[i+2:i+6])[0]
                rec["settings"].append([SETTING_NAMES.get(k, k), v])
                rec["settings_order"].append(k)
        elif ftype == WINDOW_UPDATE and sid == 0:
            rec["window_update"] = struct.unpack(">I", payload)[0] & 0x7fffffff
        elif ftype == PRIORITY:
            dep = struct.unpack(">I", payload[0:4])[0]
            rec["priority_frames"].append({"stream": sid, "excl": dep >> 31,
                                           "dep": dep & 0x7fffffff, "weight": payload[4]})
        elif ftype == HEADERS:
            # capture stream-level priority embedded in HEADERS (PRIORITY flag 0x20)
            p = payload
            if flags & 0x20:
                dep = struct.unpack(">I", p[0:4])[0]
                rec["priority_frames"].append({"stream": sid, "excl": dep >> 31,
                                               "dep": dep & 0x7fffffff, "weight": p[4], "in_headers": True})
                p = p[5:]
            hbuf += p; hend = bool(flags & 0x1)
            if flags & 0x4:  # END_HEADERS
                hl = dec.decode(bytes(hbuf))
                rec["headers"] = [[n, v] for n, v in hl]
                rec["pseudo_header_order"] = [n[1:] for n, v in hl if n.startswith(":")]
                # akamai-style h2 fingerprint:  id:val;...|window|#priority|m,p,a,s
                ssraw = ";".join(f"{rec['settings_order'][i]}:{rec['settings'][i][1]}"
                                 for i in range(len(rec["settings"])))
                pseudo = ",".join(name[0] for name in rec["pseudo_header_order"])
                rec["akamai_fingerprint"] = f"{ssraw}|{rec['window_update'] or 0}|" \
                    f"{len(rec['priority_frames'])}|{pseudo}"
                break
    return rec


def handle(sock):
    initial = read_full_record(sock)
    if not initial or initial[0] != 0x16:
        return None
    ch = parse_client_hello(clienthello_handshake(initial))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERTS, "srv.crt"), os.path.join(CERTS, "srv.key"))
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(inb, outb, server_side=True)
    drive_handshake(sock, tls, inb, outb, initial)
    alpn = tls.selected_alpn_protocol()
    tc = TlsConn(sock, tls, inb, outb)

    out = {"alpn": alpn,
           "tls": {"ja3": ch["ja3"], "ja4": ch["ja4"],
                   "cipher_suites": ch["cipher_suites"], "extensions": ch["extensions"],
                   "details": ch["details"], "raw_hex": ch["raw_hex"]}}
    if alpn == "h2":
        # minimal server SETTINGS so the client proceeds, then read its flight
        tc.write(struct.pack(">I", 0)[1:] + bytes([SETTINGS, 0]) + struct.pack(">I", 0))
        out["http2"] = read_h2_request(tc)
        # respond 200 so the client finishes cleanly
        enc_resp = b""
        from hpack import Encoder
        block = Encoder().encode([(":status", "200"), ("content-length", "2")])
        sid = 1
        out_h = struct.pack(">I", len(block))[1:] + bytes([HEADERS, 0x4]) + struct.pack(">I", sid)
        out_d = struct.pack(">I", 2)[1:] + bytes([DATA, 0x1]) + struct.pack(">I", sid) + b"ok"
        try: tc.write(out_h + block + out_d)
        except Exception: pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--label", default="client")
    ap.add_argument("--timeout", type=float, default=30)
    a = ap.parse_args()
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except OSError: pass
    s.bind(("::", a.port)); s.listen(8); s.settimeout(a.timeout)
    print(f"[h2cap:{a.label}] https://localhost:{a.port}/  waiting...", flush=True)
    while True:
        try: conn, addr = s.accept()
        except socket.timeout:
            print(f"[h2cap:{a.label}] timeout, no capture"); sys.exit(2)
        conn.settimeout(10)
        try:
            rec = handle(conn)
            if rec:
                rec["label"] = a.label; rec["peer"] = str(addr[0])
                json.dump(rec, open(a.out, "w"), indent=2)
                print(f"[h2cap:{a.label}] captured: alpn={rec['alpn']} "
                      f"ja4={rec['tls']['ja4']} "
                      f"h2={'akamai_fingerprint' in rec.get('http2', {})}", flush=True)
                if rec.get("alpn") == "h2":
                    s.close(); return
        except Exception as e:
            print(f"[h2cap:{a.label}] error: {type(e).__name__}: {e}", flush=True)
        finally:
            try: conn.close()
            except OSError: pass


if __name__ == "__main__":
    main()

"""HTTP/1.1 over the fxtls transport (used when ALPN negotiates http/1.1).
Handles content-length, chunked transfer-encoding, and close-delimited bodies."""


class _Reader:
    def __init__(self, tp):
        self.tp = tp
        self.buf = bytearray()

    def _fill(self):
        d = self.tp.recv(65536)
        if not d:
            return False
        self.buf += d
        return True

    def readline(self):
        while b"\r\n" not in self.buf:
            if not self._fill():
                line = bytes(self.buf); self.buf = bytearray(); return line
        i = self.buf.find(b"\r\n")
        line = bytes(self.buf[:i]); del self.buf[:i + 2]
        return line

    def readexact(self, n):
        while len(self.buf) < n:
            if not self._fill():
                break
        d = bytes(self.buf[:n]); del self.buf[:n]
        return d

    def readall(self):
        while self._fill():
            pass
        d = bytes(self.buf); self.buf = bytearray()
        return d


def request(tp, method, path, authority, headers, body=b""):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {authority}"]
    have = {k.lower() for k, _ in headers}
    for k, v in headers:
        lines.append(f"{k}: {v}")
    if "connection" not in have:
        lines.append("Connection: keep-alive")
    if body and "content-length" not in have:
        lines.append(f"Content-Length: {len(body)}")
    tp.write(("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b""))

    r = _Reader(tp)
    status = int(r.readline().split(b" ")[1])
    resp_headers = []
    while True:
        line = r.readline()
        if not line:
            break
        k, _, v = line.partition(b":")
        resp_headers.append((k.decode("latin1").strip().lower(), v.decode("latin1").strip()))
    hd = {k: v for k, v in resp_headers}

    te = hd.get("transfer-encoding", "").lower()
    if "chunked" in te:
        out = bytearray()
        while True:
            size = int(r.readline().split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while r.readline():       # consume trailers until blank line
                    pass
                break
            out += r.readexact(size)
            r.readexact(2)                # CRLF after each chunk
        return status, resp_headers, bytes(out)
    if "content-length" in hd:
        return status, resp_headers, r.readexact(int(hd["content-length"]))
    return status, resp_headers, r.readall()   # close-delimited

"""ctypes binding to the real-NSS (Firefox 152) TLS transport (libfxtls).
Binary-safe read/write (h2 frames contain NUL bytes, so we never use c_char_p)."""
import ctypes, os, sys, base64

_LIBNAME = {"darwin": "libfxtls.dylib"}.get(sys.platform, "libfxtls.dll" if os.name == "nt" else "libfxtls.so")
_HERE = os.path.dirname(os.path.abspath(__file__))
_CANDS = [os.path.join(_HERE, "_lib"),                                  # installed wheel layout
          os.path.abspath(os.path.join(_HERE, "..", "native"))]        # source-tree layout
_NATIVE = next((d for d in _CANDS if os.path.exists(os.path.join(d, _LIBNAME))), _CANDS[0])
_LIBPATH = os.path.join(_NATIVE, _LIBNAME)
if os.name == "nt":                              # let the loader find bundled NSS DLLs
    for _d in (_NATIVE, os.path.join(_NATIVE, "vendor")):
        if os.path.isdir(_d):
            try: os.add_dll_directory(_d)
            except (AttributeError, OSError): pass
_lib = ctypes.CDLL(_LIBPATH)
_lib.fxtls_connect.restype  = ctypes.c_void_p
_lib.fxtls_connect.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
_lib.fxtls_connect_proxy.restype  = ctypes.c_void_p
_lib.fxtls_connect_proxy.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                                     ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
_lib.fxtls_connect_socks5.restype  = ctypes.c_void_p
_lib.fxtls_connect_socks5.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                                      ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
_lib.fxtls_have_roots.restype = ctypes.c_int
_lib.fxtls_alpn.argtypes    = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
_lib.fxtls_write.argtypes   = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
_lib.fxtls_read.argtypes    = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
_lib.fxtls_shutdown.argtypes = [ctypes.c_void_p]
_lib.fxtls_close.argtypes   = [ctypes.c_void_p]


class Transport:
    """A genuine-Firefox-152 TLS connection to one host:port."""
    def __init__(self, host, port=443, timeout=15, verify=True, proxy=None):
        self.host = host
        self._stop = False
        if proxy:                                # (scheme, host, port, user, pass)
            scheme, ph, pp, user, pw = proxy
            if scheme.startswith("socks"):
                self.ctx = _lib.fxtls_connect_socks5(
                    ph.encode(), int(pp), host.encode(), int(port),
                    (user or "").encode(), (pw or "").encode(), int(timeout), 1 if verify else 0)
            else:
                auth = base64.b64encode(f"{user}:{pw}".encode()).decode() if user else ""
                self.ctx = _lib.fxtls_connect_proxy(
                    ph.encode(), int(pp), host.encode(), int(port),
                    auth.encode(), int(timeout), 1 if verify else 0)
            where = f"{scheme} {ph}:{pp} -> {host}:{port}"
        else:
            self.ctx = _lib.fxtls_connect(host.encode(), int(port), int(timeout), 1 if verify else 0)
            where = f"{host}:{port}"
        if not self.ctx:
            raise ConnectionError(f"fxtls_connect({where}) failed: handshake/connect")

    @staticmethod
    def have_roots():
        return bool(_lib.fxtls_have_roots())

    def alpn(self):
        buf = ctypes.create_string_buffer(24)
        _lib.fxtls_alpn(self.ctx, buf, 24)
        return buf.value.decode()

    def write(self, data: bytes):
        if not data:
            return 0
        cbuf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        total = 0
        while total < len(data):
            n = _lib.fxtls_write(self.ctx, ctypes.byref(cbuf, total), len(data) - total)
            if n <= 0:
                raise IOError("fxtls_write failed")
            total += n
        return total

    def recv(self, n: int) -> bytes:
        """Read up to n bytes (b'' on EOF). Retries through read timeouts (bounded)."""
        buf = ctypes.create_string_buffer(n)
        for _ in range(120):                     # ~120s cap of idle waiting
            r = _lib.fxtls_read(self.ctx, buf, n)
            if r == -2:                          # read timeout -> retry
                if self._stop: return b""
                continue
            return buf.raw[:r] if r > 0 else b""
        return b""

    def recvn(self, n: int) -> bytes:
        """Read up to n bytes for the reader thread; returns short (not raises) on
        EOF or when stop_reads() is set, so the reader loop can exit cleanly."""
        out = bytearray()
        buf = ctypes.create_string_buffer(65536)
        while len(out) < n:
            r = _lib.fxtls_read(self.ctx, buf, min(65536, n - len(out)))
            if r == -2:                          # timeout: bail if closing, else keep waiting
                if self._stop:
                    break
                continue
            if r <= 0:
                break
            out += buf.raw[:r]
        return bytes(out)

    def stop_reads(self):
        self._stop = True

    def shutdown(self):
        """Signal the reader to stop and best-effort unblock it — call before close()."""
        self._stop = True
        if self.ctx:
            _lib.fxtls_shutdown(self.ctx)

    def close(self):
        if self.ctx:
            _lib.fxtls_close(self.ctx)
            self.ctx = None

    def __enter__(self): return self
    def __exit__(self, *a): self.close()

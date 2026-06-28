"""Persistent, multiplexing HTTP/2 connection tuned to Firefox 152's fingerprint.

A single background reader thread dispatches frames to per-stream buffers, so many
Python threads can issue concurrent requests over one connection (true h2
multiplexing) while the opening frames (SETTINGS / WINDOW_UPDATE / pseudo-header
order) stay byte-faithful to Firefox.
"""
import struct, threading, time
from hpack import Encoder, Decoder

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FF_SETTINGS = [(0x1, 65536), (0x2, 0), (0x4, 131072), (0x5, 16384)]
FF_CONN_WINDOW_INCREMENT = 12517377
MAX_FRAME = 16384

DATA, HEADERS, RST, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = 0,1,3,4,6,7,8,9
F_END_STREAM, F_ACK, F_END_HEADERS, F_PRIORITY = 0x1, 0x1, 0x4, 0x20
# Firefox sends stream priority inside the request HEADERS frame: dep=0, weight byte=41.
FF_HEADERS_PRIORITY = struct.pack(">I", 0) + bytes([41])


def _frame(ftype, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", sid) + payload


class _Stream:
    __slots__ = ("status", "headers", "chunks", "done", "error", "future", "loop", "sid")
    def __init__(self):
        self.status = None; self.headers = []; self.chunks = []
        self.done = threading.Event(); self.error = None
        self.future = None; self.loop = None; self.sid = 0


class H2Connection:
    def __init__(self, transport):
        self.tp = transport
        self.enc = Encoder()
        self.dec = Decoder(); self.dec.max_allowed_table_size = 65536
        self._send_lock = threading.Lock()
        self._streams = {}; self._slock = threading.Lock()
        self._next_id = 1
        self.closed = False
        self._closing = False
        self.max_concurrent = 100        # updated from server SETTINGS(MAX_CONCURRENT_STREAMS)
        self.goaway_last = 1 << 31        # streams above this won't be processed after GOAWAY
        self._refs = 0                    # in-flight senders holding this conn (guards free)
        # in-progress header block assembly (HEADERS + CONTINUATION)
        self._hsid = None; self._hbuf = bytearray(); self._hend = False
        sp = b"".join(struct.pack(">HI", k, v) for k, v in FF_SETTINGS)
        self.tp.write(PREFACE
                      + _frame(SETTINGS, 0, 0, sp)
                      + _frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", FF_CONN_WINDOW_INCREMENT)))
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    # ---- reader thread ----
    def _read_loop(self):
        # Loop until EOF (not until self.closed): a graceful GOAWAY marks the
        # connection closed for NEW streams but in-flight streams still get their
        # responses, so we must keep reading.
        try:
            try:
                while True:
                    hdr = self.tp.recvn(9)
                    if len(hdr) < 9:
                        break
                    length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
                    ftype, flags = hdr[3], hdr[4]
                    sid = struct.unpack(">I", hdr[5:9])[0] & 0x7fffffff
                    payload = self.tp.recvn(length) if length else b""
                    if length and len(payload) < length:    # connection closed mid-frame
                        break
                    self._dispatch(ftype, flags, sid, payload)
            except Exception as e:
                self._fail_all(e); return
            self._fail_all(ConnectionError("connection closed by peer"))
        finally:
            # The reader is the only thread that does socket I/O (PR_Recv) on this fd,
            # so it MUST also be the thread that tears it down (PR_Close). Closing from
            # a different OS thread than the one that has been reading corrupts NSPR's
            # per-fd I/O bookkeeping on the Windows build and segfaults a later op
            # (0xC0000005). POSIX NSPR was unaffected, but same-thread teardown is the
            # correct, portable rule. Wait out in-flight writers (refs) first.
            self._teardown_transport()

    def _finish_headers(self):
        st = self._get(self._hsid)
        if st is not None:
            for name, value in self.dec.decode(bytes(self._hbuf)):
                if name == ":status": st.status = int(value)
                else: st.headers.append((name, value))
            if self._hend: self._finish(st)
        self._hsid = None; self._hbuf = bytearray(); self._hend = False

    def _dispatch(self, ftype, flags, sid, payload):
        if ftype == HEADERS:
            self._hsid = sid; self._hbuf = bytearray(payload); self._hend = bool(flags & F_END_STREAM)
            if flags & F_END_HEADERS: self._finish_headers()
        elif ftype == CONTINUATION:
            self._hbuf += payload
            if flags & F_END_HEADERS: self._finish_headers()
        elif ftype == DATA:
            st = self._get(sid)
            end = bool(flags & F_END_STREAM)
            if st is not None:
                st.chunks.append(payload)
                if payload:
                    # replenish connection window always; replenish the stream
                    # window only while the stream is still open (WINDOW_UPDATE on a
                    # closed stream is a protocol error -> GOAWAY).
                    upd = _frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", len(payload)))
                    if not end:
                        upd += _frame(WINDOW_UPDATE, 0, sid, struct.pack(">I", len(payload)))
                    with self._send_lock:
                        self.tp.write(upd)
                if end: self._finish(st)
        elif ftype == SETTINGS:
            if not (flags & F_ACK):
                for i in range(0, len(payload), 6):     # track MAX_CONCURRENT_STREAMS (id 3)
                    if ((payload[i] << 8) | payload[i+1]) == 0x3:
                        self.max_concurrent = struct.unpack(">I", payload[i+2:i+6])[0]
                with self._send_lock: self.tp.write(_frame(SETTINGS, F_ACK, 0))
        elif ftype == PING:
            if not (flags & F_ACK):
                with self._send_lock: self.tp.write(_frame(PING, F_ACK, 0, payload))
        elif ftype == GOAWAY:
            last_sid = struct.unpack(">I", payload[0:4])[0] & 0x7fffffff if len(payload) >= 4 else 0
            code = struct.unpack(">I", payload[4:8])[0] if len(payload) >= 8 else -1
            self.goaway_last = last_sid
            self.closed = True                          # stop accepting NEW streams (pool evicts)
            # only fail streams the server won't process; in-flight (<= last_sid) keep going
            with self._slock: items = list(self._streams.items())
            for sid_, st in items:
                if sid_ > last_sid and not st.done.is_set():
                    st.error = ConnectionError(f"GOAWAY code={code}"); self._finish(st)
        elif ftype == RST:
            st = self._get(sid)
            if st is not None and not st.done.is_set():
                st.error = ConnectionError("RST_STREAM"); self._finish(st)

    def _get(self, sid):
        with self._slock: return self._streams.get(sid)

    def _finish(self, st):
        """Mark a stream complete: wake the sync waiter and/or resolve the async future."""
        st.done.set()
        if st.future is not None and st.loop is not None:
            try: st.loop.call_soon_threadsafe(self._resolve, st)
            except RuntimeError: pass         # event loop already closed

    @staticmethod
    def _resolve(st):
        if st.future.done(): return
        if st.error: st.future.set_exception(st.error)
        else: st.future.set_result((st.status, st.headers, b"".join(st.chunks)))

    def _fail_all(self, exc):
        self.closed = True
        with self._slock: items = list(self._streams.values())
        for st in items:
            if not st.done.is_set():
                st.error = exc; self._finish(st)

    # ---- public API ----
    def _send(self, method, path, authority, headers, body, future=None, loop=None):
        # the caller (pool) holds one ref on this connection; release it once the
        # write is done so close() can never free the transport mid-write.
        try:
            if self.closed:
                raise ConnectionError("h2 connection closed")
            st = _Stream(); st.future = future; st.loop = loop
            hdr_list = [(":method", method), (":path", path),
                        (":authority", authority), (":scheme", "https")]
            hdr_list += [(k.lower(), v) for k, v in headers]
            with self._send_lock:
                sid = self._next_id; self._next_id += 2
                st.sid = sid
                with self._slock: self._streams[sid] = st
                block = self.enc.encode(hdr_list)      # HPACK is stateful -> encode+send atomically
                # Firefox carries stream priority in the HEADERS frame on the first
                # request of the connection (the navigation); on every multiplexed
                # stream it upsets some servers, so keep it to stream 1.
                end = F_END_STREAM if not body else 0
                if sid == 1:
                    out = _frame(HEADERS, F_END_HEADERS | F_PRIORITY | end, sid, FF_HEADERS_PRIORITY + block)
                else:
                    out = _frame(HEADERS, F_END_HEADERS | end, sid, block)
                mv = memoryview(body)
                for i in range(0, len(body), MAX_FRAME):
                    chunk = mv[i:i + MAX_FRAME]
                    last = i + MAX_FRAME >= len(body)
                    out += _frame(DATA, F_END_STREAM if last else 0, sid, bytes(chunk))
                self.tp.write(out)
            return st
        finally:
            self.release()

    def _pop(self, sid):
        with self._slock: self._streams.pop(sid, None)

    def request(self, method, path, authority, headers, body=b"", timeout=30):
        """Synchronous: blocks the calling thread until the response is complete."""
        st = self._send(method, path, authority, headers, body)
        ok = st.done.wait(timeout)
        self._pop(st.sid)
        if not ok:
            raise TimeoutError(f"h2 request timeout after {timeout}s")
        if st.error: raise st.error
        return st.status, st.headers, b"".join(st.chunks)

    def send_async(self, method, path, authority, headers, body, future, loop):
        """Async: returns the stream; the reader thread resolves `future` with
        (status, headers, body_bytes). Does not block the event loop."""
        return self._send(method, path, authority, headers, body, future, loop)

    def active(self):
        with self._slock:
            return len(self._streams)

    def usable(self):
        """True if this connection can take another new stream."""
        return (not self.closed and not self._closing
                and self._next_id <= self.goaway_last
                and self.active() < self.max_concurrent)

    def acquire(self):
        """Reserve this connection for one send; prevents free while writing."""
        with self._slock:
            if (self.closed or self._closing or self._next_id > self.goaway_last
                    or len(self._streams) >= self.max_concurrent):
                return False
            self._refs += 1
            return True

    def release(self):
        with self._slock:
            if self._refs > 0:
                self._refs -= 1

    def _teardown_transport(self):
        # Free the native fd once in-flight writers (refs) have drained. Idempotent
        # (tp.close() no-ops if already closed). Called from the reader thread's
        # finally, or directly by close() when there is no live reader to do it.
        for _ in range(400):             # bounded wait (~2s) for in-flight writes
            with self._slock:
                if self._refs == 0: break
            time.sleep(0.005)
        try: self.tp.close()
        except Exception: pass

    def close(self):
        # idempotent; sequence: stop reads -> reader exits and, on ITS OWN THREAD,
        # fails pending streams + tears down the fd (see _read_loop's finally).
        with self._slock:
            if self._closing:
                return
            self._closing = True
        self.closed = True
        self.tp.stop_reads()             # set stop flag; reader exits within one read timeout
        if threading.current_thread() is not self._reader and self._reader.is_alive():
            # Normal case: the reader does _fail_all + PR_Close itself; just wait.
            self._reader.join(timeout=5)
        else:
            # Re-entrant close from the reader, or the reader already gone: do it here.
            self._fail_all(ConnectionError("connection closed"))
            self._teardown_transport()

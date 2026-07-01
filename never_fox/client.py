"""never_fox — a requests-style HTTP client whose bytes on the wire are genuine
Firefox 152 (real NSS TLS byte-identical incl ECH; Firefox HTTP/2 fingerprint).

Built for high-concurrency crawling: multiple pooled HTTP/2 connections per host
(each multiplexing many streams), cookie persistence, automatic redirects, and a
requests-compatible Session / Response surface.
"""
import json as _json, gzip, zlib, threading, time, base64, random
from urllib.parse import urlsplit, urlencode, urljoin
from . import _native, h2conn, http1, h3
from .cookies import CookieJar


def _parse_proxy(proxy):
    """'http://...' or 'socks5://[user:pass@]host:port' -> (scheme,host,port,user,pass)."""
    if not proxy:
        return None
    if isinstance(proxy, dict):
        proxy = proxy.get("https") or proxy.get("http") or proxy.get("all")
        if not proxy:
            return None
    u = urlsplit(proxy if "://" in proxy else "http://" + proxy)
    scheme = (u.scheme or "http").lower()
    default = 1080 if scheme.startswith("socks") else 8080
    return (scheme, u.hostname, u.port or default, u.username or "", u.password or "")

# Global Alt-Svc cache (like Firefox): hosts seen advertising h3 -> upgrade later.
_H3_HOSTS = set()
_H3_LOCK = threading.Lock()

def _note_altsvc(host, headers_dict):
    if "h3" in headers_dict.get("alt-svc", ""):
        with _H3_LOCK:
            _H3_HOSTS.add(host)

def _host_has_h3(host):
    with _H3_LOCK:
        return host in _H3_HOSTS


def _reg_domain(host):
    """Approximate registrable domain (last two labels; no public-suffix list). Good
    enough to tell same-site from cross-site for the Sec-Fetch-Site header."""
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def _sec_fetch_site(prev_scheme, prev_host, prev_port, new_url):
    """Sec-Fetch-Site for a redirected navigation, from the origin relationship between
    the redirecting page and the target — Firefox sends same-origin / same-site /
    cross-site here, NOT 'none' (which only means a user-typed address-bar load)."""
    ns = new_url.scheme
    nh = new_url.hostname
    npp = new_url.port or (443 if ns == "https" else 80)
    if (prev_scheme, prev_host, prev_port) == (ns, nh, npp):
        return "same-origin"
    if _reg_domain(prev_host) == _reg_domain(nh):
        return "same-site"
    return "cross-site"

FF_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) "
         "Gecko/20100101 Firefox/152.0")

# Firefox 152 default top-level GET headers, in Firefox's exact order.
DEFAULT_HEADERS = [
    ("user-agent", FF_UA),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("accept-language", "en-US,en;q=0.9"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("upgrade-insecure-requests", "1"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-user", "?1"),
    ("priority", "u=0, i"),
    ("te", "trailers"),
]
_REASONS = {200:"OK",201:"Created",204:"No Content",301:"Moved Permanently",
    302:"Found",303:"See Other",304:"Not Modified",307:"Temporary Redirect",
    308:"Permanent Redirect",400:"Bad Request",401:"Unauthorized",403:"Forbidden",
    404:"Not Found",429:"Too Many Requests",500:"Internal Server Error",
    502:"Bad Gateway",503:"Service Unavailable"}


class HTTPError(Exception):
    pass


# Methods safe to auto-retry on a transport error: a retry may re-send the request,
# so non-idempotent methods (POST/PATCH) must not be retried or the peer could act on
# a duplicate. Matches urllib3/requests' default retry allowlist.
IDEMPOTENT = frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"})

# Caller-supplied headers that must NOT survive a redirect to a different host — else
# credentials leak to the redirect target (browsers/requests strip these cross-origin).
# The cookie jar is already re-evaluated per-host, so this only guards explicit headers.
_SENSITIVE_ON_REDIRECT = frozenset({"authorization", "cookie", "proxy-authorization"})


class RateLimiter:
    """Per-host pacing: at most `rate` requests/second per host (0 = unlimited).
    delay() reserves the next slot and returns how long the caller should wait."""
    def __init__(self, rate):
        self.interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._next = {}
        self._lock = threading.Lock()

    def delay(self, host):
        if not self.interval:
            return 0.0
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next.get(host, 0.0))
            self._next[host] = start + self.interval
            wait = start - now
        # ±15% jitter: a mechanically uniform cadence is itself a bot signal. The mean
        # rate is preserved (the reservation is still spaced by `interval`).
        return max(0.0, wait + self.interval * random.uniform(-0.15, 0.15))


def _retry_after(resp, attempt):
    ra = resp.headers.get("retry-after", "")
    if ra.isdigit():
        return min(int(ra), 60)             # honor a server-specified delay exactly
    base = min(2 ** attempt, 30)            # equal-jitter exponential backoff: half fixed,
    return base / 2 + random.uniform(0, base / 2)   # half random (de-synchronises retries)


def _bounded_zlib(body, wbits, limit):
    d = zlib.decompressobj(wbits)
    if not limit:
        return d.decompress(body) + d.flush()
    out = d.decompress(body, limit + 1)           # cap this call's output
    if len(out) > limit or d.unconsumed_tail:     # more remained -> over the limit
        raise HTTPError(f"decompressed body exceeded max_response_bytes ({limit})")
    out += d.flush()
    if len(out) > limit:
        raise HTTPError(f"decompressed body exceeded max_response_bytes ({limit})")
    return out


def _decompress(body, enc, limit=0):
    """Decode Content-Encoding. `limit` (bytes, 0=off) bounds the *decompressed* size
    to defuse decompression bombs; exceeding it raises HTTPError rather than OOM-ing.
    An unknown or corrupt encoding falls back to the raw bytes (best-effort)."""
    enc = (enc or "").lower()
    if not enc or enc == "identity":
        return body
    try:
        if enc == "gzip":
            return _bounded_zlib(body, 16 + zlib.MAX_WBITS, limit)
        if enc == "deflate":
            try:               return _bounded_zlib(body, zlib.MAX_WBITS, limit)
            except zlib.error: return _bounded_zlib(body, -zlib.MAX_WBITS, limit)
        if enc == "br":
            import brotli
            out = brotli.decompress(body)         # one-shot (input already h2-capped)
            if limit and len(out) > limit:
                raise HTTPError(f"decompressed body exceeded max_response_bytes ({limit})")
            return out
        if enc == "zstd":
            import io, zstandard
            rdr = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(body))
            out = rdr.read((limit + 1) if limit else -1)   # bounded read
            if limit and len(out) > limit:
                raise HTTPError(f"decompressed body exceeded max_response_bytes ({limit})")
            return out
    except HTTPError:
        raise
    except Exception:
        return body
    return body


class Response:
    def __init__(self, status, headers, body, proto, url="", max_bytes=0):
        self.status_code = status
        self.http_version = proto
        self.url = url
        self.reason = _REASONS.get(status, "")
        self.raw_headers = headers
        self.headers = {k.lower(): v for k, v in headers}
        self._raw = body
        self.content = _decompress(body, self.headers.get("content-encoding"), max_bytes)
        self.history = []
        self.cookies = {}
        self.elapsed = 0.0

    @property
    def ok(self):
        return self.status_code < 400

    @property
    def text(self):
        return self.content.decode(self.encoding, "replace")

    @property
    def encoding(self):
        ct = self.headers.get("content-type", "")
        if "charset=" in ct:
            return ct.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        return "utf-8"

    def json(self, **kw):
        return _json.loads(self.content, **kw)

    def raise_for_status(self):
        if 400 <= self.status_code < 600:
            raise HTTPError(f"{self.status_code} {self.reason} for {self.url}")
        return self

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def __repr__(self):
        return f"<Response [{self.status_code}] {self.http_version} {len(self.content)}B>"


class Session:
    def __init__(self, headers=None, verify=True, h3="auto", proxy=None,
                 max_connections_per_host=6, max_redirects=20, retries=3,
                 rate_limit=0, backoff_retries=2, max_response_bytes=None):
        self.headers = list(DEFAULT_HEADERS if headers is None else headers)
        self.verify = verify
        self.h3 = h3
        self.proxy = _parse_proxy(proxy)
        self.cookies = CookieJar()
        self.params = {}
        self.max_conns = max_connections_per_host
        self.max_redirects = max_redirects
        self.retries = retries
        self.backoff_retries = backoff_retries
        # cap the raw (on-the-wire) response body; None = unlimited. Protects memory
        # against a hostile/huge response — the h2 stream is RST once it is exceeded.
        self.max_response_bytes = max_response_bytes
        self._rl = RateLimiter(rate_limit)   # per-host requests/second
        self._pool = {}                  # (host, port) -> [H2Connection, ...]
        self._draining = []              # evicted conns awaiting safe close
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._creating = set()           # keys with a connect in flight (single-flight)

    # ---- connection pool (multiple h2 connections per host) -------------------
    def _evict_closed(self, conns):
        keep = []
        for c in conns:
            (self._draining if c.closed else keep).append(c)
        conns[:] = keep

    def _reap(self):
        with self._lock:
            d, self._draining = self._draining, []
        for c in d:                          # safe now (refcount-guarded close)
            try: c.close()
            except Exception: pass

    def _existing_conn(self, host, port, proxy):
        """Non-blocking: return a warm acquired connection (ref held), or None.
        Also sweeps drained conns whose reader already exited — on an all-warm async
        path _get_conn (which reaps) is never hit, so _draining would otherwise grow."""
        dead, result = [], None
        with self._lock:
            live = []                            # drop self-torn-down conns (cheap, no join)
            for c in self._draining:
                (live if c._reader.is_alive() else dead).append(c)
            self._draining = live
            conns = self._pool.get((host, port, proxy))
            if conns:
                self._evict_closed(conns)
                for c in sorted(conns, key=lambda c: c.active()):   # least-loaded first
                    if c.acquire():
                        result = c
                        break
        for c in dead:
            try: c.close()                       # reader gone -> close() won't join
            except Exception: pass
        return result

    def _get_conn(self, host, port, timeout, proxy):
        key = (host, port, proxy)
        self._reap()                         # reclaim drained conns on the cold path
        # Single-flight per key: a burst of concurrent requests to a cold host must
        # NOT each open its own connection (that both explodes fd/thread count and,
        # for h2, is a non-browser fingerprint — Firefox coalesces an origin onto ONE
        # multiplexed connection). Only one caller connects at a time per key; the
        # rest wait, then reuse the connection it created (or, once it is saturated,
        # take a turn creating the next). Creation still happens OUTSIDE the lock so a
        # slow TLS handshake never blocks the pool.
        with self._lock:
            while True:
                conns = self._pool.setdefault(key, [])
                self._evict_closed(conns)
                for c in sorted(conns, key=lambda c: c.active()):   # least-loaded first
                    if c.acquire():
                        return c
                if key in self._creating:    # someone is connecting; wait and re-check
                    self._cv.wait(timeout=max(1.0, timeout))
                    continue
                self._creating.add(key)      # we are the connector
                break
        try:
            tp = _native.Transport(host, port, timeout, self.verify, proxy)
            if tp.alpn() != "h2":
                return ("h1", tp)
            c = h2conn.H2Connection(tp)
            c.acquire()                      # ref for the caller; released by _send
            with self._lock:
                self._pool.setdefault(key, []).append(c)
            return c
        finally:
            with self._lock:
                self._creating.discard(key)
                self._cv.notify_all()        # wake waiters to reuse / take next turn

    def _should_try_h3(self, host, port):
        if self.h3 is False or port != 443 or not h3.available():
            return False
        return True if self.h3 is True else _host_has_h3(host)

    # ---- one hop (no redirects) ----------------------------------------------
    def _send_once(self, method, host, port, path, authority, hdrs, body, timeout, scheme, proxy):
        if scheme == "https" and not proxy and self._should_try_h3(host, port):
            try:                                          # h3 over proxy not supported -> h2
                full = f"https://{authority}{path}"
                st, rh, bd = h3.request(method, full, hdrs, body, timeout)
                return Response(st, rh, bd, "h3", full)
            except Exception:
                pass
        last = None
        max_bytes = self.max_response_bytes or 0
        attempts = self.retries if method in IDEMPOTENT else 1   # don't re-send POST/PATCH
        for _ in range(max(1, attempts)):
            try:
                conn = self._get_conn(host, port, timeout, proxy)
                if isinstance(conn, tuple):             # http/1.1
                    tp = conn[1]
                    try:
                        st, rh, bd = http1.request(tp, method, path, authority, hdrs, body)
                        return Response(st, rh, bd, "http/1.1", f"{scheme}://{authority}{path}",
                                        max_bytes)
                    finally:
                        tp.close()
                st, rh, bd = conn.request(method, path, authority, hdrs, body,
                                          timeout=timeout, max_bytes=max_bytes)
                return Response(st, rh, bd, "h2", f"{scheme}://{authority}{path}", max_bytes)
            except TimeoutError:                    # response timed out: RST already sent,
                raise                               # re-sending would just duplicate work
            except (ConnectionError, IOError) as e:
                last = e
        raise last

    def _do_hop(self, method, host, port, path, authority, hdrs, body, timeout, scheme, proxy):
        """One hop with per-host rate limiting and 429/503 backoff."""
        resp = None
        for attempt in range(self.backoff_retries + 1):
            d = self._rl.delay(host)
            if d: time.sleep(d)
            resp = self._send_once(method, host, port, path, authority, hdrs, body, timeout, scheme, proxy)
            if resp.status_code in (429, 503) and attempt < self.backoff_retries:
                time.sleep(_retry_after(resp, attempt))
                continue
            return resp
        return resp

    # ---- public request (cookies + redirects) --------------------------------
    def request(self, method, url, headers=None, data=None, json=None, params=None,
                cookies=None, timeout=15, allow_redirects=True, proxy=None, proxies=None):
        method = method.upper()
        if isinstance(headers, dict):                     # accept a dict or a list of pairs
            headers = list(headers.items())
        proxy = _parse_proxy(proxy or proxies) or self.proxy
        body, base_hdrs = self._prepare_body(data, json)
        merged_params = {**self.params, **(params or {})}
        history = []
        redirect_site = None                              # set on redirect hops (Sec-Fetch-Site)
        t0 = time.time()
        for hop in range(self.max_redirects + 1):
            u = urlsplit(url)
            host = u.hostname
            port = u.port or (443 if u.scheme == "https" else 80)
            authority = host if port in (443, 80) else f"{host}:{port}"
            path = u.path or "/"
            if u.query: path += "?" + u.query
            if merged_params: path += ("&" if "?" in path else "?") + urlencode(merged_params)

            hdrs = self._build_headers(headers, base_hdrs, host, path, u.scheme, cookies, redirect_site)
            resp = self._do_hop(method, host, port, path, authority, hdrs, body, timeout, u.scheme, proxy)
            resp.url = url
            # store cookies
            sc = [v for k, v in resp.raw_headers if k.lower() == "set-cookie"]
            if sc: self.cookies.set_from_response(host, sc)
            resp.cookies = self.cookies.as_dict()
            _note_altsvc(host, resp.headers)

            if allow_redirects and resp.status_code in (301, 302, 303, 307, 308) \
                    and "location" in resp.headers:
                history.append(resp)
                url = urljoin(url, resp.headers["location"])
                redirect_site = _sec_fetch_site(u.scheme, host, port, urlsplit(url))
                if headers and urlsplit(url).hostname != host:    # don't leak creds cross-host
                    headers = [(k, v) for k, v in headers
                               if k.lower() not in _SENSITIVE_ON_REDIRECT]
                if resp.status_code in (301, 302, 303) and method in ("POST", "PUT", "PATCH"):
                    if method == "POST" or resp.status_code == 303:
                        method, body, base_hdrs = "GET", b"", []   # browser semantics
                merged_params = {}                        # query already in Location
                continue
            resp.history = history
            resp.elapsed = time.time() - t0
            return resp
        raise HTTPError(f"too many redirects ({self.max_redirects})")

    def _prepare_body(self, data, json):
        extra = []
        if json is not None:
            body = _json.dumps(json).encode()
            extra.append(("content-type", "application/json"))
        elif isinstance(data, dict):
            body = urlencode(data).encode()
            extra.append(("content-type", "application/x-www-form-urlencoded"))
        elif data is not None:
            body = data.encode() if isinstance(data, str) else data
        else:
            body = b""
        return body, extra

    def _build_headers(self, req_headers, body_hdrs, host, path, scheme, cookies,
                       redirect_site=None):
        base = list(self.headers if req_headers is None else req_headers)
        # insert Cookie after accept-encoding (Firefox position)
        jar_cookie = self.cookies.header_for(host, path, scheme == "https")
        if cookies:
            extra = "; ".join(f"{k}={v}" for k, v in cookies.items())
            jar_cookie = (jar_cookie + "; " + extra).strip("; ") if jar_cookie else extra
        out = []
        for k, v in base:
            kl = k.lower()
            # On a redirect hop, correct the navigation headers (value-only, order kept):
            # Sec-Fetch-Site is no longer 'none', and Sec-Fetch-User (user-activation
            # only) is dropped — matching how Firefox re-issues a redirected navigation.
            if redirect_site is not None:
                if kl == "sec-fetch-site":
                    v = redirect_site
                elif kl == "sec-fetch-user":
                    continue
            out.append((k, v))
            if kl == "accept-encoding" and jar_cookie:
                out.append(("cookie", jar_cookie))
        out.extend(body_hdrs)
        return out

    # ---- verbs ----------------------------------------------------------------
    def get(self, url, **kw):     return self.request("GET", url, **kw)
    def post(self, url, **kw):    return self.request("POST", url, **kw)
    def put(self, url, **kw):     return self.request("PUT", url, **kw)
    def patch(self, url, **kw):   return self.request("PATCH", url, **kw)
    def delete(self, url, **kw):  return self.request("DELETE", url, **kw)
    def head(self, url, **kw):    kw.setdefault("allow_redirects", False); return self.request("HEAD", url, **kw)
    def options(self, url, **kw): return self.request("OPTIONS", url, **kw)

    def close(self):
        self._reap()
        with self._lock:
            allconns = [c for conns in self._pool.values() for c in conns]
            self._pool.clear()
        for c in allconns:
            try: c.close()
            except Exception: pass

    def __enter__(self): return self
    def __exit__(self, *a): self.close()


_default = Session()
def get(url, **kw):        return _default.request("GET", url, **kw)
def post(url, **kw):       return _default.request("POST", url, **kw)
def head(url, **kw):       return _default.head(url, **kw)
def put(url, **kw):        return _default.request("PUT", url, **kw)
def delete(url, **kw):     return _default.request("DELETE", url, **kw)
def request(m, url, **kw): return _default.request(m, url, **kw)

"""Async API (asyncio) over the same Firefox-152 engine.

High-concurrency friendly: HTTP/2 responses are awaited via asyncio futures that
the connection's reader thread resolves (call_soon_threadsafe) — so thousands of
concurrent requests over a pooled set of multiplexed connections do NOT need a
thread per request. Connection setup (TLS handshake), HTTP/1.1 and the h3
subprocess run in the default executor.
"""
import asyncio, time
from urllib.parse import urlsplit, urlencode, urljoin
from .client import (Session, Response, HTTPError, IDEMPOTENT, _SENSITIVE_ON_REDIRECT,
                     _note_altsvc, _parse_proxy, _retry_after, _sec_fetch_site)
from . import http1, h3


class AsyncSession:
    def __init__(self, headers=None, verify=True, h3="auto", proxy=None,
                 max_connections_per_host=6, max_redirects=20, retries=3,
                 rate_limit=0, backoff_retries=2, max_response_bytes=None):
        self._s = Session(headers, verify, h3, proxy, max_connections_per_host,
                          max_redirects, retries, rate_limit, backoff_retries,
                          max_response_bytes)
        self.cookies = self._s.cookies

    async def _do_hop(self, method, host, port, path, authority, hdrs, body, timeout, scheme, url, proxy):
        resp = None
        for attempt in range(self._s.backoff_retries + 1):
            d = self._s._rl.delay(host)
            if d: await asyncio.sleep(d)
            resp = await self._send_once(method, host, port, path, authority, hdrs, body, timeout, scheme, url, proxy)
            if resp.status_code in (429, 503) and attempt < self._s.backoff_retries:
                await asyncio.sleep(_retry_after(resp, attempt))
                continue
            return resp
        return resp

    @property
    def headers(self): return self._s.headers

    async def _send_once(self, method, host, port, path, authority, hdrs, body, timeout, scheme, url, proxy):
        loop = asyncio.get_running_loop()
        if scheme == "https" and not proxy and self._s._should_try_h3(host, port):
            try:
                full = f"https://{authority}{path}"
                st, rh, bd = await loop.run_in_executor(
                    None, lambda: h3.request(method, full, hdrs, body, timeout))
                return Response(st, rh, bd, "h3", full)
            except Exception:
                pass
        last = None
        max_bytes = self._s.max_response_bytes or 0
        attempts = self._s.retries if method in IDEMPOTENT else 1   # don't re-send POST/PATCH
        for _ in range(max(1, attempts)):
            try:
                # warm connection -> inline (no thread); only handshake hits the executor
                conn = self._s._existing_conn(host, port, proxy)
                if conn is None:
                    conn = await loop.run_in_executor(None, self._s._get_conn, host, port, timeout, proxy)
                if isinstance(conn, tuple):                      # http/1.1 in executor
                    tp = conn[1]
                    def do():
                        try: return http1.request(tp, method, path, authority, hdrs, body)
                        finally: tp.close()
                    st, rh, bd = await loop.run_in_executor(None, do)
                    return Response(st, rh, bd, "http/1.1", url, max_bytes)
                fut = loop.create_future()                       # true async: no thread per request
                stream = conn.send_async(method, path, authority, hdrs, body, fut, loop, max_bytes=max_bytes)
                try:
                    status, rh, bd = await asyncio.wait_for(fut, timeout)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    conn._rst(stream.sid)                        # cancel on the wire, then propagate
                    raise
                finally:
                    conn._pop(stream.sid)
                return Response(status, rh, bd, "h2", url, max_bytes)
            except asyncio.TimeoutError:                         # response timeout: don't re-send
                raise
            except (ConnectionError, IOError) as e:
                last = e
        raise last

    async def request(self, method, url, headers=None, data=None, json=None, params=None,
                      cookies=None, timeout=15, allow_redirects=True, proxy=None, proxies=None):
        method = method.upper()
        if isinstance(headers, dict):
            headers = list(headers.items())
        proxy = _parse_proxy(proxy or proxies) or self._s.proxy
        body, base_hdrs = self._s._prepare_body(data, json)
        merged_params = {**self._s.params, **(params or {})}
        history = []
        redirect_site = None
        t0 = time.time()
        for _ in range(self._s.max_redirects + 1):
            u = urlsplit(url)
            host = u.hostname
            port = u.port or (443 if u.scheme == "https" else 80)
            authority = host if port in (443, 80) else f"{host}:{port}"
            path = u.path or "/"
            if u.query: path += "?" + u.query
            if merged_params: path += ("&" if "?" in path else "?") + urlencode(merged_params)
            hdrs = self._s._build_headers(headers, base_hdrs, host, path, u.scheme, cookies, redirect_site)
            resp = await self._do_hop(method, host, port, path, authority, hdrs, body, timeout, u.scheme, url, proxy)
            resp.url = url
            sc = [v for k, v in resp.raw_headers if k.lower() == "set-cookie"]
            if sc: self._s.cookies.set_from_response(host, sc)
            resp.cookies = self._s.cookies.as_dict()
            _note_altsvc(host, resp.headers)
            if allow_redirects and resp.status_code in (301, 302, 303, 307, 308) \
                    and "location" in resp.headers:
                history.append(resp)
                url = urljoin(url, resp.headers["location"])
                redirect_site = _sec_fetch_site(u.scheme, host, port, urlsplit(url))
                if headers and urlsplit(url).hostname != host:
                    headers = [(k, v) for k, v in headers
                               if k.lower() not in _SENSITIVE_ON_REDIRECT]
                if resp.status_code in (301, 302, 303) and method in ("POST", "PUT", "PATCH"):
                    if method == "POST" or resp.status_code == 303:
                        method, body, base_hdrs = "GET", b"", []
                merged_params = {}
                continue
            resp.history = history
            resp.elapsed = time.time() - t0
            return resp
        raise HTTPError(f"too many redirects ({self._s.max_redirects})")

    async def get(self, url, **kw):     return await self.request("GET", url, **kw)
    async def post(self, url, **kw):    return await self.request("POST", url, **kw)
    async def put(self, url, **kw):     return await self.request("PUT", url, **kw)
    async def patch(self, url, **kw):   return await self.request("PATCH", url, **kw)
    async def delete(self, url, **kw):  return await self.request("DELETE", url, **kw)
    async def options(self, url, **kw): return await self.request("OPTIONS", url, **kw)
    async def head(self, url, **kw):
        kw.setdefault("allow_redirects", False)
        return await self.request("HEAD", url, **kw)

    async def close(self):
        await asyncio.get_running_loop().run_in_executor(None, self._s.close)

    async def __aenter__(self): return self
    async def __aexit__(self, *a): await self.close()

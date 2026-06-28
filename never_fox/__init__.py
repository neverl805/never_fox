"""never_fox — requests-style Python HTTP client whose requests are genuine Firefox 152
(real NSS TLS, byte-identical ClientHello incl ECH; Firefox HTTP/2 fingerprint).
Built for high-concurrency crawling: pooled multiplexed h2 connections, cookies,
redirects, sync + async APIs."""
from .client import (Session, Response, HTTPError, DEFAULT_HEADERS, FF_UA,
                     get, post, put, delete, head, request)

__all__ = ["Session", "Response", "HTTPError", "AsyncSession",
           "get", "post", "put", "delete", "head", "request",
           "DEFAULT_HEADERS", "FF_UA"]
__version__ = "0.3.4"


def __getattr__(name):
    if name == "AsyncSession":
        from .aio import AsyncSession
        return AsyncSession
    raise AttributeError(name)

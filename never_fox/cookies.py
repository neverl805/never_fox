"""Lightweight cookie jar (domain/path matching, expiry) for session crawling."""
import time
from http.cookies import SimpleCookie


class _C:
    __slots__ = ("name", "value", "domain", "path", "secure", "expires")
    def __init__(self, name, value, domain, path, secure, expires):
        self.name, self.value, self.domain = name, value, domain
        self.path, self.secure, self.expires = path, secure, expires


class CookieJar:
    def __init__(self):
        self._c = {}        # (domain, path, name) -> _C

    def set_from_response(self, host, set_cookie_values):
        for raw in set_cookie_values:
            self._add(host, raw)

    def _add(self, host, raw):
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return
        host = (host or "").lower()
        for name, m in jar.items():
            if m["domain"]:
                # an explicit Domain must cover the host and not be a bare public suffix
                # (a single label like "com") — otherwise reject, so a server can't scope
                # a cookie to an unrelated/too-broad domain.
                domain = m["domain"].lstrip(".").lower()
                if "." not in domain or not (host == domain or host.endswith("." + domain)):
                    continue
            else:
                domain = host
            path = m["path"] or "/"
            secure = bool(m["secure"])
            expires = None
            ma = m["max-age"]
            if ma not in ("", None):
                try:
                    age = int(ma)
                    if age <= 0:                         # delete
                        self._c.pop((domain, path, name), None); continue
                    expires = time.time() + age
                except ValueError:
                    pass
            if m.value == "":
                self._c.pop((domain, path, name), None); continue
            self._c[(domain, path, name)] = _C(name, m.value, domain, path, secure, expires)

    def header_for(self, host, path, secure):
        host = host.lower(); now = time.time(); matched = []
        for key, c in list(self._c.items()):
            if c.expires and c.expires < now:
                self._c.pop(key, None); continue
            if not (host == c.domain or host.endswith("." + c.domain)):
                continue
            if not path.startswith(c.path):
                continue
            if c.secure and not secure:
                continue
            matched.append(c)
        # RFC 6265: cookies with longer (more specific) paths are sent first.
        matched.sort(key=lambda c: len(c.path), reverse=True)
        return "; ".join(f"{c.name}={c.value}" for c in matched)

    def as_dict(self):
        return {c.name: c.value for c in self._c.values()}

    def set(self, name, value, domain, path="/"):
        self._c[(domain.lstrip(".").lower(), path, name)] = _C(name, value, domain.lstrip(".").lower(), path, False, None)

    def clear(self):
        self._c.clear()

    def __len__(self):
        return len(self._c)

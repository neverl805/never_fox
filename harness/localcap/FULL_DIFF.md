# Full local-capture diff — real Firefox 152  vs  fxreq
(both hit the same local HTTPS/h2 server; server logged TLS+h2+headers)

## Transport
- ALPN: firefox=`h2`  fxreq=`h2`  ✅

## TLS ClientHello
- ja3: ✅ identical  `6447ab086255d194909d4013b1a89e87`
- ja4: ✅ identical  `t13d1617h2_86a278354501_3cbfd9057e0d`
- cipher_suites identical: ✅
- extensions identical: ✅
- supported_groups: ✅
- signature_algorithms: ✅
- key_share_groups: ✅
- record_size_limit: ✅
- alpn: ✅

## HTTP/2
- **akamai_fingerprint**: ✅ IDENTICAL
    firefox: `1:65536;2:0;4:131072;5:16384|12517377|1|m,p,a,s`
    fxreq  : `1:65536;2:0;4:131072;5:16384|12517377|1|m,p,a,s`
- SETTINGS order+values: ✅  ff=[['HEADER_TABLE_SIZE', 65536], ['ENABLE_PUSH', 0], ['INITIAL_WINDOW_SIZE', 131072], ['MAX_FRAME_SIZE', 16384]]  fx=[['HEADER_TABLE_SIZE', 65536], ['ENABLE_PUSH', 0], ['INITIAL_WINDOW_SIZE', 131072], ['MAX_FRAME_SIZE', 16384]]
- WINDOW_UPDATE: ff=12517377 fx=12517377  ✅
- PRIORITY frames: ff=[{'stream': 3, 'excl': 0, 'dep': 0, 'weight': 41, 'in_headers': True}]  fx=[{'stream': 1, 'excl': 0, 'dep': 0, 'weight': 41, 'in_headers': True}]
- pseudo-header order: ff=['method', 'path', 'authority', 'scheme'] fx=['method', 'path', 'authority', 'scheme']  ✅

## HTTP headers (name + order + value)
- regular-header ORDER identical: ✅

| header | Firefox 152 | fxreq | match |
|---|---|---|---|
| `:method` | `GET` | `GET` | ✅ |
| `:path` | `/` | `/` | ✅ |
| `:authority` | `localhost:8444` | `localhost:8444` | ✅ |
| `:scheme` | `https` | `https` | ✅ |
| `user-agent` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Gecko/20100101 Firefox/152.0` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Gecko/20100101 Firefox/152.0` | ✅ |
| `accept` | `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` | `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` | ✅ |
| `accept-language` | `en-US,en;q=0.9` | `en-US,en;q=0.9` | ✅ |
| `accept-encoding` | `gzip, deflate, br, zstd` | `gzip, deflate, br, zstd` | ✅ |
| `upgrade-insecure-requests` | `1` | `1` | ✅ |
| `sec-fetch-dest` | `document` | `document` | ✅ |
| `sec-fetch-mode` | `navigate` | `navigate` | ✅ |
| `sec-fetch-site` | `none` | `none` | ✅ |
| `sec-fetch-user` | `?1` | `?1` | ✅ |
| `priority` | `u=0, i` | `u=0, i` | ✅ |
| `te` | `trailers` | `trailers` | ✅ |
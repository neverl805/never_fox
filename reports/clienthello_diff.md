# Firefox 152.0.2 (real)  vs  curl_cffi engine — ClientHello diff

- real browser: **Firefox 152.0.2** (NSS, captured live on this machine)
- engine: **engine-firefox147** (curl_cffi, real NSS build)

## Fingerprint hashes

| | Firefox 152 | engine |
|---|---|---|
| JA3 | `6447ab086255d194909d4013b1a89e87` | `6f7889b9fb1a62a9577e685c1fcfa919` |
| JA4 | `t13d1617h2_86a278354501_3cbfd9057e0d` | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` |
| JA3(no-GREASE) | `6447ab086255d194909d4013b1a89e87` | `6f7889b9fb1a62a9577e685c1fcfa919` |

**TLS ClientHello verdict: ❌ MISMATCH**

## Layer-by-layer

- **cipher_suites (ordered)**: ❌ DIFFER (firefox=16 vs engine=17)
    - only in **engine** : ['ECDHE_ECDSA_AES128_CBC_SHA']
- **extensions (ordered)**: ✅ identical (17 entries)
- **supported_groups (ordered)**: ✅ identical (7 entries)
- **key_share groups**: ✅ identical (3 entries)
- **signature_algorithms (ordered)**: ✅ identical (11 entries)
- **supported_versions**: ✅ identical (2 entries)
- **ec_point_formats**: ✅ identical (1 entries)
- **ALPN**: ✅ identical (2 entries)

## Firefox-152 critical markers

| marker | Firefox 152 | engine |
|---|---|---|
| X25519MLKEM768 in groups | `True` | `True` |
| X25519MLKEM768 in key_share | `True` | `True` |
| ffdhe2048 | `True` | `True` |
| ffdhe3072 | `True` | `True` |
| record_size_limit | `True` | `True` |
| rsl_value | `16385` | `4001`  ⚠️ |
| delegated_credentials | `True` | `True` |
| encrypted_client_hello(ECH) | `True` | `True` |
| session_ticket | `True` | `True` |
| psk_kem_modes | `[1]` | `[1]` |
| GREASE present | `False` | `False` |
| ALPN | `['h2', 'http/1.1']` | `['h2', 'http/1.1']` |

## Normalized ClientHello byte diff

(random, session_id, key_share key-material masked to 0 — so this reflects STRUCTURE)

- firefox normalized len: 1887 bytes
- engine   normalized len: 1890 bytes
- identical: ❌ no

## Ordered cipher lists (full)

| # | Firefox 152 | engine |
|---|---|---|
| 0 | TLS_AES_128_GCM_SHA256 | TLS_AES_128_GCM_SHA256 |
| 1 | TLS_CHACHA20_POLY1305_SHA256 | TLS_CHACHA20_POLY1305_SHA256 |
| 2 | TLS_AES_256_GCM_SHA384 | TLS_AES_256_GCM_SHA384 |
| 3 | ECDHE_ECDSA_AES128_GCM_SHA256 | ECDHE_ECDSA_AES128_GCM_SHA256 |
| 4 | ECDHE_RSA_AES128_GCM_SHA256 | ECDHE_RSA_AES128_GCM_SHA256 |
| 5 | ECDHE_ECDSA_CHACHA20_POLY1305 | ECDHE_ECDSA_CHACHA20_POLY1305 |
| 6 | ECDHE_RSA_CHACHA20_POLY1305 | ECDHE_RSA_CHACHA20_POLY1305 |
| 7 | ECDHE_ECDSA_AES256_GCM_SHA384 | ECDHE_ECDSA_AES256_GCM_SHA384 |
| 8 | ECDHE_RSA_AES256_GCM_SHA384 | ECDHE_RSA_AES256_GCM_SHA384 |
| 9 | ECDHE_ECDSA_AES256_CBC_SHA | ECDHE_ECDSA_AES256_CBC_SHA |
| 10 | ECDHE_RSA_AES128_CBC_SHA | ECDHE_ECDSA_AES128_CBC_SHA ⬅️ |
| 11 | ECDHE_RSA_AES256_CBC_SHA | ECDHE_RSA_AES128_CBC_SHA ⬅️ |
| 12 | RSA_AES128_GCM_SHA256 | ECDHE_RSA_AES256_CBC_SHA ⬅️ |
| 13 | RSA_AES256_GCM_SHA384 | RSA_AES128_GCM_SHA256 ⬅️ |
| 14 | RSA_AES128_CBC_SHA | RSA_AES256_GCM_SHA384 ⬅️ |
| 15 | RSA_AES256_CBC_SHA | RSA_AES128_CBC_SHA ⬅️ |
| 16 | — | RSA_AES256_CBC_SHA ⬅️ |
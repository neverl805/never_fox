# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`never_fox` is a `requests`-style Python HTTP client whose bytes on the wire are a **genuine Firefox 152**, not an emulation. It links the **real NSS TLS engine** (the same library Firefox uses) through a thin native shim, so the TLS ClientHello is byte-for-byte identical to Firefox 152 — including ECH, the `X25519MLKEM768` post-quantum group, `record_size_limit`, delegated credentials, and certificate compression — and the HTTP/2 frames/headers match Firefox too. It is built for high-concurrency crawling and anti-bot evasion.

**The fingerprint is the product.** Almost any change to the TLS config, the HTTP/2 framing, or the default header set risks breaking byte-identity with real Firefox. Treat `native/verify.py` as a hard gate (see below) and re-run it after touching anything in the fingerprint surface.

## Architecture: two layers

### 1. Native engine (`native/`, C, links real NSS)
- **`fxtls_lib.c`** → compiled to `libfxtls.{dylib,so,dll}`. Owns the TCP connect, the Firefox-152 TLS handshake, raw send/recv, and proxy tunneling (HTTP `CONNECT` + SOCKS5). Exposes a tiny C ABI (`fxtls_connect`, `fxtls_connect_proxy`, `fxtls_connect_socks5`, `fxtls_read/write`, `fxtls_shutdown`, `fxtls_close`, error/diagnostic getters). HTTP framing is *not* here — it lives in Python above this layer.
- **`fxtls_config.h`** → `fxtls_configure()` is the **single source of truth for the ClientHello**: cipher suite list+order, named groups, signature schemes, ALPN, cert-compression algs, ECH GREASE size (100 → the genuine 281-byte ECH extension), `SSL_RECORD_SIZE_LIMIT=16385`, etc. Edit fingerprint behavior here.
- **`firefox152_reference.json`** → the authoritative captured Firefox 152 fingerprint. `verify.py` diffs the engine's actual ClientHello against this, field-by-field and byte-for-byte (random/session_id/key_share/ECH payload masked). **If you change `fxtls_config.h`, this reference and `verify.py`'s `FIELDS` list are what you reconcile against.**
- NSS itself is **never compiled here** — it comes prebuilt from each platform's package manager (Homebrew / apt / MSYS2). `build.py` finds it via `pkg-config` and compiles only the ~250-line shim (seconds).
- **`native/h3/`** → the HTTP/3 backend build (separate from the TLS shim). `build_h3.py` clones pinned `mozilla/neqo` + `mozilla/nss-rs`, overlays never_fox's patched files from `native/h3/files/`, wires a Cargo `[patch]` so neqo links the patched nss-rs, and builds `neqo-client`. The patched `crypto.rs` makes the QUIC ClientHello match Firefox 152 (GREASE off, fixed extension order, SCT, ECH GREASE, FF sig-alg order, cert compression); the patched nss-rs adds ffdhe2048/3072, delegated credentials, `SSL_SignatureSchemePrefSet`, and RFC 8879 cert (de)compression. This build **does** compile NSS from source (needs rustup/cargo, libclang, mercurial, ninja, gyp-next) — heavy, minutes; `H3_NSS_DIR` reuses a prebuilt NSS to skip it. The clones and `native/neqo/` are gitignored (~343 MB); only the resulting `neqo-client` gets staged into the wheel.

### 2. Python protocol + client layer (`never_fox/`)
- **`_native.py`** — `ctypes` binding to `libfxtls`. The `Transport` class wraps one connection. Binary-safe (never uses `c_char_p`; h2 frames contain NUL). **NSS is initialized once at import time, single-threaded** (`_lib.fxtls_have_roots()` at module top) because `fxtls__ensure_init` is not internally locked — two threads cold-starting a pool would race `NSS_NoDB_Init` and crash.
- **`client.py`** — the `Session` (connection pool, cookies, redirects, per-host rate limiting, 429/503 backoff, proxy parsing) and `Response`. Sync API. `DEFAULT_HEADERS` and `FF_UA` here are Firefox 152's exact top-level GET headers **in Firefox's exact order** — order is part of the fingerprint.
- **`h2conn.py`** — persistent multiplexing HTTP/2 connection. A single background reader thread dispatches frames to per-stream buffers so many Python threads (or asyncio futures) share one connection. `FF_SETTINGS`, the connection `WINDOW_UPDATE` increment, the pseudo-header order, and the priority-in-HEADERS behavior are all tuned to match Firefox's Akamai HTTP/2 fingerprint. HPACK encode+send is done atomically under `_send_lock` (HPACK is stateful).
- **`aio.py`** — `AsyncSession`. Reuses the sync `Session`'s pool/cookies. Warm h2 requests are awaited via asyncio futures the reader thread resolves with `call_soon_threadsafe` → **thread count ≈ connection count, not request count**. Only the TLS handshake, HTTP/1.1, and the h3 subprocess hit the executor.
- **`http1.py`** — HTTP/1.1 fallback (used only when ALPN negotiates `http/1.1`).
- **`h3.py`** — experimental HTTP/3 via a **bundled `neqo-client`** binary (Firefox's real QUIC/h3 stack, patched to match the FF152 ClientHello — see `native/h3/` below) driven as a subprocess. The binary is resolved from `never_fox/_lib/` (wheel) or the dev source tree; the body is read back via neqo's `--output-dir` (writing to a temp file). Any failure — missing binary, UDP/443 blocked, idle timeout, non-zero exit — raises, and the caller silently falls back to h2, so h3 can never break a request. **Current CLI-path limits:** status is hard-coded `200`, response headers are absent (content-encoding is *sniffed* from body magic bytes), and request bodies (POST/PUT) aren't supported (they fall back to h2). A cdylib upgrade to fix status/headers is planned. h3 is opt-in per host: `client.py` only tries it after an `Alt-Svc: h3` advertisement (`_note_altsvc`/`_host_has_h3`).
- **`cookies.py`** — lightweight cookie jar (domain/path matching + expiry).

### Library resolution (dev vs installed)
`_native.py` looks for `libfxtls` in `never_fox/_lib/` (installed wheel layout) first, then `../native/` (source-tree layout). **In development, building into `native/` is picked up directly** — no install needed once the repo is on `PYTHONPATH`.

## Crash-safety invariants (load-bearing — do not "simplify")

The connection-teardown code in `_native.py`, `h2conn.py`, and `fxtls_lib.c` encodes hard-won fixes for segfault-class bugs (the peer-RST-then-reconnect crash, mostly Windows-only). The extensive comments there are not optional. Key rules:
- **Never `PR_Shutdown` a *live* SSL fd** concurrently with the reader's `PR_Recv` — that corrupts global NSS state (the original keep-alive crash). `Transport.shutdown()` only sets a stop flag; the actual teardown is in `close()`.
- **The reader thread must perform its own teardown (same-thread `PR_Close`).** NSPR ties an fd's I/O bookkeeping to the thread doing the I/O; closing an h2 fd from a *different* OS thread than the reader that has been calling `PR_Recv` corrupts that state and segfaults a later op (`0xC0000005`, Windows-only — POSIX NSPR is native-threaded and tolerates it). So `H2Connection._read_loop` does `_teardown_transport()` (drain `_refs` → `tp.close()`) in its `finally`; `close()` only sets the stop flag and `join()`s the reader. The same rule makes the http1 path safe for free (it reads and closes on the one calling thread). Do not move the `PR_Close` back onto the caller's thread.
- **Drain peer-closed fds before `PR_Close`**: if the peer already sent EOF/RST (`_peer_eof`), call `fxtls_shutdown` first; `PR_Close` alone on RST-corrupted state double-frees and the next NSS op segfaults.
- `fxtls__finish` calls `SSL_ClearSessionCache()` before every handshake so no session is ever resumed — this keeps the fingerprint at Firefox's first-connection shape (no `pre_shared_key`) *and* kills the "RST corrupts a cached sid → next connect segfaults" crash class.

## Common commands

```bash
# Build the native engine (auto-finds NSS via pkg-config; produces native/libfxtls.*)
python native/build.py

# Verify the engine's ClientHello == Firefox 152 — THE fingerprint gate. Run after
# any change to fxtls_config.h, the C engine, or whenever NSS version drifts.
python native/verify.py

# Bundle dependent NSS dylibs into native/vendor/ (self-contained, cross-machine)
python native/bundle.py

# Stage native/libfxtls.* + vendor/ into never_fox/_lib/ for wheel-building
python native/stage_lib.py

# Build a platform-specific wheel (py3-none-<platform>, see setup.py)
python -m pip wheel . --no-deps -w dist

# (Optional) Build the HTTP/3 backend — clones+patches mozilla/neqo, compiles NSS
# from source. Heavy (minutes). Produces native/h3/neqo-client. See native/h3/.
python native/h3/build_h3.py
```

System deps before building (prebuilt NSS etc.):
- macOS: `brew install nss nspr brotli zstd`
- Linux: `sudo apt-get install libnss3-dev libnspr4-dev libbrotli-dev libzstd-dev zlib1g-dev patchelf`
- Windows: MSYS2 `mingw-w64-x86_64-{nss,nspr,brotli,zstd,zlib,gcc,pkg-config}`
- Python deps: `pip install hpack brotli zstandard`

`native/build.sh` is the macOS-only quick path (also builds the standalone `fxtls` CH-probe binary). `build.py` is the cross-platform entry point used by CI. `build_manylinux.sh` builds inside a `manylinux2014` container for broad Linux compatibility.

## Fingerprint verification harness (`harness/`)

There is no `pytest` suite. Correctness = "the wire bytes match real Firefox 152", proven by capture-and-diff:

```bash
# CI gate (also the fastest local check): engine ClientHello vs the FF152 reference
python native/verify.py

# Full end-to-end local capture: real Firefox + never_fox both hit a local HTTPS/h2
# server; diff every field. See harness/localcap/FULL_DIFF.md and MULTISITE.md.
python harness/localcap/diff_h2cap.py

# macOS reverse/compare pipeline against a real local Firefox 152 (see REPORT.md §6)
python harness/drive_engine.py --target firefox147
python harness/capture_firefox.py 8444
python harness/diff_report.py
```

`harness/hello_sink.py` is the ClientHello parser/sink (`parse_client_hello`, `normalized_hex`, JA3/JA4 computation) that both `verify.py` and the capture scripts depend on. `native/_debug_repro.py` reproduces the peer-RST→reconnect crash (`FXTLS_DEBUG=1 FXTLS_REPRO_MODE={fin,rst}`).

## CI & platform notes (`.github/workflows/build.yml`)

- Matrix builds on native runners: Linux x86_64 / Linux arm64 / macOS arm64 / Windows x86_64. Each runs `build.py` → `bundle.py` → `verify.py` (gate) → `stage_lib.py` → wheel → smoke test. A `vX.Y.Z` tag attaches all four wheels to a GitHub Release.
- **Linux must use a *full* NSS build** (manylinux2014 / Fedora-style). conda-forge's stripped NSS drops both `X25519MLKEM768` and RFC 8879 cert compression, which makes `verify.py` fail. This is why CI does not use the conda NSS to *run*.
- The native lib is a platform-specific binary tied to one OS+arch (like Cronet). There is no Python C-extension — `setup.py` forces a `py3-none-<platform>` wheel tag (works on any CPython 3.x, one platform).
- Diagnostic env vars: `FXTLS_DEBUG=1` (flushed native trace, survives a segfault), `FXTLS_CA_MODULE` / `FXTLS_NSS_DIST` / `FXTLS_VERIFY_PORT` / `FXTLS_REPRO_*`.

## Gotchas

- `__version__` in `never_fox/__init__.py` and `version` in `pyproject.toml` are maintained separately — bump both.
- Certificate validation uses NSS's builtin Mozilla root list (`libnssckbi`) — the same trust store as Firefox — when `verify=True`. The C engine searches several paths for the ckbi module (next to the lib, `vendor/`, system locations); basename varies by platform.
- The known-limitations and the full reverse-engineering/measurement story are in `README.md` and `REPORT.md` (both partly in Chinese). `REPORT.md` documents an earlier `curl_cffi`-based path A; the current engine links NSS directly.

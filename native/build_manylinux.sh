#!/bin/bash
# Broad-compat Linux engine (CentOS 7+, glibc 2.17). Runs inside a manylinux2014
# container. Builds NSS + NSPR FROM SOURCE with the container's old-glibc toolchain,
# so headers, link libs and runtime libs are one self-consistent version (no ABI
# skew) and everything links against glibc 2.17. brotli/zstd come from conda-forge
# (also built for glibc 2.17). Any recent NSS + our config => byte-perfect FF152
# (verify.py asserts it); running here also proves the glibc-2.17 floor.
set -euo pipefail

REPO="$PWD"                       # /io (mounted repo); we cd away to build NSS
ARCH=$(uname -m)
echo "=== manylinux2014 build, arch=$ARCH ==="

# 1) conda-forge toolchain libs (glibc 2.17): brotli, zstd, python, pkg-config,
#    patchelf, plus gyp + ninja for the NSS build.
case "$ARCH" in x86_64) MF=x86_64 ;; aarch64) MF=aarch64 ;; *) echo "bad arch"; exit 1 ;; esac
if [ ! -x /opt/conda/bin/conda ]; then
  curl -fsSL "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-${MF}.sh" -o /tmp/mf.sh
  bash /tmp/mf.sh -b -p /opt/conda
fi
/opt/conda/bin/conda create -y -n fx -c conda-forge \
  python=3.10 brotli zstd zlib pkg-config patchelf ninja
PFX=/opt/conda/envs/fx
export PATH="$PFX/bin:$PATH"
export PKG_CONFIG_PATH="$PFX/lib/pkgconfig"
python -m pip install -q gyp-next

# 2) NSS + NSPR from source (sibling checkouts; build.sh builds both -> ../dist)
echo "=== clone + build NSS/NSPR from source ==="
W=/tmp/nssbuild; rm -rf "$W"; mkdir -p "$W"; cd "$W"
git clone --depth 1 https://github.com/nss-dev/nspr.git
git clone --depth 1 https://github.com/nss-dev/nss.git
( cd nss && ./build.sh --opt --disable-tests )
export FXTLS_NSS_DIST="$W/dist"
echo "--- NSS dist layout ---"
find "$W/dist" -name 'ssl.h' -o -name 'libssl3.so' 2>/dev/null | head
cd "$REPO"

# 3) compile + vendor against the from-source NSS (self-consistent) + conda brotli/zstd
echo "=== build.py ==="; python native/build.py
echo "=== bundle.py ==="; python native/bundle.py
for so in native/vendor/*.so*; do patchelf --set-rpath '$ORIGIN' "$so" 2>/dev/null || true; done
echo "--- from-source NSS version (must be recent, has MLKEM/ECH) ---"
strings "$(find "$FXTLS_NSS_DIST" -name libnssutil3.so | head -1)" 2>/dev/null \
  | grep -oE 'Network Security Services [0-9.]+' | head -1 || true
echo "--- libfxtls.so NSS resolution (rpath only, must point into vendor/) ---"
ldd native/libfxtls.so 2>&1 | grep -iE 'libnss3|libssl3|libnspr4|not found' || true

# NSS init sanity — isolate "NSS_NoDB_Init failed" from "handshake failed"
echo "--- NSS init sanity (have_roots triggers NSS_NoDB_Init + loads softokn) ---"
python - <<'PY' || echo "  >>> NSS init FAILED"
import importlib.util
spec = importlib.util.spec_from_file_location("_n", "never_fox/_native.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print("  _native loaded; fxtls_have_roots() =", m._lib.fxtls_have_roots())
PY

# 4) verify — proves glibc-2.17 compatibility AND the FF152 fingerprint
echo "=== verify.py ==="; python native/verify.py

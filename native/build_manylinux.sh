#!/bin/bash
# Broad-compat Linux engine (CentOS 7+, glibc 2.17). Runs inside a manylinux2014
# container. Trick: compile/link against conda-forge NSS (built for glibc 2.17,
# gives us the headers + link symbols incl. the MLKEM enum), then vendor Firefox
# 152's OWN NSS libraries (full X25519MLKEM768 + cert compression, also built by
# Mozilla against an old glibc) for the runtime so the ClientHello is byte-perfect.
set -euo pipefail

ARCH=$(uname -m)
FF_VER="${FF_VER:-152.0.2}"
case "$ARCH" in
  x86_64)  FF_PLAT=linux-x86_64;  MF=x86_64 ;;
  aarch64) FF_PLAT=linux-aarch64; MF=aarch64 ;;
  *) echo "unsupported arch $ARCH"; exit 1 ;;
esac
echo "=== arch=$ARCH  firefox=$FF_VER ($FF_PLAT) ==="

# 1) conda-forge toolchain (glibc 2.17 compatible): NSS/NSPR headers + symbols,
#    brotli, zstd, a clean python, pkg-config, patchelf.
if [ ! -x /opt/conda/bin/conda ]; then
  curl -fsSL "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-${MF}.sh" -o /tmp/mf.sh
  bash /tmp/mf.sh -b -p /opt/conda
fi
/opt/conda/bin/conda create -y -n fx -c conda-forge \
  python=3.10 nss nspr brotli zstd pkg-config patchelf
PFX=/opt/conda/envs/fx
export PATH="$PFX/bin:$PATH"
export PKG_CONFIG_PATH="$PFX/lib/pkgconfig"

# 2) compile + vendor against conda (symbols resolve; brotli/zstd are real)
echo "=== build.py ==="; python native/build.py
echo "=== bundle.py ==="; python native/bundle.py

# 3) swap the vendored NSS/NSPR for Firefox 152's own libraries (full MLKEM)
echo "=== fetch Firefox $FF_VER NSS ==="
curl -fsSL "https://ftp.mozilla.org/pub/firefox/releases/${FF_VER}/${FF_PLAT}/en-US/firefox-${FF_VER}.tar.xz" -o /tmp/ff.tar.xz
mkdir -p /tmp/ff && tar -xf /tmp/ff.tar.xz -C /tmp/ff
swapped=0
for l in libnss3 libnssutil3 libssl3 libsmime3 libsoftokn3 libfreebl3 libfreeblpriv3 \
         libnssckbi libnssdbm3 libnspr4 libplc4 libplds4 libmozsqlite3 libnssckbi; do
  if [ -f "/tmp/ff/firefox/$l.so" ]; then
    cp -f "/tmp/ff/firefox/$l.so" native/vendor/ && swapped=$((swapped+1))
  fi
done
echo "  swapped $swapped Firefox NSS/NSPR libs into native/vendor/"

# 4) verify — running here proves both glibc-2.17 compatibility AND the FF152 fingerprint
echo "=== verify.py ==="; python native/verify.py

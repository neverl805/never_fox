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
  python=3.10 nss nspr brotli zstd sqlite pkg-config patchelf
PFX=/opt/conda/envs/fx
export PATH="$PFX/bin:$PATH"
export PKG_CONFIG_PATH="$PFX/lib/pkgconfig"

# 2) compile + vendor against conda (symbols resolve; brotli/zstd are real)
echo "=== build.py ==="; python native/build.py
echo "=== bundle.py ==="; python native/bundle.py

# 3) swap the vendored NSS/NSPR for Firefox 152's own libraries (full MLKEM).
#    Copy ALL of Firefox's .so (except the huge libxul + irrelevant media/UI libs)
#    so every transitive NSS dep (libmozsqlite3 for softokn, etc.) comes along.
#    Firefox's libs carry RUNPATH=$ORIGIN, so they find each other inside vendor/.
echo "=== fetch Firefox $FF_VER NSS ==="
curl -fsSL "https://ftp.mozilla.org/pub/firefox/releases/${FF_VER}/${FF_PLAT}/en-US/firefox-${FF_VER}.tar.xz" -o /tmp/ff.tar.xz
mkdir -p /tmp/ff && tar -xf /tmp/ff.tar.xz -C /tmp/ff
echo "--- Firefox ships these .so: ---"; ls -la /tmp/ff/firefox/*.so 2>/dev/null
swapped=0
for so in /tmp/ff/firefox/*.so; do
  base=$(basename "$so")
  case "$base" in
    libxul.so|libmozavcodec.so|libmozavutil.so|libmozgtk.so|libmozwayland.so|libgkcodecs.so) continue ;;
  esac
  cp -f "$so" native/vendor/ && swapped=$((swapped+1))
done
# insurance: if Firefox didn't ship libmozsqlite3, satisfy softokn's NEEDED with conda sqlite
if [ ! -f native/vendor/libmozsqlite3.so ]; then
  sq=$(ls "$PFX"/lib/libsqlite3.so* 2>/dev/null | head -1)
  [ -n "$sq" ] && cp -fL "$sq" native/vendor/libmozsqlite3.so && echo "  (fallback: conda sqlite -> libmozsqlite3.so)"
fi
echo "  swapped $swapped Firefox libs into native/vendor/"

# 4) verify — running here proves both glibc-2.17 compatibility AND the FF152 fingerprint
echo "=== verify.py ==="; python native/verify.py

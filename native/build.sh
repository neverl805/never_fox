#!/bin/bash
# Build fxtls (CH-probe binary + transport shared library) against real NSS,
# with real RFC 8879 certificate decompression (zlib/brotli/zstd).
set -e
NSS=$(brew --prefix nss)
NSPR=$(brew --prefix nspr)
BROTLI=$(brew --prefix brotli)
ZSTD=$(brew --prefix zstd)
HERE=$(cd "$(dirname "$0")" && pwd)

INC="-I$NSS/include/nss -I$NSPR/include/nspr -I$BROTLI/include -I$ZSTD/include"
LIBS="-L$NSS/lib -L$NSPR/lib -lssl3 -lnss3 -lnspr4 -lplc4 -lplds4 -lsmime3 \
      -L$BROTLI/lib -lbrotlidec -L$ZSTD/lib -lzstd -lz"
RPATH="-Wl,-rpath,$NSS/lib -Wl,-rpath,$NSPR/lib -Wl,-rpath,$BROTLI/lib -Wl,-rpath,$ZSTD/lib"

clang -O2 -g -o "$HERE/fxtls" "$HERE/fxtls.c" $INC $LIBS $RPATH
clang -O2 -g -dynamiclib -o "$HERE/libfxtls.dylib" "$HERE/fxtls_lib.c" \
      -install_name "$HERE/libfxtls.dylib" $INC $LIBS $RPATH
echo "built: $HERE/fxtls  +  $HERE/libfxtls.dylib"

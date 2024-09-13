#!/bin/sh
# find root
cd `dirname $PWD/$0` ; cd ..
#TODO: add support for ccache

# XXX. fails with >1
[ -z "${MAKE_JOBS}" ] && MAKE_JOBS=8

OLD_LDFLAGS="${LDFLAGS}"
unset LDFLAGS

export CC="emcc"
export CFLAGS="-Oz"
export LDFLAGS="-sWASM=1 -sSIDE_MODULE=1 -Wl,--allow-multiple-definition"
export AR="emar"

CFGFLAGS=" \
  --prefix=/usr \
  --host=x86_64-unknown-linux-gnu \
  --with-compiler=wasm \
  --without-dylink \
  --with-libversion="" \
  --with-static-themes \
  --with-checks-level=0 \
  --without-jemalloc \
  --without-fork \
  --without-gperf \
  --without-gpl \
  --without-ptrace-wrap \
  --disable-threads \
  --disable-debugger \
  --with-libr \
"

CAPSTONE_ARCHS="arm aarch64 mips x86"

make mrproper
cp -f dist/plugins-cfg/plugins.emscripten.cfg plugins.cfg
./configure-plugins

./configure ${CFGFLAGS} && \
	make -s -j ${MAKE_JOBS} DEBUG=0 BINS="" CAPSTONE_ARCHS="${CAPSTONE_ARCHS}"

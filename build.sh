#!/usr/bin/env bash

: ${CC=gcc}
: ${MAKE=make}
: ${BIN=sas}
: ${JOBS=4}

SRCS="src/*.c"
LDFLAGS="$LDFLAGS -lm -static-libgcc -Wl,-Bstatic"
CMAKE_DEFAULT_FLAGS=" $CMAKE_DEFAULT_FLAGS -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=`pwd`/lib/prefix -DCMAKE_INSTALL_PREFIX=`pwd`/lib/prefix -DBUILD_SHARED_LIBS=OFF"

[[ "$@" == "clean" ]] && rm -rf lib/zlib/build lib/mbedtls-3.2.1/build lib/prefix $BIN *.exe && exit 0
[[ $OSTYPE == 'msys'* || $CC == *'mingw'* ]] && SSL_CONFIGURE="mingw64"
[ ! -e "lib/zlib" ] && echo "Make sure you've cloned submodules. (git submodule update --init --depth=1)" && exit -1

mkdir -p lib/prefix/include lib/prefix/lib
if [[ "$@" != "-DSAS_NO_ZLIB" && "$@" != *"-lz"* ]]; then
  [[ ! -e "lib/zlib/build" && $OSTYPE != 'msys'* ]] && cd lib/zlib && mkdir build && cd build && $CC -D_LARGEFILE64_SOURCE -I.. ../*.c -c && ar rc libz.a *.o && cp libz.a ../../prefix/lib && cp ../*.h ../../prefix/include && cd ../../../
  LDFLAGS="$LDFLAGS -lz"
fi
if [[ "$@" != "-DSAS_NO_SSL" && "$@" != *"-lmbed"* ]]; then
  [ ! -e "lib/mbedtls-3.2.1/build" ] && cd lib/mbedtls-3.2.1 && mkdir build && cd build && cmake .. $CMAKE_DEFAULT_FLAGS  -G "Unix Makefiles" -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF $SSL_CONFIGURE && $MAKE -j $JOBS && $MAKE install && cd ../../../
  LDFLAGS="$LDFLAGS -lmbedtls -lmbedx509 -lmbedcrypto"
fi
[[ "$@" != *"-llua"* ]] && CFLAGS="$CFLAGS -Ilib/lua -DMAKE_LIB=1" && SRCS="$SRCS lib/lua/onelua.c"

# Build the pre-packaged lua file into the executbale.
xxd -i src/main.lua > src/main.lua.c

[[ $OSTYPE != 'msys'* && $CC != *'mingw'* && $CC != "emcc" ]] && LDFLAGS=" $LDFLAGS -Wl,-Bdynamic -ldl -pthread"
[[ $OSTYPE == 'msys'* || $CC == *'mingw'* ]] && LDFLAGS="$LDFLAGS -lbcrypt -lws2_32 -lz -lwinhttp -lole32 -lcrypt32 -lrpcrt4"

[[ " $@" != *" -g"* && " $@" != *" -O"* ]] && CFLAGS="$CFLAGS -O3" && LDFLAGS="$LDFLAGS -s"
$CC $CFLAGS $SRCS $@ -o $BIN $LDFLAGS


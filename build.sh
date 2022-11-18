#!/usr/bin/env bash

: ${CC=gcc}
: ${MAKE=make}
: ${BIN=sas}
: ${JOBS=4}

SRCS="src/*.c"
LDFLAGS="$LDFLAGS -lm -static-libgcc"

[[ "$@" == "clean" ]] && rm -rf lib/zlib/build lib/openssl/build lib/prefix $BIN *.exe && exit 0
[[ $OSTYPE == 'msys'* || $CC == *'mingw'* ]] && SSL_CONFIGURE="mingw64"

# Build supporting libraries, libgit2, libz, libssl (with libcrypto)
if [[ "$@" != "-DSAS_NO_ZLIB" && "$@" != *"-lz"* ]]; then
  [ ! -e "lib/zlib" ] && echo "Make sure you've cloned submodules. (git submodule update --init --depth=1)" && exit -1
  [ ! -e "lib/zlib/build" ] && cd lib/zlib && mkdir build && cd build && ../configure --prefix=`pwd`/../../prefix && $MAKE -j $JOBS && $MAKE install && cd ../../../
  LDFLAGS="$LDFLAGS -Llib/libz/build -l:libz.a" && CFLAGS="$CFLAGS -Ilib/prefix/include" && LDFLAGS="$LDFLAGS -Llib/prefix/lib -Llib/prefix/lib64"
fi
if [[ "$@" != "-DSAS_NO_SSL" && "$@" != *"-lssl"* && "$@" != *"-lcrypto"* ]]; then
  [ ! -e "lib/openssl/build" ] && cd lib/openssl && mkdir build && cd build && ../Configure --prefix=`pwd`/../../prefix $SSL_CONFIGURE && $MAKE -j $JOBS && $MAKE install_sw install_ssldirs && cd ../../../ && ln -sf lib/prefix/lib64/libcrypto.a lib/prefix/lib/libcyrpto.a
  LDFLAGS="$LDFLAGS -Llib/libz/build" && CFLAGS="$CFLAGS -Ilib/prefix/include" && LDFLAGS="$LDFLAGS -Llib/prefix/lib -Llib/prefix/lib64 -l:libssl.a -l:libcrypto.a"
fi
[[ "$@" != *"-llua"* ]] && CFLAGS="$CFLAGS -Ilib/lua -DMAKE_LIB=1" && SRCS="$SRCS lib/lua/onelua.c"

# Build the pre-packaged lua file into the executbale.
xxd -i src/main.lua > src/main.lua.c

[[ $OSTYPE != 'msys'* && $CC != *'mingw'* && $CC != "emcc" ]] && LDFLAGS=" $LDFLAGS -ldl -pthread"
[[ $OSTYPE == 'msys'* || $CC == *'mingw'* ]] && LDFLAGS="$LDFLAGS -lbcrypt -lws2_32 -lz -lwinhttp -lole32 -lcrypt32 -lrpcrt4"

[[ " $@" != *" -g"* && " $@" != *" -O"* ]] && CFLAGS="$CFLAGS -O3" && LDFLAGS="$LDFLAGS -s"
$CC $CFLAGS $SRCS $@ -o $BIN $LDFLAGS 


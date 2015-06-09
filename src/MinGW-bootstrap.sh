#!/bin/bash
mkdir -p $HOME/bin
cat >$HOME/bin/mingw64 << 'EOF'
#!/bin/sh
PREFIX=x86_64-w64-mingw32
export CC=$PREFIX-gcc
export CXX=$PREFIX-g++
export CPP="$PREFIX-gcc -E"
export RANLIB=$PREFIX-ranlib
export STRIP=$PREFIX-strip
export DLLTOOL=$PREFIX-dlltool
export DLLWRAP=$PREFIX-dllwrap
export AS=$PREFIX-gcc
export AR=$PREFIX-ar
export WINDRES=$PREFIX-windres
export PKGCONFIG=$PREFIX-pkg-config
export OBJDUMP=$PREFIX-objdump
export PATH="/usr/x86_64-w64-mingw32/bin:$PATH"
exec "$@"
EOF
chmod u+x $HOME/bin/mingw64

export PATH="$HOME/bin:$PATH"

# check "cache"
if [ -f "$HOME/mingw64/usr/local/lib/libssl.dll.a" ]
then
	echo "Reusing existing compiled libraries! ;)"
	exit 0
fi

mkdir -p $HOME/mingw64; cd $HOME/mingw64
# wget -c http://www.oberhumer.com/opensource/lzo/download/lzo-2.09.tar.gz
wget -c http://zlib.net/zlib-1.2.8.tar.gz
wget -c https://www.openssl.org/source/openssl-1.0.2a.tar.gz

# LZO
# cd $HOME/mingw64
# tar -xzf lzo-2.09.tar.gz
# cd $HOME/mingw64/lzo-2.09
# ./configure --host=x86_64-w64-mingw32
# make
# DESTDIR=$HOME/mingw64 make install

# zlib
cd $HOME/mingw64
tar -xzf zlib-1.2.8.tar.gz
cd $HOME/mingw64/zlib-1.2.8
mingw64 ./configure --static
mingw64 make
DESTDIR=$HOME/mingw64 mingw64 make install

# OpenSSL
cd $HOME/mingw64
tar -xzf openssl-1.0.2a.tar.gz
cd $HOME/mingw64/openssl-1.0.2a
CROSS_COMPILE=x86_64-w64-mingw32- ./Configure no-static shared --openssldir=$HOME/mingw64/usr/local mingw64
mingw64 make -s
mingw64 make install_sw
find $HOME/mingw64/usr

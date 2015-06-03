#!/bin/bash

./configure && make -sj4 check  # regular build (using GCC and Clang)

make clean; cd ..; git clean -fdx

# http://docs.travis-ci.com/user/languages/c/
if [ "$CC" = "clang" ] # skip MinGW + Clang combination
then
	exit 0
fi

cd src && ./MinGW-bootstrap.sh  # MinGW build
export CFLAGS_EXTRA="-I$HOME/mingw64/usr/local/include"
export LDFLAGS="-L$HOME/mingw64/usr/local/lib"
mingw64 ./configure OPENSSL_LIBS="-lssl -lcrypto" --host=x86_64-w64-mingw32
mingw64 make -sj4
mv ../run/john ../run/john.exe

# Misc.
scd=`pwd`
cd $HOME/mingw64
wget -c http://dl.fedoraproject.org/pub/fedora/linux/releases/22/Everything/x86_64/os/Packages/m/mingw64-gmp-6.0.0-2.fc21.noarch.rpm
wget -c http://dl.fedoraproject.org/pub/fedora/linux/releases/22/Everything/x86_64/os/Packages/m/mingw64-openssl-1.0.2a-1.fc22.noarch.rpm
wget -c http://dl.fedoraproject.org/pub/fedora/linux/releases/22/Everything/x86_64/os/Packages/m/mingw64-zlib-1.2.8-3.fc21.noarch.rpm
wget -c http://dl.fedoraproject.org/pub/fedora/linux/releases/22/Everything/x86_64/os/Packages/m/mingw64-winpthreads-4.0.2-1.fc22.noarch.rpm
wget -c http://dl.fedoraproject.org/pub/fedora/linux/releases/22/Everything/x86_64/os/Packages/m/mingw64-libgomp-5.1.0-1.fc22.x86_64.rpm
wget -c http://dl.fedoraproject.org/pub/fedora/linux/releases/22/Everything/x86_64/os/Packages/m/mingw64-gcc-5.1.0-1.fc22.x86_64.rpm
wget -c http://indy.fulgan.com/SSL/openssl-1.0.2a-x64_86-win64.zip

rpm2cpio mingw64-gmp-6.0.0-2.fc21.noarch.rpm | cpio -idmv
rpm2cpio mingw64-openssl-1.0.2a-1.fc22.noarch.rpm | cpio -idmv
rpm2cpio mingw64-zlib-1.2.8-3.fc21.noarch.rpm | cpio -idmv
rpm2cpio mingw64-winpthreads-4.0.2-1.fc22.noarch.rpm | cpio -idmv
rpm2cpio mingw64-libgomp-5.1.0-1.fc22.x86_64.rpm | cpio -idmv
rpm2cpio mingw64-gcc-5.1.0-1.fc22.x86_64.rpm | cpio -idmv
unzip openssl-1.0.2a-x64_86-win64.zip

cd "$scd"

basepath="$HOME/mingw64/usr/x86_64-w64-mingw32/sys-root/mingw/bin"

# cp "$basepath/libwinpthread-1.dll" ../run
# cp "$basepath/zlib1.dll" ../run
# cp "$basepath/libgmp-10.dll" ../run
# cp "$basepath/libssl-10.dll" ../run
# cp "$basepath/libcrypto-10.dll" ../run
# cp "$basepath/libgomp-1.dll" ../run
# cp "$basepath/libgcc_s_seh-1.dll" ../run
cp "$HOME/mingw64/ssleay32.dll" ../run
cp "$HOME/mingw64/libeay32.dll" ../run

find ../run

v=`git rev-parse --short HEAD`
cd ..
zip -r ~/JtR-MinGW.zip run/ doc/ README.md README README-jumbo

#!/bin/bash
#
# now does mingw-64 build, and linux-64 no-sse2 build  (and tests both)

# 64-bit MinGW
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

# 32-bit MinGW
cat >$HOME/bin/mingw32 << 'EOF'
#!/bin/sh
PREFIX=i686-w64-mingw32
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
export PATH="/usr/i686-w64-mingw32/bin:$PATH"
exec "$@"
EOF
chmod u+x $HOME/bin/mingw32

cd /base/JohnTheRipper/src
export PATH="$HOME/bin:$PATH"

# stop wine from messing around, during the build phase
# echo -1 > /proc/sys/fs/binfmt_misc/status
# umount /proc/sys/fs/binfmt_misc

echo ""
echo '******************************************************************************'
echo "now building for Windows, with CPU fallback"
echo '******************************************************************************'
echo ""

# Build with AVX
mingw32 ./configure --enable-werror --disable-native-tests CPPFLAGS='-mavx -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-sse2.exe\""' --host=i686-w64-mingw32
if [ "x$?" != "x0" ] ; then exit 1 ; fi
mingw32 make -sj4
if [ "x$?" != "x0" ] ; then exit 1 ; fi
mv -v ../run/john ../run/john-avx.exe
make clean; make distclean

# Build with AVX2 (32-bit, see https://github.com/magnumripper/JohnTheRipper/issues/2543 for details)
mingw32 ./configure --enable-werror --disable-native-tests CPPFLAGS='-mavx2 -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-avx.exe\""' --host=i686-w64-mingw32
if [ "x$?" != "x0" ] ; then exit 1 ; fi
mingw32 make -sj4
if [ "x$?" != "x0" ] ; then exit 1 ; fi
mv -v ../run/john ../run/john-avx2.exe
make clean; make distclean

# Build with SSE2 only
# mingw64 ./configure --disable-native-tests CPPFLAGS='-mno-ssse3' --host=x86_64-w64-mingw32
mingw32 ./configure --enable-werror --disable-native-tests CPPFLAGS='-mno-ssse3' --host=i686-w64-mingw32
# mingw64 ./configure --host=x86_64-w64-mingw32
if [ "x$?" != "x0" ] ; then exit 1 ; fi
mingw64 make -sj4
if [ "x$?" != "x0" ] ; then exit 1 ; fi
mv -v ../run/john ../run/john-sse2.exe

# AVX2 is default, but with CPU fallback
mv -v ../run/john-avx2.exe ../run/john.exe

cd ../run
# the mingw build does not name many exe files correctly, fix that.
for f in genmkvpwd mkvcalcproba calc_stat tgtsnarf raw2dyna uaf2john wpapcap2john cprepair putty2john racf2john keepass2john hccap2john dmg2john bitlocker2john; do mv $f $f.exe; done
# for f in *.exe ; do x86_64-w64-mingw32-strip $f ; done
# remove opencl kernels and ztex stuff for mingw builds
rm -rf kernels ztex
cd ../src

# basepath="/usr/x86_64-w64-mingw32/sys-root/mingw/bin"
basepath="/usr/i686-w64-mingw32/sys-root/mingw/bin"

find $basepath | grep "dll$"

# cp "$basepath/libwinpthread-1.dll" ../run
# cp "$basepath/zlib1.dll" ../run
# cp "$basepath/libgmp-10.dll" ../run
# cp "$basepath/libssl-10.dll" ../run
# cp "$basepath/libcrypto-10.dll" ../run
# cp "$basepath/libgomp-1.dll" ../run
# cp "$basepath/libgcc_s_seh-1.dll" ../run  # not valid for 32-bit MinGW toolchain
cp ${basepath}/*.dll ../run

find ../run

v=`git rev-parse --short HEAD`
cd ..
mkdir -p /base/builds
zip -r /base/builds/JtR-MinGW-${v}.zip run/ doc/ README.md README README-jumbo
# 7z a /base/builds/JtR-MinGW-${v}.7z run/ doc/ README.md README README-jumbo

# restore the sse2 build for testing purposes
mv -v run/john-sse2.exe run/john.exe

echo ""
echo ""
echo ""
echo ""
echo '******************************************************************************'
echo "now testing the 32-bit SSE2 Windows build"
echo '******************************************************************************'
echo ""
# crazy testing!
cd /base/JohnTheRipper/run
export WINEDEBUG=-all  # suppress wine warnings
/usr/bin/wine john.exe --list=build-info
echo "[Disabled:Formats]" > john-local.conf
/usr/bin/wine john.exe --test-full=0
# if [ "x$?" != "x0" ] ; then exit 1 ; fi

# now build a non-SIMD 64 bit exe and test it
# dnf install -y openssl openssl-devel zlib-devel gmp-devel libpcap-devel
echo ""
echo ""
echo ""
echo ""
echo '******************************************************************************'
echo "now building/testing a NON-SIMD 64-bit Linux build"
echo '******************************************************************************'
echo ""
cd /base/JohnTheRipper/src
make -s distclean
CFLAGS_EXTRA="-fstack-protector-all" ./configure --enable-werror --disable-simd
if [ "x$?" != "x0" ] ; then exit 1 ; fi
make -sj4
if [ "x$?" != "x0" ] ; then exit 1 ; fi
../run/john --list=build-info
echo "[Disabled:Formats]" > john-local.conf
../run/john -test-full=0
if [ "x$?" != "x0" ] ; then exit 1 ; fi

# now build a non-SIMD 32 bit exe and test it
# dnf install -y glibc-headers.i686 glibc.i686 glibc-devel.i686 libgcc.i686 openssl-devel.i686 gmp-devel.i686 libpcap-devel.i686
echo ""
echo ""
echo ""
echo ""
echo '******************************************************************************'
echo "now building/testing a 32 bit legacy NON-SIMD Linux build"
echo '******************************************************************************'
echo ""
make -s distclean
JOHN_CFLAGS=-m32 JOHN_ASFLAGS=-m32 JOHN_LDFLAGS=-m32 make -f Makefile.legacy -sj4 linux-x86-any
# do NOT exit on error from make.  We expect an error in the libpcap stuff
../run/john --list=build-info
echo "[Disabled:Formats]" > john-local.conf
../run/john -test-full=0
if [ "x$?" != "x0" ] ; then exit 1 ; fi

# now build a 32 bit SSE2 exe and test it
echo ""
echo ""
echo ""
echo ""
echo '******************************************************************************'
echo "now building/testing a 32 bit legacy SSE2 Linux build"
echo '******************************************************************************'
echo ""
make -f Makefile.legacy -s clean
JOHN_CFLAGS=-m32 JOHN_ASFLAGS=-m32 JOHN_LDFLAGS=-m32 make -f Makefile.legacy -sj4 linux-x86-sse2
# do NOT exit on error from make.  We expect an error in the libpcap stuff
../run/john --list=build-info
echo "[Disabled:Formats]" > john-local.conf
../run/john -test-full=0

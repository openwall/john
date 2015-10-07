#!/bin/bash
#
# now does mingw-64 build, and linux-64 no-sse2 build  (and tests both)

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

cd /base/JohnTheRipper/src
export PATH="$HOME/bin:$PATH"

# stop wine from messing around, during the build phase
# echo -1 > /proc/sys/fs/binfmt_misc/status
# umount /proc/sys/fs/binfmt_misc

mingw64 ./configure --host=x86_64-w64-mingw32
if [ "x$?" != "x0" ] ; then exit 1 ; fi
mingw64 make -sj4
if [ "x$?" != "x0" ] ; then exit 1 ; fi
mv ../run/john ../run/john.exe

# the mingw build does not name many exe files correctly.  Fix that.  Also strip all exe files for distro.
cd ../run
for f in `ls -l | grep wxr | grep -v [\.][epr] | cut -c 46-` ; do mv $f $f.exe ; done
for f in benchmark-unify mailer makechr relbench ; do mv $f.exe $f ; done
for f in *.exe ; do x86_64-w64-mingw32-strip $f ; done
cd ../src

basepath="/usr/x86_64-w64-mingw32/sys-root/mingw/bin"

find $basepath | grep "dll$"

cp "$basepath/libwinpthread-1.dll" ../run
cp "$basepath/zlib1.dll" ../run
cp "$basepath/libgmp-10.dll" ../run
cp "$basepath/libssl-10.dll" ../run
cp "$basepath/libcrypto-10.dll" ../run
cp "$basepath/libgomp-1.dll" ../run
cp "$basepath/libgcc_s_seh-1.dll" ../run

find ../run

v=`git rev-parse --short HEAD`
cd ..
mkdir /base/builds
zip -r /base/builds/JtR-MinGW-${v}.zip run/ doc/ README.md README README-jumbo

# crazy testing!
cd /base/JohnTheRipper/run
export WINEDEBUG=-all  # suppress wine warnings
/usr/bin/wine john.exe --list=build-info
echo "[Disabled:Formats]" > john-local.conf
echo ".include [Disabled:Formats_base]" >> john-local.conf
/usr/bin/wine john.exe --test-full=0
# if [ "x$?" != "x0" ] ; then exit 1 ; fi

# now build a non-SIMD 64 bit exe and test it
dnf install -y openssl openssl-devel zlib-devel gmp-devel libpcap-devel
echo ""
echo ""
echo ""
echo ""
echo '******************************************************************************'
echo "now testing a NON-SIMD build"
echo '******************************************************************************'
echo ""
cd /base/JohnTheRipper/src
make -s distclean
CPPFLAGS="-mno-sse2" ./configure
if [ "x$?" != "x0" ] ; then exit 1 ; fi
make -sj4
if [ "x$?" != "x0" ] ; then exit 1 ; fi
../run/john --list=build-info
echo "[Disabled:Formats]" > john-local.conf
echo ".include [Disabled:Formats_base]" >> john-local.conf
../run/john -test-full=0
if [ "x$?" != "x0" ] ; then exit 1 ; fi

# now build a non-SIMD 32 bit exe and test it
dnf install -y glibc-headers.i686 glibc.i686 glibc-devel.i686 libgcc.i686 openssl-devel.i686 gmp-devel.i686 libpcap-devel.i686
echo ""
echo ""
echo ""
echo ""
echo '******************************************************************************'
echo "now testing a 32 bit NON-SIMD build"
echo '******************************************************************************'
echo ""
make -s distclean
JOHN_CFLAGS=-m32 JOHN_ASFLAGS=-m32 JOHN_LDFLAGS=-m32 make -f Makefile.legacy -sj4 linux-x86-any
# do NOT exit on error from make.  We expect an error in the libpcap stuff
../run/john --list=build-info
echo "[Disabled:Formats]" > john-local.conf
echo ".include [Disabled:Formats_base]" >> john-local.conf
../run/john -test-full=0
if [ "x$?" != "x0" ] ; then exit 1 ; fi

# now build a 32 bit SSE2 exe and test it
echo ""
echo ""
echo ""
echo ""
echo '******************************************************************************'
echo "now testing a 32 bit SSE2 build"
echo '******************************************************************************'
echo ""
make -f Makefile.legacy -s clean
JOHN_CFLAGS=-m32 JOHN_ASFLAGS=-m32 JOHN_LDFLAGS=-m32 make -f Makefile.legacy -sj4 linux-x86-sse2
# do NOT exit on error from make.  We expect an error in the libpcap stuff
../run/john --list=build-info
echo "[Disabled:Formats]" > john-local.conf
echo ".include [Disabled:Formats_base]" >> john-local.conf
../run/john -test-full=0

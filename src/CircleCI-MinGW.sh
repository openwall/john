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

cd /base/JohnTheRipper/src
export PATH="$HOME/bin:$PATH"

# stop wine from messing around, during the build phase
# echo -1 > /proc/sys/fs/binfmt_misc/status
# umount /proc/sys/fs/binfmt_misc

mingw64 ./configure --host=x86_64-w64-mingw32
mingw64 make -sj4
mv ../run/john ../run/john.exe

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
/usr/bin/wine john.exe --test=0

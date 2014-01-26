Fedora >= 19 cross-compiling instructions
=========================================

32-bit builds
-------------

$ sudo yum install mingw32-openssl mingw32-openssl-static \
	mingw32-gcc mingw32-gcc-c++ -y

$ export GCC=/usr/bin/i686-w64-mingw32-gcc
$ export GXX=/usr/bin/i686-w64-mingw32-g++

$ make win32-mingw-x86-sse2

64-bit builds
-------------

$ sudo yum install mingw64-openssl mingw64-openssl-static \
	mingw64-gcc mingw64-gcc-c++ mingw64-winpthreads-static \
	mingw64-zlib-static mingw64-libgomp -y

$ export GCC=/usr/bin/x86_64-w64-mingw32-gcc
$ export GXX=/usr/bin/x86_64-w64-mingw32-g++

$ make win64-mingw-x86-64

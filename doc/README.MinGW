Fedora >= 22 cross-compiling instructions
=========================================

32-bit builds
-------------

$ sudo dnf install mingw32-openssl mingw32-openssl-static \
	mingw32-gcc mingw32-gcc-c++ binutils -y

$ ./configure --host=i686-w64-mingw32

$ make -sj4

64-bit builds
-------------

$ sudo dnf install mingw64-openssl mingw64-openssl-static \
	mingw64-gcc mingw64-gcc-c++ mingw64-winpthreads-static \
	mingw64-zlib-static mingw64-libgomp mingw64-binutils -y

$ ./configure --host=x86_64-w64-mingw32

$ make -sj4

Notes
-----

Ubuntu (and similar systems) do not have a full MinGW environment.

configure on my newest 64 bit Fedora required this:

AR=/usr/bin/x86_64-w64-mingw32-ar STRIP=/usr/bin/x86_64-w64-mingw32-strip \
	OPENSSL_LIBS="-lssl -lcrypto" ./configure --host=x86_64-w64-mingw32 \
	--build=x86_64-pc-linux

configure was not setting ar or strip properly. I have wine installed, so
without the --build the configure was NOT thinking it was doing a cross
compile. Also, the OPENSSL_LIBS had to be force listed for this cross
compile to link right.

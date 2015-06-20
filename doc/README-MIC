
Intel MIC (Xeon Phi) is a coprocessor computer architecture developed by Intel.
Program built for MIC cannot run on normal Intel processors. So you need to 
have a MIC coprocessor and related enviroments setup before trying to build 
John the Ripper (JtR) for MIC. Tutorial on how to setup the software 
environments for MIC can be found on Intel's website.


-----------------------
Library Denpendencies:
-----------------------

JtR requires some libraries that are not available on MIC, which means you'll 
need to build them for MIC by yourself.
These libraries are:
    Zlib (libz)
    GMP (libgmp)
    OpenSSL/LibreSSL (libssl & libcrypto)

They can be downloaded from their websites. But building them requires some 
effort, and only the mentioned versions are guaranteed to work.  
Assuming those libraries are to be install under path $MIC and the path to
JtR is $JOHN, then follow the steps below.

Build Zlib (version 1.2.8):
$ cd */zlib-1.2.8
$ CC="icc -mmic" ./configure --prefix=$MIC
$ make && make install

Build GMP (version 6.0.0a):
$ cd */gmp-6.0.0
$ ./configure CC="icc -mmic" --host=k1om --prefix=$MIC
$ make && make install

OpenSSL and LibreSSL offer almost the same functionality, you can use either one
as convenient.

Build OpenSSL (version 1.0.2a)
$ cd */openssl-1.0.2a
$ ./Configure linux-x86_64-icc -mmic no-asm shared --prefix=$MIC
$ make && make install

Build LibreSSL (version 2.1.6):
$ cd libressl-2.1.6
$ ./configure CC="icc -mmic" --host=k1om-linux --prefix=$MIC
$ make && make install


--------------
Building JtR:
--------------

After building those libraries, now it's straightforward to build JtR for MIC.

$ cd $JOHN/src
$ ./configure CC="icc -mmic" CPPFLAGS="-I$MIC/include" LDFLAGS="-L$MIC/lib" --host=mic-linux
$ make && make install

After that, you can use scp to transfer the executables and config files you 
need under directory $JOHN/run to MIC. 
You also need to transfer some dynamic libraries to MIC, which is requried by 
JtR at runtime, including those mentioned above (under $MIC/lib) and the 
following:
    libiomp*
    libimf
    libirng
    libintlc
    libsvml
They can be found under /opt/intel/lib/mic or some other directory you
specified when installing Intel compiler.


---------
Contact:
---------

If you still have problem building JtR for MIC, feel free to contact
<zhanglei.april@gmail.com> or JtR's mailing list.

Have fun.
Lei Zhang

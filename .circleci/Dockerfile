FROM fedora:rawhide
MAINTAINER dhiru

RUN rpm -e --nodeps gdbm

RUN dnf install mingw64-openssl mingw64-openssl-static \
mingw64-gcc mingw64-gcc-c++ mingw64-winpthreads-static \
mingw64-zlib-static mingw64-libgomp binutils git make \
automake gcc gcc-c++ zip findutils mingw64-gmp \
mingw64-wpcap wine -y

RUN dnf install mingw32-openssl mingw32-openssl-static \
mingw32-gcc mingw32-gcc-c++ mingw32-winpthreads \
mingw32-zlib mingw32-openssl-static mingw32-openssl \
mingw32-wpcap mingw32-winpthreads-static -y

RUN dnf install openssl openssl-devel zlib-devel \
gmp-devel libpcap-devel bzip2-devel -y

RUN dnf install glibc-headers.i686 glibc.i686 glibc-devel.i686 \
libgcc.i686 openssl-devel.i686 gmp-devel.i686 \
libpcap-devel.i686 bzip2-devel.i686 -y

# docker build -t dhiru/fedora:28 .
# docker login
# docker push dhiru/fedora:28
# docker run -it dhiru/fedora:28 /bin/bash

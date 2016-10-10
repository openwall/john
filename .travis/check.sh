#!/bin/bash

if [[ "$FRESH" != "yes" ]]; then
    cd src

    # Configure and build
    ./configure $ASAN
    make -sj4

    ../.travis/test.sh

else
   docker run -v $HOME:/root -v $(pwd):/cwd ubuntu:latest sh -c ' \
      cd /cwd/src; \
      apt-get update -qq; \
      apt-get install -y build-essential libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev libbz2-dev; \
      ./configure --enable-asan; \
      make -sj4; \
      ASAN="fresh" ../.travis/test.sh
  '

#   docker run -v $HOME:/root -v $(pwd):/cwd centos:latest sh -c ' \
#      cd /cwd/src; \
#      yum update -y; \
#      yum groupinstall -y 'Development Tools'; \
#      yum install -y openssl-devel gmp-devel libpcap-devel pkgconfig libnet-devel bzip2-devel; \
#      ./configure --enable-asan; \
#      make -sj4; \
#      ../.travis/test.sh
#  '
fi


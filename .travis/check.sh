#!/bin/bash

if [[ "$FRESH" != "yes" ]]; then
    cd src
    export LOG=$(git log -n 1)

    if [[ $LOG == *'[no asan]'* ]]; then 
        export ASAN=""
    fi

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
#      dnf update -y; \
#      dnf install -y build-essential libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev; \
#      ./configure --enable-asan; \
#      make -sj4; \
#      ../.travis/test.sh
#  '
fi


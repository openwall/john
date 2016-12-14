#!/bin/bash

if [[ "$TEST" == "basic" ]]; then
    cd src

    # Prepare environment
    sudo apt-get update -qq
    sudo apt-get install libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev
    sudo apt-get install fglrx-dev opencl-headers || true

    # Configure and build
    ./configure $ASAN $BUILD_OPTS
    make -sj4

    ../.travis/test.sh

elif [[ "$TEST" == "fresh" ]]; then
    # ASAN using a 'recent' compiler
    docker run -v $HOME:/root -v $(pwd):/cwd ubuntu:16.10 sh -c " \
      cd /cwd/src; \
      apt-get update -qq; \
      apt-get install -y build-essential libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev libbz2-dev; \
      ./configure --enable-asan; \
      make -sj4; \
      export OPENCL="""$OPENCL"""; \
      PROBLEM='slow' ../.travis/test.sh
   "

elif [[ "$TEST" == "TS --restore" ]]; then
    # Test Suite run
    cd src

    # Prepare environment
    sudo apt-get update -qq
    sudo apt-get install libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev

    # Configure and build
    ./configure
    make -sj4

    cd ..
    git clone --depth 1 https://github.com/magnumripper/jtrTestSuite.git tests
    cd tests
    #export PERL_MM_USE_DEFAULT=1
    (echo y;echo o conf prerequisites_policy follow;echo o conf commit)|cpan
    cpan install Digest::MD5
    ./jtrts.pl --restore

elif [[ "$TEST" == "TS docker" ]]; then
    # Test Suite run
    docker run -v $HOME:/root -v $(pwd):/cwd ubuntu:xenial sh -c ' \
      cd /cwd/src; \
      apt-get update -qq; \
      apt-get install -y build-essential libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev libbz2-dev git; \
      ./configure; \
      make -sj4; \
      cd ..; \
      git clone --depth 1 https://github.com/magnumripper/jtrTestSuite.git tests; \
      cd tests; \
      cpan install Digest::MD5; \
      ./jtrts.pl --restore
    '
else
    echo
    echo  -----------------
    echo  "Nothing to do!!"
    echo  -----------------
fi


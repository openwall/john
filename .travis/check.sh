#!/bin/bash

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
    # brew install --force openssl
    cd src

    ./configure --enable-werror CPPFLAGS="-I/usr/local/opt/openssl/include" LDFLAGS="-L/usr/local/opt/openssl/lib"
    make -sj4

    ../.travis/test.sh

elif [[ -z "$TEST" || "$TEST" == "encoding" ]]; then
    cd src

    # Build and run with the address sanitizer instrumented code
    export ASAN_OPTIONS=symbolize=1
    export ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)

    # Prepare environment
    sudo apt-get update -qq
    sudo apt-get install libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev libiomp-dev

    if [[ "$OPENCL" == "yes" ]]; then
        sudo apt-get install fglrx-dev opencl-headers || true

        # Fix the OpenCL stuff
        mkdir -p /etc/OpenCL
        mkdir -p /etc/OpenCL/vendors
        sudo ln -sf /usr/lib/fglrx/etc/OpenCL/vendors/amdocl64.icd /etc/OpenCL/vendors/amd.icd
    fi

    if [[ ! -f /usr/lib/x86_64-linux-gnu/libomp.so ]]; then
        # A bug somewhere?
        sudo ln -sf /usr/lib/libiomp5.so /usr/lib/x86_64-linux-gnu/libomp.so
    fi

    # Configure and build
    ./configure --enable-werror $ASAN
    make -sj4

    ../.travis/test.sh "$TEST"

elif [[ "$TEST" == "fresh test" ]]; then
    # ASAN using a 'recent' compiler
    docker run -v $HOME:/root -v $(pwd):/cwd ubuntu:rolling sh -c " \
      cd /cwd/src; \
      apt-get update -qq; \
      apt-get install -y build-essential libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev libbz2-dev libomp-dev; \
      ./configure --enable-werror --enable-asan; \
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
    ./configure --enable-werror
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
      ./configure --enable-werror; \
      make -sj4; \
      cd ..; \
      git clone --depth 1 https://github.com/magnumripper/jtrTestSuite.git tests; \
      cd tests; \
      cpan install Digest::MD5; \
      ./jtrts.pl --restore
    '
else
    echo  "Nothing to do!!"
fi

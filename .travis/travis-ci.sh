#!/bin/bash

######################################################################
# Copyright (c) 2019 Claudio André <claudioandre.br at gmail.com>
#
# This program comes with ABSOLUTELY NO WARRANTY; express or implied.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, as expressed in version 2, seen at
# http://www.gnu.org/licenses/gpl-2.0.html
######################################################################

function do_Install_Dependencies(){
    echo
    echo '-- Installing Base Dependencies --'

    # Prepare environment
    sudo apt-get update -qq
    sudo apt-get -y -qq install \
        build-essential libssl-dev yasm libgmp-dev libpcap-dev pkg-config \
        debhelper libnet1-dev libbz2-dev wget clang llvm zlib1g-dev wget > /dev/null

    if [[ "$_system_version" != "12.04" ]]; then
        # Ubuntu precise doesn't have this package
        sudo apt-get -y -qq install \
            libiomp-dev > /dev/null
    fi

    if [[ ! -f /usr/lib/x86_64-linux-gnu/libomp.so ]]; then
        # A bug somewhere?
        sudo ln -sf /usr/lib/libiomp5.so /usr/lib/x86_64-linux-gnu/libomp.so
    fi

    if [[ "$TEST" == *";OPENCL;"* ]]; then
        sudo apt-get -y -qq install fglrx-dev opencl-headers || true

        # Fix the OpenCL stuff
        mkdir -p /etc/OpenCL
        mkdir -p /etc/OpenCL/vendors
        sudo ln -sf /usr/lib/fglrx/etc/OpenCL/vendors/amdocl64.icd /etc/OpenCL/vendors/amd.icd
    fi
}

function do_Build(){

    if [[ "$TEST" == *"MacOS"* ]]; then
        BASE="Apple MacOS"
    else
        BASE="Ubuntu"
    fi
    TASK_RUNNING="$TEST"
    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/show_info.sh
    source show_info.sh

    echo
    echo '-- Building JtR --'

    # Configure and build
    cd src || exit 1
    eval ./configure "$ASAN_OPT $BUILD_OPTS"
    make -sj2
}

function do_Prepare_To_Test(){
    echo
    echo '-- Preparing to test --'

    # Environmnet
    do_Install_Dependencies

    # Configure and build
    do_Build
}

function do_TS_Setup(){
    echo
    echo '-- Test Suite set up --'

    # Prepare environment
    cd .. || exit 1
    git clone --depth 1 https://github.com/magnumripper/jtrTestSuite.git tests
    cd tests || exit 1
    #export PERL_MM_USE_DEFAULT=1
    (echo y;echo o conf prerequisites_policy follow;echo o conf commit)|cpan
    cpan install Digest::MD5

    # copy the needed john-local.conf to the run folder
    echo "### Adding ###" >> ../run/john-local.conf
    cat john-local.conf >> ../run/john-local.conf
}

function do_Build_Docker_Command(){
    echo
    echo '-- Build Docker command --'

    if [[ true ]]; then
        update="\
          apt-get update -qq; \
          apt-get install -y -qq build-essential libssl-dev yasm libgmp-dev libpcap-dev pkg-config debhelper libnet1-dev libbz2-dev wget llvm libomp-dev zlib1g-dev git > /dev/null; "

        if [[ "$TEST" == *";POCL;"* ]]; then
            update="$update apt-get install -y -qq libpocl-dev ocl-icd-libopencl1 pocl-opencl-icd opencl-headers;"
            export OPENCL="yes"
        fi

        if [[ "$TEST" == *";clang;"* ]]; then
            update="$update apt-get install -y -qq clang;"
        fi

        if [[ "$TEST" == *"experimental;"* ]]; then
            update="$update apt-get install -y -qq software-properties-common;"
            update="$update add-apt-repository -y ppa:ubuntu-toolchain-r/test;"
            update="$update apt-get update -qq;"
            update="$update apt-get install -y -qq gcc-snapshot;"
            update="$update update-alternatives --install /usr/bin/gcc gcc /usr/lib/gcc-snapshot/bin/gcc 60 --slave /usr/bin/g++ g++ /usr/lib/gcc-snapshot/bin/g++;"
        fi
    fi

    docker_command=" \
      cd /cwd; \
      $update \
      export OPENCL=$OPENCL; \
      export CC=$CCO; \
      export TEST='$TEST'; \
      export TRAVIS_COMPILER=$TRAVIS_COMPILER; \
      export FUZZ=$FUZZ; \
      export ASAN_OPT=$ASAN_OPT; \
      export BUILD_OPTS='$BUILD_OPTS'; \
      echo; \
      $0 DO_BUILD; \
      cd /cwd/src; \
      ../.travis/CI-tests.sh
   "
}

function do_Build_Docker_Command_Image(){
    echo
    echo '-- Build Docker command --'

    if [[ "$TEST" == *";POCL;"* ]]; then
        export OPENCL="yes"
    fi

    docker_command=" \
      cd /cwd; \
      export OPENCL=$OPENCL; \
      export CC=$CCO; \
      export TEST='$TEST'; \
      export TRAVIS_COMPILER=$TRAVIS_COMPILER; \
      export FUZZ=$FUZZ; \
      export ASAN_OPT=$ASAN_OPT; \
      export BUILD_OPTS='$BUILD_OPTS'; \
      echo; \
      $0 DO_BUILD; \
      cd /cwd/src; \
      ../.travis/CI-tests.sh
   "
}

# Do the build inside Docker
if [[ "$1" == "DO_BUILD" ]]; then
    do_Build
    exit 0
fi

# Set up environment
if [[ "$TEST" == *";ASAN;"* ]]; then
    export ASAN_OPT="--enable-asan"
fi

if [[ "$TEST" == *";OPENCL;"* ]]; then
    export OPENCL="yes"
fi

if [[ "$TEST" == *";gcc;"* || "$TEST" == *";experimental;"* ]]; then
    export CCO="gcc"
fi

if [[ "$TEST" == *";clang;"* ]]; then
    export CCO="clang"
fi

if [[ "$TEST" == *";afl-clang-fast;"* ]]; then
    export CCO="afl-clang-fast"
fi

if [[ "$TEST" == *"usual;"* ]]; then
    # Needed on ancient ASAN
    export ASAN_OPTIONS=symbolize=1
    export ASAN_SYMBOLIZER_PATH
    ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)

    # Configure and build
    do_Prepare_To_Test

    # Run the test: --test-full=0
    ../.travis/CI-tests.sh

elif [[ "$TEST" == *"MacOS;"* ]]; then
    # Configure and build
    do_Build

    # Run the test: --test-full=0
    ../.travis/CI-tests.sh

elif [[ "$TEST" == *"ztex;"* ]]; then
    # Build the docker command line
    do_Build_Docker_Command_Image

    # Run docker
    docker run --cap-add SYS_PTRACE -v "$HOME":/root -v "$(pwd)":/cwd claudioandre/john:ubuntu.rolling sh -c "$docker_command"

elif [[ "$TEST" == *"fresh;"* ]]; then
    # Build the docker command line
    do_Build_Docker_Command_Image

    # Run docker
    docker run --cap-add SYS_PTRACE -v "$HOME":/root -v "$(pwd)":/cwd claudioandre/john:ubuntu.devel sh -c "$docker_command"

elif [[ "$TEST" == *"experimental;"* ]]; then
    # Build the docker command line
    do_Build_Docker_Command

     # Run docker
     docker run --cap-add SYS_PTRACE -v "$HOME":/root -v "$(pwd)":/cwd ubuntu:devel sh -c "$docker_command"

elif [[ "$TEST" == *"OpenCL;"* ]]; then
    # What is working for OpenCL
    # Build the docker command line
    do_Build_Docker_Command_Image

    # Run docker
    docker run --cap-add SYS_PTRACE -v "$HOME":/root -v "$(pwd)":/cwd claudioandre/john:ubuntu.opencl sh -c "$docker_command"

elif [[ "$TEST" == *"centos6;"* ]]; then
    # Stable environment (compiler/OS)
    # Build the docker command line
    do_Build_Docker_Command_Image

    # Run docker
    docker run -v "$HOME":/root -v "$(pwd)":/cwd claudioandre/john:centos.6 sh -c "$docker_command"

elif [[ "$TEST" == *"snap;"* ]]; then
    # Prepare environment
    sudo apt-get update -qq
    sudo apt-get install snapd

    # Install and test
    sudo snap install --channel=edge john-the-ripper

    # Run the test
    .travis/CI-tests.sh

elif [[ "$TEST" == *"TS"* ]]; then
    # Configure and build
    do_Prepare_To_Test

    # Test Suite set up
    do_TS_Setup

    if [[ "$TEST" == *"TS --restore;"* ]]; then
        # Run the test: Test Suite --restore
        ./jtrts.pl --restore

    elif [[ "$TEST" == *"TS --internal;"* ]]; then
        # Run the test: Test Suite --internal
        ./jtrts.pl -noprelims -internal
    else
        # Run the test: Test Suite
        if [[ "$TEST" != *";OPENCL;"* ]]; then
            ./jtrts.pl -stoponerror -dynamic none
        else
            ./jtrts.pl -noprelims -type opencl
        fi
    fi

else
    echo
    echo  -----------------
    echo  "Nothing to do!!"
    echo  -----------------
fi
# --------- General notes ---------
# 'Recent' environment (compiler/OS)
# clang 4 + ASAN + libOpenMP + fork are not working on CI.

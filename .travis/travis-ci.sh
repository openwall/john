#!/bin/bash

# Need a docker image to run the tests
if [[ "$DOCKER" == "yes" ]]; then
    docker run --cap-add SYS_PTRACE -v "$(pwd)":/cwd claudioandre/john:opencl sh -c \
      "
        cd /cwd; \
        export OPENCL=$OPENCL; \
        export CC=$TRAVIS_COMPILER; \
        export BUILD_OPTS='$BUILD_OPTS'; \
        echo; \
        $0;
      "
    exit $?
fi

# ---- Build and test JtR ----
cd src

# The testing binary
JTR=../run/john

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
    ./configure --enable-werror CPPFLAGS="-I/usr/local/opt/openssl/include" LDFLAGS="-L/usr/local/opt/openssl/lib"
    make -sj4
else
    # Address sanitizer instrumented code
    export ASAN_OPTIONS=symbolize=1
    export ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)

    if [[ "$OPENCL" == "yes" && "$TRAVIS_DIST" == "trusty" ]]; then
        # Fix the OpenCL stuff
        mkdir -p /etc/OpenCL/vendors
        sudo ln -sf /usr/lib/fglrx/etc/OpenCL/vendors/amdocl64.icd /etc/OpenCL/vendors/amd.icd
    fi

    # Configure and build
    ./configure --enable-werror $BUILD_OPTS
    make -sj4
fi

# Disable problematic formats before testing
source ../.ci/disable_formats.sh

echo '---------------------------------- Build Info ----------------------------------'
$JTR --list=build-info
echo '--------------------------------------------------------------------------------'

# Except for MacOS, split tests
if [[ "$OPENCL" == "yes" && "$TRAVIS_OS_NAME" != "osx" ]]; then
    echo '-- Running $JTR -test=0 --format=opencl --'
    $JTR -test=0 --format=opencl
else
    echo '-- Running $JTR -test=0 --'
    $JTR -test=0
fi


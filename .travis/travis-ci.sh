#!/bin/bash

env

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

# Build and test JtR
cd src

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
    ./configure --enable-werror CPPFLAGS="-I/usr/local/opt/openssl/include" LDFLAGS="-L/usr/local/opt/openssl/lib"
    make -sj4
else
    # Build and run with the address sanitizer instrumented code
    export ASAN_OPTIONS=symbolize=1
    export ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer)

    if [[ "$OPENCL" == "yes" ]]; then
        # Fix the OpenCL stuff
        mkdir -p /etc/OpenCL/vendors
        sudo ln -sf /usr/lib/fglrx/etc/OpenCL/vendors/amdocl64.icd /etc/OpenCL/vendors/amd.icd
    fi

    # Configure and build
    ./configure --enable-werror $BUILD_OPTS
    make -sj4
fi

# There was (at least) a bug in echo -e in Travis
# TODO: we know these formats must be fixed (or removed)
echo '[Local:Disabled:Formats]' > john-local.conf
echo 'Raw-SHA512-free-opencl = Y' >> john-local.conf
echo 'XSHA512-free-opencl = Y' >> john-local.conf
echo 'gpg-opencl = Y' >> john-local.conf
echo 'KeePass-opencl = Y' >> john-local.conf
echo 'scrypt = Y' >> john-local.conf
echo 'django-scrypt = Y' >> john-local.conf
echo 'multibit = Y' >> john-local.conf

# These formats fails OpenCL CPU runtime
echo 'lotus5-opencl = Y' >> john-local.conf
echo 'pgpdisk-opencl = Y' >> john-local.conf

# Show build info
echo '---------------------------------- Build Info ----------------------------------'
../run/john --list=build-info
echo '--------------------------------------------------------------------------------'

# Except for MacOS, split tests
if [[ "$OPENCL" == "yes" && "$TRAVIS_OS_NAME" != "osx" ]]; then
    echo '$ ../run/john -test=0 --format=opencl'
    ../run/john -test=0 --format=opencl
else
    echo '$ ../run/john -test=0'
    ../run/john -test=0
fi


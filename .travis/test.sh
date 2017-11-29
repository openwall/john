#!/bin/sh -e

do_test_encoding() {
    echo "Testing $1"
    ../run/john -test-full=0 --format="$1" --encoding=utf8
    echo
    ../run/john -test-full=0 --format="$1" --encoding=cp737
    echo "Done $1"
}

# There is a bug in echo -e in Travis
echo '[Local:Disabled:Formats]' > john-local.conf
echo 'Raw-SHA512-free-opencl = Y' >> john-local.conf
echo 'XSHA512-free-opencl = Y' >> john-local.conf
echo 'gpg-opencl = Y' >> john-local.conf

if test "$1" = "encoding" ; then
    do_test_encoding cpu

    if test "$OPENCL" = "yes" ; then
        do_test_encoding opencl
    fi
else

    # Proper testing. Trusty AMD GPU drivers on Travis are fragile
    if test "$PROBLEM" = "slow" ; then
        ../run/john -test=0 --format=cpu
    else
        ../run/john -test-full=0 --format=cpu
    fi

    if test "$TRAVIS_OS_NAME" = "osx" ; then
        do_test_encoding cpu
    fi

    if test "$OPENCL" = "yes" ; then
        ../run/john -test-full=0 --format=opencl

        if test "$TRAVIS_OS_NAME" = "osx" ; then
            do_test_encoding opencl
        fi
    fi
fi


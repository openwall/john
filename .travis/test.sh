#!/bin/sh -e

# There is a bug in echo -e in Travis
echo '[Local:Disabled:Formats]' > john-local.conf
echo 'Raw-SHA512-free-opencl = Y' >> john-local.conf
echo 'XSHA512-free-opencl = Y' >> john-local.conf
echo 'gpg-opencl = Y' >> john-local.conf

if test "$1" = "encoding" ; then
    ../run/john -test-full=0 --format=cpu --encoding=utf8
    echo
    ../run/john -test-full=0 --format=cpu --encoding=cp737

    if test "$OPENCL" = "yes" ; then
        ../run/john -test-full=0 --format=opencl --encoding=utf8
        echo
        ../run/john -test-full=0 --format=opencl --encoding=cp737
    fi
else

    # Proper testing. Trusty AMD GPU drivers on Travis are fragile
    if test "$PROBLEM" = "slow" ; then
        ../run/john -test=0 --format=cpu
    else
        ../run/john -test-full=0 --format=cpu
    fi

    if test "$OPENCL" = "yes" ; then
        ../run/john -test-full=0 --format=opencl
    fi
fi


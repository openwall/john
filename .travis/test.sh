#!/bin/sh -e

# There is a bug in echo -e in Travis
echo '[Local:Disabled:Formats]' > john-local.conf
echo 'Raw-SHA512-free-opencl = Y' >> john-local.conf
echo 'XSHA512-free-opencl = Y' >> john-local.conf
echo 'gpg-opencl = Y' >> john-local.conf

# Proper testing. Trusty AMD GPU drivers on Travis are fragile
if test "$PROBLEM" = "slow" ; then
    ../run/john -test=0 --format=cpu
    ../run/john -test=0 --format=cpu --encoding=utf8
    ../run/john -test=0 --format=cpu --encoding=cp737
else
    ../run/john -test-full=0 --format=cpu
    ../run/john -test-full=0 --format=cpu --encoding=utf8
    ../run/john -test-full=0 --format=cpu --encoding=cp737
fi

if test "$OPENCL" = "yes" ; then
    ../run/john -test-full=0 --format=opencl
    ../run/john -test-full=0 --format=opencl --encoding=utf8
    ../run/john -test-full=0 --format=opencl --encoding=cp737
fi


#!/bin/sh -e

# There is a bug in echo -e in Travis
echo '[Disabled:Formats]' > john-local.conf
echo 'Raw-SHA512-free-opencl = Y' >> john-local.conf
echo 'XSHA512-free-opencl = Y' >> john-local.conf
echo 'gpg-opencl = Y' >> john-local.conf

# Proper testing. Trusty AMD GPU drivers on Travis are fragile
if test "$ASAN" = "fresh" ; then
    ../run/john -test=0 --format=cpu
else
    ../run/john -test-full=0 --format=cpu
fi

if test -z "$ASAN" -o "$OPENCL" = "yes" ; then
    ../run/john -test-full=0 --format=opencl
fi


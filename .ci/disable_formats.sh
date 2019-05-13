#!/bin/bash -e

# There was a bug in echo -e in Travis
# TODO: we know these formats must be fixed (or removed)
echo '[Local:Disabled:Formats]' > john-local.conf
echo 'Raw-SHA512-free-opencl = Y' >> john-local.conf
echo 'XSHA512-free-opencl = Y' >> john-local.conf
echo 'gpg-opencl = Y' >> john-local.conf
echo 'KeePass-opencl = Y' >> john-local.conf

# These formats fails OpenCL CPU runtime
echo 'lotus5-opencl = Y' >> john-local.conf
echo 'pgpdisk-opencl = Y' >> john-local.conf

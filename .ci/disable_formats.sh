#!/bin/bash -e

# There was a bug in echo -e in Travis
# TODO: we know these formats must be fixed (or removed)
echo '[Local:Disabled:Formats]' > ../run/john-local.conf
echo 'Raw-SHA512-free-opencl = Y' >> ../run/john-local.conf
echo 'XSHA512-free-opencl = Y' >> ../run/john-local.conf
echo 'gpg-opencl = Y' >> ../run/john-local.conf
echo 'KeePass-opencl = Y' >> ../run/john-local.conf

# These formats fails OpenCL CPU runtime
echo 'lotus5-opencl = Y' >> ../run/john-local.conf
echo 'pgpdisk-opencl = Y' >> ../run/john-local.conf

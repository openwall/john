#!/bin/bash -e
#
# Edit this script for testing current issue, place it in base directory
# (at same level as src, doc, run)
#
# Run with `git bisect run ./bisect.script.sh`
#
# This script should exit with return code 0 for "good" and 1 for "bad"
# return code 125 is special for "could not test" (eg. "could not build")
#
# To checkout some date, use eg:
# `git checkout bleeding-jumbo@{2017-11-08}`
#
COMMIT=`git rev-parse HEAD`
cd src
./configure --disable-openmp --disable-opencl --disable-cuda --disable-rexgen || exit 125
make -s clean || exit 125
make -sj8 || exit 125

# Optionally save all binaries during bisecting
#cp -av ../run/john ../run/john.$COMMIT

# Here's the test, you probably want to replace it
../run/john --incremental=digits --mask=?w?d --min-length=2 --max-length=2 --stdout -max-cand=10 > result.txt || exit 125
grep -q "#" result.txt && exit 1
exit 0

if [ $LINES -eq 22 ]; then
	echo "******** GOOD! ********"
	exit 0
else
	echo "******** BAD! ********"
	exit 1
fi

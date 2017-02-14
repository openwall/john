#!/bin/sh -e

# There is a bug in echo -e in Travis
echo '[Disabled:Formats]' > john-local.conf
echo 'Raw-SHA512-free-opencl = Y' >> john-local.conf
echo 'XSHA512-free-opencl = Y' >> john-local.conf
echo 'gpg-opencl = Y' >> john-local.conf

# Proper testing. Trusty AMD GPU drivers on Travis are fragile
if test "$PROBLEM" = "slow" ; then
    ../run/john -test=0 --format=cpu
else
    ../run/john -test-full=0 --format=cpu
fi

if test "$OPENCL" = "yes" ; then
    ../run/john -test-full=0 --format=opencl
fi

if test "$EXTRAS" = "yes" ; then
    wget http://openwall.info/wiki/_media/john/KeePass-samples.tar
    wget http://openwall.info/wiki/_media/john/rar_sample_files.tar
    wget http://openwall.info/wiki/_media/john/zip_sample_files.tar
    wget http://openwall.info/wiki/_media/john/test.gpg.tar.gz
    tar -xopf KeePass-samples.tar
    tar -xopf rar_sample_files.tar
    tar -xopf zip_sample_files.tar
    tar -xozf test.gpg.tar.gz

    ../run/gpg2john *.asc > file1
    ../run/rar2john *.rar > file2
    ../run/zip2john *.zip > file3
    ../run/keepass2john keepass2.kdbx > file4

    # Tests
    ../run/john file1
    ../run/john file2 --wordlist
    ../run/john file3
    ../run/john file4
fi

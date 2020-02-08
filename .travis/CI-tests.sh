#!/bin/bash -e

######################################################################
# Copyright (c) 2019 Claudio André <claudioandre.br at gmail.com>
#
# This program comes with ABSOLUTELY NO WARRANTY; express or implied.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, as expressed in version 2, seen at
# http://www.gnu.org/licenses/gpl-2.0.html
######################################################################

#------------------------------------------------------
#                     Random Tests
#------------------------------------------------------
do_Test () {
    echo
    echo "==> ($1)"
    TEMP=$(mktemp _tmp_output.XXXXXXXX)
    TO_RUN="$1"

    # Do not exit (abort Travis) if the command returns a non-zero status
    set +e
    eval "$TO_RUN" 2>&1 | tee $TEMP; ret_code=${PIPESTATUS[0]}
    echo "====> ($ret_code)"
    set -e

    if [[ "$5" == "ERROR" ]]; then
        read RESULT <<< $(cat $TEMP | grep "$2")

        if [[ -z $RESULT || $ret_code -eq 0 ]]; then
            echo --------------------------------------------
            echo "Test: ($1) FAILED"
            echo --------------------------------------------
            echo
            exit 1
        fi
        echo "Test: ($1) failed, as expected ($ret_code)."

    else

        if [[ $ret_code -ne 0 ]]; then
            read MAX_TIME <<< $(echo $1 | awk '/-max-/ { print 1 }')

            if ! [[ $ret_code -eq 1 && "$MAX_TIME" == "1" ]]; then
                echo "ERROR ($ret_code): $TO_RUN"
                echo

                exit 1
            fi
        fi

        if [[ $3 -lt 0 ]]; then
            read RESULT <<< $(cat $TEMP | grep "$2")

            if [[ -z $RESULT ]]; then
                echo --------------------------------------------
                echo "Test: ($1) FAILED"
                echo --------------------------------------------
                echo
                exit 1
            fi
        else
            read R1 <<< $(cat $TEMP | grep -E '[0-9]+ password' | grep -o '[0-9]*' | sed -n '1p')
            read R2 <<< $(cat $TEMP | grep -E '[0-9]+ password' | grep -o '[0-9]*' | sed -n '2p')

            if [[ -z $R1 ]] || [[ -z $R2 ]]; then
                echo --------------------------------------------
                echo "Test: ($1) FAILED: |$R1| |$R2|"
                echo --------------------------------------------
                echo
                exit 1
            fi

            if [[ $3 -ne $R1 ]] || [[ $4 -ne $R2 ]]; then
                echo --------------------------------------------
                echo "Test: ($1) FAILED"
                echo "- Expected values: [$3 $4]; found: [$R1 $R2]"
                echo --------------------------------------------
                echo
                exit 1
            fi
        fi
    fi
    Total_Tests=$((Total_Tests + 1))

    #-- Remove the tmp file.
    rm $TEMP
}

# ---- Show JtR Build Info ----
if [[ "$TEST" == *"snap;"* ]];  then
    JtR="john"
else
    JtR="../run/john"
fi

echo '--------------------------------'
"$JtR" -help
echo '--------------------------------'
"$JtR" -list=build-info
echo '--------------------------------'

# Extra testing
if [[ -z "${TEST##*EXTRAS*}" ]]; then
    # Get some data from wiki
    echo --------------------------------------------
    wget http://openwall.info/wiki/_media/john/KeePass-samples.tar
    wget http://openwall.info/wiki/_media/john/rar_sample_files.tar
    wget http://openwall.info/wiki/_media/john/zip_sample_files.tar
    wget http://openwall.info/wiki/_media/john/test.gpg.tar.gz
    tar -xopf KeePass-samples.tar
    tar -xopf rar_sample_files.tar
    tar -xopf zip_sample_files.tar
    tar -xozf test.gpg.tar.gz

    # UTF-8 tests
    echo --------------------------------------------
    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/answers
    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/specials

    # Prepare for tests
    echo --------------------------------------------
    ../run/zip2john *.zip > ~/file1
    ../run/keepass2john keepass2.kdbx > ~/file2
    ../run/gpg2john *.asc > ~/file4
    ../run/rar2john *.rar > ~/file10

    echo --------------------------------------------
    echo '$SHA512$cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e' > ~/self
    echo '$SHA512$b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86' >> ~/self
    echo '$SHA512$fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe' >> ~/self
    echo '$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.' >> ~/self

    echo '6.doc:$oldoffice$1*f6391b03f90cf0d10b66b4116463ac20*1d0e3dd64b92265e6907ccf50c1b10bc*e0ce0f57ba306386294b634c9e099c66:::::/home/jim/rc/tmp/2/origin/20170509172828116.doc' >> ~/self
    echo '8.doc:$oldoffice$1*70744b12ffe9f9956638a28f17a4d9c4*60d9a9c5b462395be03b20c3ce52f38c*6e4e29c224b5a8137296b6d2490feba8:::::/home/jim/rc/tmp/2/origin/20170509172828141.doc' >> ~/self
    echo 'XXX.zip:$pkzip2$1*2*2*0*10*4*7f808508*0*41*0*10*7f80*7319*8fe32c524ec41bc23f18d30fd3641020*$/pkzip2$:::::XXX.zip' >> ~/self
    echo 'XXX.zip:$pkzip2$1*2*2*0*10*4*7f808508*0*41*0*10*7f80*7319*30fc1e61e10e8d79ec55a90d58121392*$/pkzip2$:::::/home/claudio/Downloads/XXX.zip' >> ~/self

    echo --------------------------------------------
    for i in `../run/john -inc -stdout | head -1000 | shuf | head -30`; do echo -n $i | md5sum  | cut -d" " -f1; done > ~/file3 # openssl md5
    for i in `../run/john -inc -stdout | head -1000 | shuf | head -30`; do echo -n $i | sha1sum | cut -d" " -f1; done > ~/file5
    for i in `../run/john -inc -stdout | head -100                   `; do echo -n $i | md5sum  | cut -d" " -f1; done > ~/file6

    cat ~/file1 ~/file2 ~/file3 ~/file4 ~/file5 ~/file6 ~/file10 > ~/hash

    # Tests
    Total_Tests=0

    do_Test "$JtR --max-candidates=13 --stdout --mask=?l"              "13p 0:00:00"      -1  -1
    do_Test "$JtR --max-candidates=50 --stdout --mask=?l"              "26p 0:00:00"      -1  -1

    do_Test "$JtR ~/file1 --single"                                     "2g 0:00:00"      -1  -1
    do_Test "$JtR ~/file2 --wordlist"                                   "1g 0:00:00"      -1  -1
    do_Test "$JtR ~/file3 --incremental --format=Raw-MD5"              "30g 0:00:00"      -1  -1
    #do_Test "$JtR ~/file4"                                              "4g 0:00:00"      -1  -1
    do_Test "$JtR ~/file5"                                             "30g 0:00:00"      -1  -1

    do_Test "$JtR ~/hash --loopback"  "No password hashes left to crack (see FAQ)"        -1  -1
    do_Test "$JtR ~/self --loopback"                                    "1g 0:00:00"      -1  -1
    do_Test "$JtR ~/hash --show"                        ""                                33 263
    do_Test "$JtR ~/hash --show:left"                   ""                                 2   0  #Zip format
    do_Test "$JtR ~/hash --show --format=raw-sha1"      ""                                30   0
    do_Test "$JtR ~/self --show --format=Raw-sha512"    ""                                 1   2

    #do_Test "$JtR ~/hash --make-charset=chr --format=Raw-MD5" "Loaded 38 plaintexts"                                      -1  -1
    #do_Test "$JtR ~/hash --make-charset=chr --format=Raw-MD5" "Successfully wrote charset file: chr (28 characters)"      -1  -1

    rm -f ../run/*.pot
    do_Test "$JtR ~/file6 --wordlist --rules=jumbo --format=raw-md5"   "66g 0:00:00"      -1  -1
    # do_Test "$JtR ~/hash --loopback --format=rar --max-l=5"              "1g 0:00:0"      -1  -1
    do_Test "$JtR ~/file6 --show --format=raw-md5"                                ""      66  34
    # do_Test "$JtR ~/hash --show:left --format=rar"                                ""       1   1
    do_Test "$JtR ~/self -form=SHA512crypt"                             "1g 0:00:00"      -1  -1

    if test "$CC" = "gcc" ; then
        # Fails in clang+ASAN+libOmp
        do_Test "$JtR ~/self -form=raw-SHA512 --incremental -fork=2"     "2g 0:00:0"      -1  -1
    else
        do_Test "$JtR ~/self -form=raw-SHA512 --incremental"             "3g 0:00:0"      -1  -1
    fi
    do_Test "$JtR ~/self --show --format=raw-SHA512"                              ""       3   0

    do_Test "$JtR ~/self --form=oldoffice --mask=5?d5?a73?A3"                   "1g 0:00:00"      -1  -1
    do_Test "$JtR ~/self --form=oldoffice --increm:digits --min-l=6 --max-l=6"  "1g 0:00:00"      -1  -1
    do_Test "$JtR specials -word:answers --mask=?w?a"                           "2g 0:00:"       -1  -1
    do_Test "$JtR specials -word:answers -form=SHA512crypt"                    "15g 0:00:"       -1  -1
    #do_Test "$JtR ~/self --form=pkzip --mask=zipcrypto"                         "1g 0:00:00"      -1  -1
    #do_Test "$JtR ~/self --form=pkzip"                                          "1g 0:00:00"      -1  -1

    echo '--------------------------------------------------------------------------------'
    echo "All tests passed without error! Performed $Total_Tests tests in $SECONDS seconds."
    echo '--------------------------------------------------------------------------------'
fi

if test "$FUZZ" = "zzuf" ; then
    # Required defines
    TEST=';ZZUF_FUZZ;' # Controls how the test will happen
    arch=$(uname -m)
    JTR_BIN="$JtR"
    JTR_CL=""

    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/run_tests.sh
    source run_tests.sh

elif test "$FUZZ" = "afl" ; then
    # Required defines
    TEST=';AFL_FUZZ;' # Controls how the test will happen
    arch=$(uname -m)
    JTR_BIN="$JtR"
    JTR_CL=""

    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/run_tests.sh
    source run_tests.sh

elif test "$FUZZ" = "shared" ; then
    # Required defines
    # TEST  # Defined inside .travis.yml
    arch=$(uname -m)
    JTR_BIN="$JtR"
    JTR_CL=""

    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/run_tests.sh
    source run_tests.sh

elif test "$FUZZ" = "full" ; then
    # Required defines
    TEST=';MY_FULL;' # Controls how the test will happen
    arch=$(uname -m)
    JTR_BIN="$JtR"
    JTR_CL=""

    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/run_tests.sh
    source run_tests.sh

elif test "$FUZZ" = "internal" ; then
    # Required defines
    TEST=';MY_INTERNAL;' # Controls how the test will happen
    arch=$(uname -m)
    JTR_BIN="$JtR"
    JTR_CL=""

    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/run_tests.sh
    source run_tests.sh

elif test "$FUZZ" = "snap" ; then
    # Required defines
    TEST=';full;extra;crack;' # Controls how the test will happen
    arch=$(uname -m)
    JTR_BIN="$JtR"
    JTR_CL=""

    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/run_tests.sh
    source run_tests.sh

elif test "$FUZZ" = "check" ; then
    # Required defines
    TEST=';CHECK;' # Controls how the test will happen
    arch=$(uname -m)
    JTR_BIN="$JtR"
    JTR_CL=""

    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/run_tests.sh
    source run_tests.sh

elif test "$FUZZ" = "ztex" ; then
    echo "$ JtR -test=0 --format=ztex"
    do_Test "$JtR -test=0 --format=descrypt-ztex" "No ZTEX devices found" 0 0 "ERROR"
    do_Test "$JtR -test=0 --format=bcrypt-ztex"   "No ZTEX devices found" 0 0 "ERROR"
    do_Test "$JtR -test=0 --format=sha512crypt-ztex"   "No ZTEX devices found" 0 0 "ERROR"
    do_Test "$JtR -test=0 --format=drupal7-ztex"   "No ZTEX devices found" 0 0 "ERROR"
    do_Test "$JtR -test=0 --format=sha256crypt-ztex"   "No ZTEX devices found" 0 0 "ERROR"
    do_Test "$JtR -test=0 --format=md5crypt-ztex"   "No ZTEX devices found" 0 0 "ERROR"
    do_Test "$JtR -test=0 --format=phpass-ztex"   "No ZTEX devices found" 0 0 "ERROR"

elif [[ "$TEST" != *"EXTRAS"* ]]; then
    # ---- Regular testing ----
    # Trusty AMD GPU drivers on Travis are fragile.
    # - a simple run of --test fails;
    # - clang reports memory issues.
    if test "$FUZZ" = "slow" ; then
        echo "$ JtR -test=0 --format=cpu"
        "$JtR" -test=0 --format=cpu
    elif test -z "$OPENCL" ; then
        echo "$ JtR -test-full=0"
        "$JtR" -test-full=0
    elif test -z "$F" -o "$F" = "1" ; then
        echo "$ JtR -test-full=0 --format=cpu"
        "$JtR" -test-full=0 --format=cpu
    fi
    echo '--------------------------------'

    if test "$OPENCL" = "yes" ; then

        if test -z "$F" -o "$F" = "2" ; then

            if test "$CC" != "clang" ; then
                echo "OpenCL: john --list=opencl-devices"
                "$JtR" --list=opencl-devices -verb=5
                echo '--------------------------------'
            fi
            echo "$ JtR -test-full=0 --format=opencl"
            "$JtR" -test-full=0 --format=opencl
        fi
    fi
fi

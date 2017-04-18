#!/bin/bash

function do_Init(){
    ../run/john -form:cpu --list=format-tests | cut -f3 &> alltests.in
}

function do_Done(){
    rm alltests.in
}

function do_All_Devices(){
    #TODO: do some parse and replace to dev=CPU+GPU
    echo 'Checking all devices...'

    if [ ${1:0:3} == "256" ]; then
        for i in 0 1 2 3 4 6 7 ; do ../run/john -form:raw-sha256-opencl    --test -dev:$i ; done
        for i in 0 1 2 3 4 6 7 ; do ../run/john -form:raw-sha256-opencl    --test --mask=?d?d?d?d###8 -dev:$i ; done
    fi
    if [ ${1:4:3} == "512" ]; then
        for i in 0 1 2 3 4 6 7 ; do ../run/john -form:raw-sha512-ng-opencl --test -dev:$i ; done
        for i in 0 1 2 3 4 6 7 ; do ../run/john -form:raw-sha512-ng-opencl --test --mask=?d?d?d?d###8 -dev:$i ; done
    fi
}

function do_Test_Suite(){
    echo 'Running Test Suite...'

    ./jtrts.pl -type raw-sha256-opencl -passthru "-dev:0"
    ./jtrts.pl -type raw-sha256-opencl -passthru "-dev:2"
    ./jtrts.pl -type raw-sha256-opencl -passthru "-dev:7"
    ./jtrts.pl -internal -type raw-sha256-opencl -passthru "-dev:0 --fork=2"
    ./jtrts.pl -internal -type raw-sha256-opencl -passthru "-dev:2 --fork=2"
    ./jtrts.pl -internal -type raw-sha256-opencl -passthru "-dev:7 --fork=2"
}


function do_Test(){
    TO_RUN="$5 ../run/john -ses=tst-cla -pot=tst-cla.pot $1 $2 $3 &> /dev/null"
    eval $TO_RUN
    ret_code=$?
    if [ $ret_code != 0 -a $ret_code != 1 ]; then
        echo "ERROR ($ret_code): $TO_RUN"
        echo
 
        exit 1
    fi
    TO_SHOW="../run/john -show=left -pot=tst-cla.pot $1 $2 &> tmp.cracked"
    eval $TO_SHOW

    eval $TO_SHOW
    ret_code=$?
    if [ $ret_code != 0 ]; then
        echo "ERROR ($ret_code): $TO_SHOW"
        echo
 
        exit 1
    fi
    #cat tmp.cracked | awk '/password hash/ { print $1 }'
    read CRACKED <<< $(cat tmp.cracked | awk '/password hash/ { print $1 }')

    #echo "DEBUG: ($CRACKED) $TO_RUN"
    #echo "DEBUG: ($CRACKED) $TO_SHOW"

    if [ $CRACKED -ne $4 ]; then
        echo "ERROR: $TO_RUN"
        echo "Expected value: $4, value found: $CRACKED. $TO_SHOW"
        echo
 
        exit 1
    fi
    #-- Remove tmp files.
    rm tst-cla.pot
    rm tmp.cracked
} 

function sha256(){
    echo 'Executing raw-SHA256 tests...'
    do_Test "cisco4_tst.in"     "-form:Raw-SHA256-opencl" "-wo:pw.dic --rules=all --skip"         1500
    do_Test "rawsha256_tst.in"  "-form:Raw-SHA256-opencl" "-wo:pw.dic --rules=all -dev=2"         1500
    do_Test "alltests.in"       "-form=raw-SHA256-opencl" "-incremental -max-run=40 -fork=4 -dev=0"                                9
    do_Test "alltests.in"       "-form=raw-SHA256-opencl" "-incremental -max-run=40 -fork=4 -dev=7"                                9

    do_Test "alltests.in"       "-form=Raw-SHA256-opencl" "-mask:?l -min-len=4 -max-len=7"           2 
    do_Test "alltests.in"       "-form=Raw-SHA256-opencl" "-mask:?d -min-len=1 -max-len=8"           4 "_GPU_MASK_CAND=0" 
    do_Test "alltests.in"       "-form=raw-SHA256-opencl" "-mask=[Pp][Aa@][Ss5][Ss5][Ww][Oo0][Rr][Dd] -dev=0"                      2

}

function sha512(){
    echo 'Executing raw-SHA512 tests...'
    do_Test "rawsha512_tst.in" "-form=raw-SHA512-ng-opencl" "-wo:pw.dic --rules=all"                                             1500
    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-incremental -max-run=40 -fork=2 -dev=0"                               3
    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-incremental -max-run=40 -fork=4 -dev=7"                               3

    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-mask=[Pp][Aa@][Ss5][Ss5][Ww][Oo0][Rr][Dd] -dev=0"                     1
    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-mask:?l?l?l?l?l?l?l --skip -dev=2"                                    1
    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-mask:?d2345?d?d?d"                                                    1
    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-mask:1?d3?d5?d7?d90123?d5?d7?d90"                                     1
    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-mask=?u?u?uCAPS"                                                      1
    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-mask:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx[x-z] -min=55 -max-l=55"  1
    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-mask:TestTESTt3st"                                                    2
    do_Test "alltests.in"      "-form=raw-SHA512-ng-opencl" "-mask:john?a?l?l?lr  -dev=7"                                           1

    do_Test "alltests.in"      "-form=xSHA512-ng-opencl" "-mask:?l?l?l?l?l"                            1
    do_Test "alltests.in"      "-form=xSHA512-ng-opencl" "-mask=[Pp][Aa@][Ss5][Ss5][Ww][Oo0][Rr][Dd]"  1
    do_Test "alltests.in"      "-form=xSHA512-ng-opencl" "-mask=boob?l?l?l"                            1
    do_Test "alltests.in"      "-form=xSHA512-ng-opencl" "-mask:?d -min-len=1 -max-len=4"              5 "_GPU_MASK_CAND=0"
    do_Test "alltests.in"      "-form=xSHA512-ng-opencl" "-mask:?d -min-len=4 -max-len=8"              6  
}

function do_all(){
    sha256
    sha512
}

function do_help(){
    echo 'Usage: ./test-claudio.sh [OPTIONS] [hash]'
    echo 
    echo 'help:       prints this help info.'
    echo 'basic:      do basic tests using all devices. You can filter using:'
    echo '            ./test-claudio.sh basic 256,000'
    echo '            ./test-claudio.sh basic basic 000,512'
    echo '            ./test-claudio.sh basic basic 256,512'
    echo 'raw-sha256: filter and execute only raw-sha256 tests.'
    echo 'raw-sha512: filter and execute only raw-sha512 tests.'
    echo

    exit 0 
}

#-----------   Init   -----------
if [ "$1" == "help" -o "$1" == "-help" -o "$1" == "--help" ]; then
    do_help
fi

clear
do_Init

if [ "$#" == "0" ]; then
    do_all
fi

if [ "$1" == "basic" ]; then
    do_All_Devices $2
    do_Test_Suite
fi

if [ "$1" == "raw-sha256" ]; then
    sha256
fi

if [ "$1" == "raw-sha512" ]; then
    sha512
fi

#-----------   Done  -----------
do_Done

#----------- The End -----------
echo 
echo 'All tests passed without error!'
exit 0

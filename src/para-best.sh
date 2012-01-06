#!/bin/sh
#
# This file is part of John the Ripper password cracker,
# Copyright (c) 1996-2000,2003,2005,2008,2011 by Solar Designer
#
# This file made by magnum, based on best.sh. No rights reserved.

[ $# -eq 4 ] || exit 1

CC=$1
MAKE=$2
PARA_DEPEND=$3
EXTRA_CFLAGS=$4

# Detect the best intrinsics PARAs
MD4_BEST=0
MD5_BEST=0
SHA1_BEST=0
MD4_PARA=1
MD5_PARA=1
SHA1_PARA=1
MD4_PARA_BEST=1
MD5_PARA_BEST=1
SHA1_PARA_BEST=1
MAX=1

while [ $MAX -eq 1 ]; do
    rm -f $PARA_DEPEND para-bench
    echo ; echo "Compiling intrinsics benchmarks with PARA $PARA"
    export JOHN_CFLAGS="$EXTRA_CFLAGS -DMD4_SSE_PARA=$MD4_PARA -DMD5_SSE_PARA=$MD5_PARA -DSHA1_SSE_PARA=$SHA1_PARA"
    $MAKE para-bench || exit 1
    MAX=0
    TIME=1
    RES=0
    for i in 1 2 3 4 5; do
	RES=$(($RES+`./para-bench 4 $TIME`)) || exit 1
    done
    RES=$(($RES/5))
    if [ $(($RES*100)) -gt $(($MD4_BEST*101)) ]; then
	MAX=1
	MD4_PARA_BEST=$MD4_PARA
	MD4_PARA=$(($MD4_PARA+1))
	MD4_BEST=$RES
    fi
    RES=0
    for i in 1 2 3 4 5; do
	RES=$(($RES+`./para-bench 2 $TIME`)) || exit 1
    done
    RES=$(($RES/5))
    if [ $(($RES*100)) -gt $(($MD5_BEST*101)) ]; then
	MAX=1
	MD5_PARA_BEST=$MD5_PARA
	MD5_PARA=$(($MD5_PARA+1))
	MD5_BEST=$RES
    fi
    RES=0
    for i in 1 2 3 4 5; do
	RES=$(($RES+`./para-bench 6 $TIME`)) || exit 1
    done
    RES=$(($RES/5))
    if [ $(($RES*100)) -gt $(($SHA1_BEST*101)) ]; then
	MAX=1
	SHA1_PARA_BEST=$SHA1_PARA
	SHA1_PARA=$(($SHA1_PARA+1))
	SHA1_BEST=$RES
    fi
    if [ $MAX -eq 0 ]; then
	echo ======================================================
	[ -f /proc/cpuinfo ] && grep -m1 "^model name" /proc/cpuinfo
	echo "gcc version: $CC (`$CC -v 2>&1 | grep -m1 \"version \"`)"
	echo "Best paras:"
	echo "  raw-MD4: $MD4_PARA_BEST  ($(($MD4_BEST/10000))K c/s)"
	echo "crypt-MD5: $MD5_PARA_BEST  ($(($MD5_BEST/10)) c/s)"
	echo " raw-SHA1: $SHA1_PARA_BEST  ($(($SHA1_BEST/10000))K c/s)"
	break
    fi
done

# Produce generic.h, make sure everything is rebuilt with detected options,
# and do some cleanup

#./detect $DES_BEST $DES_COPY $DES_BS $MD5_X2 $MD5_IMM $BF_SCALE $BF_X2 \
#	> generic.h
#rm -f $DES_DEPEND $DES_BS_DEPEND $MD5_DEPEND $BF_DEPEND \
#	bench detect best.o detect.o arch.h

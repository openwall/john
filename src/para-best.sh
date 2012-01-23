#!/bin/sh
#
# This file is part of John the Ripper password cracker,
# Copyright (c) 1996-2000,2003,2005,2008,2011 by Solar Designer
#
# This file made by magnum, based on best.sh. No rights reserved.

[ $# -eq 5 ] || exit 1

CC=$1
MAKE="$2"
PARA_DEPEND=$3
EXTRA_CFLAGS=$4
ARCH_SIZE=$5

# Detect the best intrinsics PARAs
MD4_BEST=0
MD5_BEST=0
MD5c_BEST=0
SHA1_BEST=0
MD4_BEST_INTR=0
MD5_BEST_INTR=0
MD5c_BEST_INTR=0
SHA1_BEST_INTR=0
SHA1_BEST80_INTR=0
MD4_PARA=1
MD5_PARA=1
SHA1_PARA=1
MD4_PARA_BEST="asm"
MD5_PARA_BEST="asm"
MD5c_PARA_BEST="asm"
SHA1_PARA_BEST="asm"
TIME=1

if [ $5 -eq 32 ]; then
    rm -f $PARA_DEPEND para-bench
    echo ; echo "Compiling assembler benchmarks"
    export JOHN_CFLAGS="$EXTRA_CFLAGS -DJOHN_DISABLE_INTRINSICS"
    $MAKE >/dev/null para-bench$5 || exit 1
    SHA1_FASTEST="80*4"
    MD4_BEST=`./para-bench 4 $TIME` || exit 1
    MD5c_BEST=`./para-bench 2 $TIME` || exit 1
    MD5_BEST=`./para-bench 5 $TIME` || exit 1
    SHA1_BEST=`./para-bench 6 $TIME` || exit 1
fi

while [ true ]; do
    rm -f $PARA_DEPEND para-bench
    echo ; echo "Compiling MD4 intrinsics benchmarks with PARA $MD4_PARA"
    export JOHN_CFLAGS="$EXTRA_CFLAGS -DMD4_SSE_PARA=$MD4_PARA -DMD5_SSE_PARA=$MD5_PARA -DSHA1_SSE_PARA=$SHA1_PARA"
    $MAKE >/dev/null para-bench$5 || exit 1
    RES=`./para-bench 4 $TIME` || exit 1
    if [ $(($RES*100)) -gt $(($MD4_BEST_INTR*101)) ]; then
	if [ $(($RES*100)) -gt $(($MD4_BEST*101)) ]; then
	    MD4_PARA_BEST=$MD4_PARA
	    MD4_BEST=$RES
	fi
	MD4_PARA=$(($MD4_PARA+1))
	MD4_BEST_INTR=$RES
    else
	MD4_PARA=$(($MD4_PARA-1))
	break
    fi
done

while [ true ]; do
    rm -f $PARA_DEPEND para-bench
    echo ; echo "Compiling MD5 intrinsics benchmarks with PARA $MD5_PARA"
    export JOHN_CFLAGS="$EXTRA_CFLAGS -DMD4_SSE_PARA=$MD4_PARA -DMD5_SSE_PARA=$MD5_PARA -DSHA1_SSE_PARA=$SHA1_PARA"
    $MAKE >/dev/null para-bench$5 || exit 1
    RESc=`./para-bench 2 $TIME` || exit 1
    RES=`./para-bench 5 $TIME` || exit 1
    if [ $(($RESc*100)) -gt $(($MD5c_BEST_INTR*101)) -o $(($RES*100)) -gt $(($MD5_BEST_INTR*101)) ]; then
	if [ $(($RESc*100)) -gt $(($MD5c_BEST_INTR*101)) ]; then
	    MD5c_BEST_INTR=$RESc
	fi
	if [ $(($RES*100)) -gt $(($MD5_BEST_INTR*101)) ]; then
	    MD5_BEST_INTR=$RES
	fi
	if [ $(($RESc*100)) -gt $(($MD5c_BEST*101)) ]; then
	    MD5c_PARA_BEST=$MD5_PARA
	    MD5c_BEST=$RESc
	fi
	if [ $(($RES*100)) -gt $(($MD5_BEST*101)) ]; then
	    MD5_PARA_BEST=$MD5_PARA
	    MD5_BEST=$RES
	fi
	MD5_PARA=$(($MD5_PARA+1))
    else
	MD5_PARA=$(($MD5_PARA-1))
	break
    fi
done

while [ true ]; do
    rm -f $PARA_DEPEND para-bench
    echo ; echo "Compiling SHA1 intrinsics benchmarks with PARA $SHA1_PARA and 16*4 buffer"
    export JOHN_CFLAGS="$EXTRA_CFLAGS -DMD4_SSE_PARA=$MD4_PARA -DMD5_SSE_PARA=$MD5_PARA -DSHA1_SSE_PARA=$SHA1_PARA -DSHA_BUF_SIZ=16"
    $MAKE >/dev/null para-bench$5 || exit 1
    RES=`./para-bench 6 $TIME` || exit 1
    if [ $(($RES*100)) -gt $(($SHA1_BEST_INTR*101)) ]; then
	SHA1_FASTEST="16*4"
	if [ $(($RES*100)) -gt $(($SHA1_BEST*101)) ]; then
	    SHA1_PARA_BEST=$SHA1_PARA
	    SHA1_BEST=$RES
	fi
	SHA1_PARA=$(($SHA1_PARA+1))
	SHA1_BEST_INTR=$RES
    else
	SHA1_PARA=$(($SHA1_PARA-1))
	break
    fi
done

SHA1_80PARA=1
while [ true ]; do
    rm -f $PARA_DEPEND para-bench
    echo ; echo "Compiling SHA1 intrinsics benchmarks with PARA $SHA1_80PARA and 80*4 buffer"
    export JOHN_CFLAGS="$EXTRA_CFLAGS -DMD4_SSE_PARA=$MD4_PARA -DMD5_SSE_PARA=$MD5_PARA -DSHA1_SSE_PARA=$SHA1_80PARA -DSHA_BUF_SIZ=80"
    $MAKE >/dev/null para-bench$5 || exit 1
    RES=`./para-bench 6 $TIME` || exit 1
    if [ $(($RES*100)) -gt $(($SHA1_BEST80_INTR*101)) ]; then
	if [ $(($RES*100)) -gt $(($SHA1_BEST_INTR*101)) ]; then
	    SHA1_BEST_INTR=$RES
	    SHA1_FASTEST="80*4"
	    if [ $(($RES*100)) -gt $(($SHA1_BEST*101)) ]; then
		SHA1_PARA_BEST=$SHA1_80PARA
		SHA1_BEST=$RES
	    fi
	fi
	SHA1_80PARA=$(($SHA1_80PARA+1))
	SHA1_BEST80_INTR=$RES
    else
	SHA1_80PARA=$(($SHA1_80PARA-1))
	break
    fi
done

if [ $SHA1_BEST80_INTR > $SHA1_BEST_INTR ]; then
    SHA1_PARA=$SHA1_80PARA
fi

echo ======================================================
[ -f /proc/cpuinfo ] && grep -m1 "^model name" /proc/cpuinfo
echo "gcc version: $CC (`$CC -v 2>&1 | grep -m1 \"version \"`)"
echo "Best -m$5 paras:"
if [ "$MD4_PARA_BEST" = "asm" ]; then
    echo "  raw-MD4: $MD4_PARA_BEST  ($(($MD4_BEST/10000))K c/s), para $MD4_PARA  ($(($MD4_BEST_INTR/10000))K c/s)"
else
    echo "  raw-MD4: $MD4_PARA_BEST  ($(($MD4_BEST/10000))K c/s)"
fi
if [ "$MD5c_PARA_BEST" = "asm" ]; then
    echo "crypt-MD5: $MD5c_PARA_BEST  ($(($MD5c_BEST/10)) c/s), para $MD5_PARA  ($(($MD5c_BEST_INTR/10)) c/s)"
else
    echo "crypt-MD5: $MD5c_PARA_BEST  ($(($MD5c_BEST/10)) c/s)"
fi
if [ "$MD5_PARA_BEST" = "asm" ]; then
    echo "  raw-MD5: $MD5_PARA_BEST  ($(($MD5_BEST/10000))K c/s), para $MD5_PARA  ($(($MD5_BEST_INTR/10000)) c/s)"
else
    echo "  raw-MD5: $MD5_PARA_BEST  ($(($MD5_BEST/10000))K c/s)"
fi
if [ "$SHA1_PARA_BEST" = "asm" ]; then
    echo " raw-SHA1: $SHA1_PARA_BEST  ($(($SHA1_BEST/10000))K c/s), para $SHA1_PARA  ($(($SHA1_BEST_INTR/10000))K c/s) [$SHA1_FASTEST]"
else
    echo " raw-SHA1: $SHA1_PARA_BEST  ($(($SHA1_BEST/10000))K c/s) [$SHA1_FASTEST]"
fi

# Produce generic.h, make sure everything is rebuilt with detected options,
# and do some cleanup

#./detect $DES_BEST $DES_COPY $DES_BS $MD5_X2 $MD5_IMM $BF_SCALE $BF_X2 \
#	> generic.h
#rm -f $DES_DEPEND $DES_BS_DEPEND $MD5_DEPEND $BF_DEPEND \
#	bench detect best.o detect.o arch.h

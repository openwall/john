#!/bin/sh
#
# This file is part of John the Ripper password cracker,
# Copyright (c) 1996-2000 by Solar Designer
#

[ $# -eq 3 ] || exit 1

MAKE=$1
HAMMER=$2
DES_DEPEND=$3

# Detect the best non-bitslice DES algorithm

MAX=0
DES_BEST=1

for MODE in 2 3; do
	if ./detect $MODE 0 0 1 0 0 > arch.h; then
		rm -f $DES_DEPEND bench
		$MAKE $HAMMER NAIL=bench \
			BENCH_DES_OBJS_DEPEND="$DES_DEPEND" || exit 1
		RES=`./bench 1` || exit 1
		if [ $RES -gt $MAX ]; then
			MAX=$RES
			DES_BEST=$MODE
		fi
	fi
done

# Check if bitslice DES is faster

./detect $DES_BEST 0 1 1 0 0 > arch.h
rm -f $DES_DEPEND bench

$MAKE $HAMMER NAIL=bench BENCH_DES_OBJS_DEPEND="$DES_DEPEND" || exit 1
RES=`./bench 1` || exit 1
if [ $RES -gt $MAX ]; then
	DES_BS=1
else
	DES_BS=0
fi

# Produce sparc.h, make sure everything is rebuilt with detected options,
# and do some cleanup

./detect $DES_BEST 0 $DES_BS 1 0 0 > sparc.h
rm -f $DES_DEPEND bench detect best.o detect.o arch.h

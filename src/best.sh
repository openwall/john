#!/bin/sh
#
# This file is part of John the Ripper password cracker,
# Copyright (c) 1996-2000,2003,2005,2008,2011 by Solar Designer
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# There's ABSOLUTELY NO WARRANTY, express or implied.
#

[ $# -eq 5 ] || exit 1

MAKE=$1
DES_DEPEND=$2
DES_BS_DEPEND=$3
MD5_DEPEND=$4
BF_DEPEND=$5

# Detect the best non-bitslice DES algorithm

MAX=0
DES_BEST=1

for MODE in 1 2 3 4 5; do
	if ./detect $MODE 1 0 0 0 0 0 > arch.h; then
		rm -f $DES_DEPEND bench
		echo "Compiling: DES benchmark (code version #$MODE)"
		$MAKE bench || exit 1
		RES=`./bench 1` || exit 1
		if [ $RES -gt $MAX ]; then
			MAX=$RES
			DES_BEST=$MODE
		fi
	fi
done

./detect $DES_BEST 0 0 0 0 0 0 > arch.h
rm -f $DES_DEPEND bench

echo "Compiling: DES benchmark (code version #$DES_BEST, no key copying)"
$MAKE bench || exit 1
RES=`./bench 1` || exit 1
if [ $RES -gt $MAX ]; then
	MAX=$RES
	DES_COPY=0
else
	DES_COPY=1
fi

# Check if bitslice DES is faster

DES_BS=0

rm -f $DES_DEPEND bench

for MODE in 1 2 3; do
	if ./detect $DES_BEST $DES_COPY $MODE 0 0 0 0 > arch.h; then
		echo "Compiling: DES benchmark (bitslice, code version #$MODE)"
		if [ $MODE -gt 1 ]; then
			rm -f $DES_BS_DEPEND bench
		fi
		$MAKE bench || exit 1
		RES=`./bench 1` || exit 1
		if [ $RES -gt $MAX ]; then
			MAX=$RES
			DES_BS=$MODE
		fi
	fi
done

# Detect the best MD5 algorithm

MAX=`./bench 2` || exit 1

./detect $DES_BEST $DES_COPY $DES_BS 1 0 0 0 > arch.h
rm -f $MD5_DEPEND bench

echo "Compiling: MD5 benchmark (two hashes at a time)"
$MAKE bench || exit 1
RES=`./bench 2` || exit 1
if [ $RES -gt $MAX ]; then
	MAX=$RES
	MD5_X2=1
else
	MD5_X2=0
fi

./detect $DES_BEST $DES_COPY $DES_BS $MD5_X2 1 0 0 > arch.h
rm -f $MD5_DEPEND bench

echo "Compiling: MD5 benchmark (immediate values)"
$MAKE bench || exit 1
RES=`./bench 2` || exit 1
if [ $RES -gt $MAX ]; then
	MD5_IMM=1
else
	MD5_IMM=0
fi

# Detect the best Blowfish algorithm

MAX=`./bench 3` || exit 1

./detect $DES_BEST $DES_COPY $DES_BS $MD5_X2 $MD5_IMM 1 0 > arch.h
rm -f $BF_DEPEND bench

echo "Compiling: Blowfish benchmark (scale)"
$MAKE bench || exit 1
RES=`./bench 3` || exit 1
if [ $RES -gt $MAX ]; then
	MAX=$RES
	BF_SCALE=1
else
	BF_SCALE=0
fi

./detect $DES_BEST $DES_COPY $DES_BS $MD5_X2 $MD5_IMM $BF_SCALE 1 > arch.h
rm -f $BF_DEPEND bench

echo "Compiling: Blowfish benchmark (two hashes at a time)"
$MAKE bench || exit 1
RES=`./bench 3` || exit 1
if [ $RES -gt $MAX ]; then
	BF_X2=1
else
	BF_X2=0
fi

# Produce generic.h, make sure everything is rebuilt with detected options,
# and do some cleanup

./detect $DES_BEST $DES_COPY $DES_BS $MD5_X2 $MD5_IMM $BF_SCALE $BF_X2 \
	> generic.h
rm -f $DES_DEPEND $DES_BS_DEPEND $MD5_DEPEND $BF_DEPEND \
	bench detect best.o detect.o arch.h

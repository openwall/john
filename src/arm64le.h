/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013,2019 by Solar Designer
 * And others
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Architecture specific parameters for 64-bit ARM in little-endian mode.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#if AC_BUILT
#include "autoconfig.h"
#else
#define ARCH_WORD			long
#define ARCH_SIZE			8
#define ARCH_BITS			64
#define ARCH_BITS_LOG			6
#define ARCH_BITS_STR			"64"
#define ARCH_LITTLE_ENDIAN		1
#define ARCH_INT_GT_32			0
#endif

#define ARCH_ALLOWS_UNALIGNED		0
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define CPU_DETECT			0

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			0
#define DES_COPY			0
#define DES_BS_ASM			0
#if !JOHN_NO_SIMD
/*
 * Here we assume that we're on AArch64, which implies we have Advanced SIMD.
 * Tell our originally 32-bit ARM code that we sort of have NEON.
 * Newer gcc does the same for us on its own, but older gcc needs help here.
 */
#ifndef __ARM_NEON
#define __ARM_NEON 1
#endif
/*
 * Give native vsel() a try with DES_BS=3, even though the timings are often
 * such that it might be better to avoid its use, and DES_BS=1 might be better.
 * This varies between systems, and we can't detect what's optimal from here.
 */
#define DES_BS				3
#if 1
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"DES 128/128 ASIMD"
#else
#define DES_BS_VECTOR			1
#define DES_BS_ALGORITHM_NAME		"DES 64/64 ASIMD"
#endif
#else
#define DES_BS				1
#define DES_BS_VECTOR			0
#endif
#define DES_BS_EXPAND			1

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#define BF_ASM				0
#define BF_SCALE			0
#define BF_X2				1

#if !JOHN_NO_SIMD
#define SIMD_COEF_32		4
#define SIMD_COEF_64		2
#ifndef SIMD_PARA_MD4
#define SIMD_PARA_MD4		2
#endif
#ifndef SIMD_PARA_MD5
#define SIMD_PARA_MD5		2
#endif
#ifndef SIMD_PARA_SHA1
#define SIMD_PARA_SHA1		1
#endif
#ifndef SIMD_PARA_SHA256
#define SIMD_PARA_SHA256	1
#endif
#ifndef SIMD_PARA_SHA512
#define SIMD_PARA_SHA512	1
#endif
#endif

#define STR_VALUE(arg)			#arg
#define PARA_TO_N(n)			STR_VALUE(n) "x"
#define PARA_TO_MxN(m, n)		STR_VALUE(m) "x" STR_VALUE(n)

#if SIMD_PARA_MD4 > 1
#define MD4_N_STR			PARA_TO_MxN(SIMD_COEF_32, SIMD_PARA_MD4)
#else
#define MD4_N_STR			PARA_TO_N(SIMD_COEF_32)
#endif
#if SIMD_PARA_MD5 > 1
#define MD5_N_STR			PARA_TO_MxN(SIMD_COEF_32, SIMD_PARA_MD5)
#else
#define MD5_N_STR			PARA_TO_N(SIMD_COEF_32)
#endif
#if SIMD_PARA_SHA1 > 1
#define SHA1_N_STR			PARA_TO_MxN(SIMD_COEF_32, SIMD_PARA_SHA1)
#else
#define SHA1_N_STR			PARA_TO_N(SIMD_COEF_32)
#endif
#if SIMD_PARA_SHA256 > 1
#define SHA256_N_STR		PARA_TO_MxN(SIMD_COEF_32, SIMD_PARA_SHA256)
#else
#define SHA256_N_STR		PARA_TO_N(SIMD_COEF_32)
#endif
#if SIMD_PARA_SHA512 > 1
#define SHA512_N_STR		PARA_TO_MxN(SIMD_COEF_64, SIMD_PARA_SHA512)
#else
#define SHA512_N_STR		PARA_TO_N(SIMD_COEF_64)
#endif

#define SHA_BUF_SIZ			16

#endif

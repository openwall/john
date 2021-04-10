/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Architecture specific parameters for Intel MIC.
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

#define CPU_NAME			"MIC"

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			1
#define DES_COPY			0
#define DES_BS_ASM			0
#define DES_BS				1
#define DES_BS_VECTOR			8
#define DES_BS_ALGORITHM_NAME		"DES 512/512 MIC"
#define DES_BS_EXPAND			1

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#define BF_ASM				0
#define BF_SCALE			1
#ifndef BF_X2
#define BF_X2				1
#endif

#define SIMD_COEF_32		16
#define SIMD_COEF_64		8

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
/* 2 is faster at least for Bitcoin, but makes sha512crypt fail self-test */
#define SIMD_PARA_SHA512	1
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

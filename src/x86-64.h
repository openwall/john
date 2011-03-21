/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2003,2006,2008,2010,2011 by Solar Designer
 */

/*
 * Architecture specific parameters for x86-64.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#define ARCH_WORD			long
#define ARCH_SIZE			8
#define ARCH_BITS			64
#define ARCH_BITS_LOG			6
#define ARCH_BITS_STR			"64"
#define ARCH_LITTLE_ENDIAN		1
#define ARCH_INT_GT_32			0
#define ARCH_ALLOWS_UNALIGNED		1
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define OS_TIMER			1
#define OS_FLOCK			1

#define CPU_DETECT			0

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			1
#define DES_COPY			0
#define DES_BS				1
#if defined(__AVX__) && defined(__GNUC__)
/* Require gcc for AVX because DES_bs_all is aligned in a gcc-specific way */
#define DES_BS_ASM			0
#if 0
/* 512-bit as 2x256 */
#define DES_BS_VECTOR			8
#if defined(__XOP__) && defined(__GNUC__)
/* Require gcc for 256-bit XOP because of __builtin_ia32_vpcmov_v8sf256() */
#undef DES_BS
#define DES_BS                          3
#define DES_BS_ALGORITHM_NAME           "256/256 X2 BS XOP"
#else
#define DES_BS_ALGORITHM_NAME           "256/256 X2 BS AVX"
#endif
#elif 0
/* 384-bit as 256+64+64 */
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			6
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX + 64/64 BS MMX + 64/64 BS"
#elif 0
/* 320-bit as 256+64 MMX */
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			5
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX + 64/64 BS MMX"
#elif 0
/* 320-bit as 256+64 */
#define DES_BS_NO_MMX
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			5
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX + 64/64 BS"
#elif 0
/* 256-bit as 1x256 */
#define DES_BS_VECTOR			4
#if defined(__XOP__) && defined(__GNUC__)
/* Require gcc for 256-bit XOP because of __builtin_ia32_vpcmov_v8sf256() */
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"256/256 BS XOP"
#else
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX"
#endif
#elif 0
/* 256-bit as 2x128 */
#define DES_BS_NO_AVX256
#define DES_BS_VECTOR			4
#ifdef __XOP__
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"128/256 X2 BS XOP"
#else
#define DES_BS_ALGORITHM_NAME		"128/256 X2 BS AVX"
#endif
#else
/* 128-bit */
#define DES_BS_VECTOR			2
#ifdef __XOP__
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"128/256 BS XOP"
#else
#define DES_BS_ALGORITHM_NAME		"128/256 BS AVX"
#endif
#endif
#elif defined(__SSE2__) && defined(__GNUC__) && \
    ((__GNUC__ == 4 && __GNUC_MINOR__ >= 4) || __GNUC__ > 4)
#define DES_BS_ASM			0
#if 1
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16"
#elif 0
#define DES_BS_VECTOR			3
#define DES_BS_VECTOR_SIZE		4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16 + 64/64 BS MMX"
#elif 0
#define DES_BS_NO_MMX
#define DES_BS_VECTOR			3
#define DES_BS_VECTOR_SIZE		4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16 + 64/64 BS"
#else
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16 + 64/64 BS MMX + 64/64 BS"
#endif
#else
#define DES_BS_ASM			1
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16"
#endif
#define DES_BS_EXPAND			1

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#define BF_ASM				0
#define BF_SCALE			1
#define BF_X2				1

#endif

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2003,2006,2008,2010,2011 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
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

#define CPU_DETECT			0

#ifdef __XOP__
#define JOHN_XOP
#endif
#if defined(__AVX__) || defined(JOHN_XOP)
#define JOHN_AVX
#endif

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			1
#define DES_COPY			0
#define DES_BS				1
#if 0
#define DES_BS_VECTOR			0
#define DES_BS_ALGORITHM_NAME		"DES 64/64"
#elif defined(JOHN_AVX) && (defined(__GNUC__) || defined(_OPENMP))
/*
 * Require gcc for AVX/XOP because DES_bs_all is aligned in a gcc-specific way,
 * except in OpenMP-enabled builds, where it's aligned by different means.
 */
#undef CPU_DETECT
#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_REQ_AVX
#define CPU_NAME			"AVX"
#ifndef CPU_FALLBACK
#define CPU_FALLBACK			0
#endif
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-avx"
#define CPU_FALLBACK_BINARY_DEFAULT
#endif
#define DES_BS_ASM			0
#if 0
/* 512-bit as 2x256 */
#define DES_BS_VECTOR			8
#if defined(JOHN_XOP) && defined(__GNUC__)
/* Require gcc for 256-bit XOP because of __builtin_ia32_vpcmov_v8sf256() */
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 256/256 X2 XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"DES 256/256 X2 AVX-16"
#endif
#elif 0
/* 384-bit as 256+128 */
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			6
#if defined(JOHN_XOP) && defined(__GNUC__)
/* Require gcc for 256-bit XOP because of __builtin_ia32_vpcmov_v8sf256() */
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 256/256 XOP-16 + 128/128 XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX-16 + 128/128 AVX-16"
#endif
#elif 0
/* 384-bit as 256+64+64 */
#define DES_BS_NO_AVX128
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			6
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX-16 + 64/64 MMX + 64/64"
#elif 0
/* 320-bit as 256+64 MMX */
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			5
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX-16 + 64/64 MMX"
#elif 0
/* 320-bit as 256+64 */
#define DES_BS_NO_MMX
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			5
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX-16 + 64/64"
#elif 0
/* 256-bit as 1x256 */
#define DES_BS_VECTOR			4
#if defined(JOHN_XOP) && defined(__GNUC__)
/* Require gcc for 256-bit XOP because of __builtin_ia32_vpcmov_v8sf256() */
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 256/256 XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX-16"
#endif
#elif 0
/* 256-bit as 2x128 */
#define DES_BS_NO_AVX256
#define DES_BS_VECTOR			4
#ifdef JOHN_XOP
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 128/128 X2 XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"DES 128/128 X2 AVX-16"
#endif
#else
/* 128-bit */
#define DES_BS_VECTOR			2
#ifdef JOHN_XOP
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 128/128 XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"DES 128/128 AVX-16"
#endif
#endif
#elif defined(__SSE2__) && defined(_OPENMP)
#define DES_BS_ASM			0
#if 1
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2-16"
#elif 0
#define DES_BS_VECTOR			3
#define DES_BS_VECTOR_SIZE		4
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2-16 + 64/64 MMX"
#elif 0
#define DES_BS_NO_MMX
#define DES_BS_VECTOR			3
#define DES_BS_VECTOR_SIZE		4
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2-16 + 64/64"
#elif 0
#define DES_BS_NO_MMX
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"DES 128/128 X2 SSE2-16"
#else
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2-16 + 64/64 MMX + 64/64"
#endif
#else
#define DES_BS_ASM			1
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2-16"
#endif
#define DES_BS_EXPAND			1

#if CPU_DETECT && DES_BS == 3
#define CPU_REQ_XOP
#undef CPU_NAME
#define CPU_NAME			"XOP"
#ifdef CPU_FALLBACK_BINARY_DEFAULT
#undef CPU_FALLBACK_BINARY
#define CPU_FALLBACK_BINARY		"john-non-xop"
#endif
#endif

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#define BF_ASM				0
#define BF_SCALE			1
#define BF_X2				1

#endif

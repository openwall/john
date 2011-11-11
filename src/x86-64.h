/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2003,2006,2008,2010,2011 by Solar Designer
 *
 * ...with a trivial change in the jumbo patch, by Alain Espinosa.
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
#define DES_BS_ALGORITHM_NAME		"64/64 BS"
#elif defined(JOHN_AVX) && defined(__GNUC__)
/* Require gcc for AVX because DES_bs_all is aligned in a gcc-specific way */
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
#define DES_BS_ALGORITHM_NAME		"256/256 X2 BS XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"256/256 X2 BS AVX-16"
#endif
#elif 0
/* 384-bit as 256+128 */
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			6
#if defined(JOHN_XOP) && defined(__GNUC__)
/* Require gcc for 256-bit XOP because of __builtin_ia32_vpcmov_v8sf256() */
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"256/256 BS XOP-16 + 128/128 BS XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX-16 + 128/128 BS AVX-16"
#endif
#elif 0
/* 384-bit as 256+64+64 */
#define DES_BS_NO_AVX128
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			6
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX-16 + 64/64 BS MMX + 64/64 BS"
#elif 0
/* 320-bit as 256+64 MMX */
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			5
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX-16 + 64/64 BS MMX"
#elif 0
/* 320-bit as 256+64 */
#define DES_BS_NO_MMX
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_VECTOR			5
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX-16 + 64/64 BS"
#elif 0
/* 256-bit as 1x256 */
#define DES_BS_VECTOR			4
#if defined(JOHN_XOP) && defined(__GNUC__)
/* Require gcc for 256-bit XOP because of __builtin_ia32_vpcmov_v8sf256() */
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"256/256 BS XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX-16"
#endif
#elif 0
/* 256-bit as 2x128 */
#define DES_BS_NO_AVX256
#define DES_BS_VECTOR			4
#ifdef JOHN_XOP
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"128/128 X2 BS XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"128/128 X2 BS AVX-16"
#endif
#else
/* 128-bit */
#define DES_BS_VECTOR			2
#ifdef JOHN_XOP
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"128/128 BS XOP-16"
#else
#define DES_BS_ALGORITHM_NAME		"128/128 BS AVX-16"
#endif
#endif
#elif defined(__SSE2__) && defined(_OPENMP)
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
#elif 0
#define DES_BS_NO_MMX
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"128/128 X2 BS SSE2-16"
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

#if defined(__INTEL_COMPILER) || defined(USING_ICC_S_FILE)
#define MD5_SSE_PARA		3
#define MD5_N_STR			"12x"
#elif defined(__GNUC__)
#define MD5_SSE_PARA		2
#define MD5_N_STR			"8x"
#else
#define MD5_SSE_PARA		3
#define MD5_N_STR			"12x"
#endif

#if defined(__INTEL_COMPILER) || defined(USING_ICC_S_FILE)
#define MD4_SSE_PARA		3
#define MD4_N_STR			"12x"
#elif defined(__GNUC__)
#define MD4_SSE_PARA		2
#define MD4_N_STR			"8x"
#else
#define MD4_SSE_PARA		3
#define MD4_N_STR			"12x"
#endif

#if defined(__INTEL_COMPILER) || defined(USING_ICC_S_FILE)
#define SHA1_SSE_PARA		2
#define SHA1_N_STR			"8x"
#elif defined(__GNUC__)
#define SHA1_SSE_PARA		2
#define SHA1_N_STR			"8x"
#else
#define SHA1_SSE_PARA		2
#define SHA1_N_STR			"8x"
#endif

#define BF_ASM				0
#define BF_SCALE			1
#define BF_X2				1

#define NT_X86_64

#endif

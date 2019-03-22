/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2005,2006,2008,2010,2011,2013,2019 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Architecture specific parameters for x86 with SSE2.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#define ARCH_WORD			long
#define ARCH_SIZE			4
#define ARCH_BITS			32
#define ARCH_BITS_LOG			5
#define ARCH_BITS_STR			"32"
#define ARCH_LITTLE_ENDIAN		1
#define ARCH_INT_GT_32			0
#define ARCH_ALLOWS_UNALIGNED		1
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define DES_ASM				1
#define DES_128K			0
#define DES_X2				1
#define DES_MASK			1
#define DES_SCALE			0
#define DES_EXTB			0
#define DES_COPY			1
#define DES_STD_ALGORITHM_NAME		"DES 48/64 4K MMX"
#define DES_BS_ASM			0
#define DES_BS				1
#define DES_BS_EXPAND			1

#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_NAME			"SSE2"
#ifndef CPU_FALLBACK
#define CPU_FALLBACK			0
#endif
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-sse"
#define CPU_FALLBACK_BINARY_DEFAULT
#endif

#ifdef __XOP__
#define JOHN_XOP
#endif
#if defined(__AVX__) || defined(JOHN_XOP)
#define JOHN_AVX
#endif

#if defined(JOHN_AVX) && (defined(__GNUC__) || defined(_OPENMP))
/*
 * Require gcc for non-OpenMP AVX+ builds, because DES_bs_all is aligned in a
 * gcc-specific way in those.  (In non-OpenMP SSE2 builds, it's aligned in the
 * assembly file.  In OpenMP builds, it's aligned by our runtime code.)
 */
#define CPU_REQ_AVX
#undef CPU_NAME
#define CPU_NAME			"AVX"
#ifndef CPU_FALLBACK
#define CPU_FALLBACK			0
#endif
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-avx"
#define CPU_FALLBACK_BINARY_DEFAULT
#endif
#ifdef __AVX512F__
#define DES_BS_VECTOR			16
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 512/512 AVX512F"
#elif defined(__AVX2__)
#define DES_BS_VECTOR			8
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX2"
#else
#define DES_BS_VECTOR			4
#ifdef JOHN_XOP
#define CPU_REQ_XOP
#undef CPU_NAME
#define CPU_NAME			"XOP"
#ifdef CPU_FALLBACK_BINARY_DEFAULT
#undef CPU_FALLBACK_BINARY
#define CPU_FALLBACK_BINARY		"john-non-xop"
#endif
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 128/128 XOP"
#else
#define DES_BS_ALGORITHM_NAME		"DES 128/128 AVX"
#endif
#endif
#else
/* Not AVX+ or non-gcc non-OpenMP */
#ifndef _OPENMP
#undef DES_BS_ASM
#define DES_BS_ASM			1
#endif
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2"
#endif

#ifdef _OPENMP
#define MD5_ASM				0
#else
#define MD5_ASM				1
#endif
#define MD5_X2				0
#define MD5_IMM				1

#if defined(_OPENMP) || \
    (defined(__GNUC__) && \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 2)))
#define BF_ASM				0
#define BF_X2				1
#else
#define BF_ASM				1
#define BF_X2				0
#endif
#define BF_SCALE			1

#endif

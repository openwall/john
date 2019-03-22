/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2003,2006,2008,2010,2011,2015,2019 by Solar Designer
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

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			1
#define DES_COPY			0
#define DES_BS_ASM			0
#define DES_BS				1
#define DES_BS_EXPAND			1

#define CPU_DETECT			0

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
#ifdef __AVX512F__
#define DES_BS_VECTOR			8
#undef DES_BS
#define DES_BS				4
#define DES_BS_ALGORITHM_NAME		"DES 512/512 AVX512F"
#elif defined(__AVX2__)
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX2"
#else
#define DES_BS_VECTOR			2
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
#elif defined(__SSE2__)
/* Not AVX+ or non-gcc non-OpenMP */
#ifndef _OPENMP
#undef DES_BS_ASM
#define DES_BS_ASM			1
#endif
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"DES 128/128 SSE2"
#endif

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#define BF_ASM				0
#define BF_SCALE			1

/*
 * 3x (as opposed to 2x) interleaving provides substantial speedup on Core 2
 * CPUs, as well as slight speedup on some other CPUs.  Unfortunately, it
 * results in lower cumulative performance with multiple concurrent threads or
 * processes on some newer SMT-capable CPUs.  While this has nothing to do with
 * AVX per se, building for AVX implies we do not intend to run on a Core 2
 * (which has at most SSE4.1), so checking for AVX here provides an easy way to
 * avoid this performance regression in AVX-enabled builds.  In multi-binary
 * packages with runtime fallbacks, the AVX-enabled binary would invoke a
 * non-AVX fallback binary from its john.c if run e.g. on a Core 2.  We could
 * check for SSE4.2 rather than AVX here, as SSE4.2 was introduced along with
 * SMT-capable Nehalem microarchitecture CPUs, but apparently those CPUs did
 * not yet exhibit the performance regression with 3x interleaving.  Besides,
 * some newer CPUs capable of SSE4.2 but not AVX happen to lack SMT, so will
 * likely benefit from the 3x interleaving with no adverse effects for the
 * multi-threaded case.
 */
#ifdef __AVX__
#define BF_X2				1
#else
#define BF_X2				3
#endif

#endif

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2003,2006,2008,2010,2011,2015 by Solar Designer
 *
 * ...with a trivial change in the jumbo patch, by Alain Espinosa.
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

#if AC_BUILT
#include "autoconfig.h"
#else
#if defined(__ILP32__) || defined(_WIN64) || defined (__LLP64__) || \
	(defined(__SIZE_OF_LONG__) && __SIZEOF_LONG__ == 4)
#define ARCH_WORD			long long
#else
#define ARCH_WORD			long
#endif
#define ARCH_SIZE			8
#define ARCH_BITS			64
#define ARCH_BITS_LOG			6
#define ARCH_BITS_STR			"64"
#define ARCH_LITTLE_ENDIAN		1
#define ARCH_INT_GT_32			0
#endif

#if !defined(ARCH_ALLOWS_UNALIGNED)
#define ARCH_ALLOWS_UNALIGNED		1
#endif
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define CPU_DETECT			0

#if !defined(JOHN_NO_SIMD) && defined(__SSE2__)
#define CPU_NAME			"SSE2"
#endif

#if !defined(JOHN_NO_SIMD) && (__SSSE3__ || JOHN_SSSE3)
#undef CPU_DETECT
#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_REQ_SSSE3			1
#undef CPU_NAME
#define CPU_NAME			"SSSE3"
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-ssse3"
#define CPU_FALLBACK_BINARY_DEFAULT
#endif
#endif

#if !defined(JOHN_NO_SIMD) && (__SSE4_1__ || JOHN_SSE4_1)
#undef CPU_DETECT
#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_REQ_SSE4_1			1
#undef CPU_NAME
#define CPU_NAME			"SSE4.1"
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-sse4.1"
#define CPU_FALLBACK_BINARY_DEFAULT
#endif
#endif

#if !defined(JOHN_NO_SIMD) && defined(__XOP__)
#define JOHN_XOP			1
#endif
#if !defined(JOHN_NO_SIMD) && (defined(__AVX__) || defined(JOHN_XOP) || defined(JOHN_AVX2))
#define JOHN_AVX			1
#endif

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			1
#define DES_COPY			0
#define DES_BS				1
#if defined(JOHN_NO_SIMD) || !defined(__SSE2__)
#define DES_BS_VECTOR			0
#define DES_BS_ALGORITHM_NAME		"DES 64/64"
#elif !defined(JOHN_NO_SIMD) && defined(JOHN_AVX) && (defined(__GNUC__) || defined(_OPENMP))
/*
 * Require gcc for AVX/XOP because DES_bs_all is aligned in a gcc-specific way,
 * except in OpenMP-enabled builds, where it's aligned by different means.
 */
#undef CPU_DETECT
#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_REQ_AVX			1
#undef CPU_NAME
#define CPU_NAME			"AVX"
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
#elif __AVX2__ || JOHN_AVX2
/* 256-bit as 1x256 */
#define DES_BS_VECTOR			4
#undef CPU_NAME
#define CPU_NAME			"AVX2"
#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_REQ_AVX2			1
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-avx2"
#define CPU_FALLBACK_BINARY_DEFAULT
#endif
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX2-16"
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
#elif !defined(JOHN_NO_SIMD) && (defined(__SSE2__) && defined(_OPENMP))
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

#if !defined(JOHN_NO_SIMD) && CPU_DETECT && DES_BS == 3
#define CPU_REQ_XOP			1
#undef CPU_NAME
#define CPU_NAME			"XOP"
#ifdef CPU_FALLBACK_BINARY_DEFAULT
#undef CPU_FALLBACK_BINARY
#define CPU_FALLBACK_BINARY		"john-non-xop"
#endif
#endif

#if !defined(JOHN_NO_SIMD) && (__AVX512F__ || JOHN_AVX512F)
#undef CPU_DETECT
#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_REQ_AVX512F			1
#undef CPU_NAME
#define CPU_NAME			"AVX512F"
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-avx512f"
#define CPU_FALLBACK_BINARY_DEFAULT
#endif
#endif

#if !defined(JOHN_NO_SIMD) && (__AVX512BW__ || JOHN_AVX512BW)
#undef CPU_DETECT
#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_REQ_AVX512BW			1
#undef CPU_NAME
#define CPU_NAME			"AVX512BW"
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-avx512bw"
#define CPU_FALLBACK_BINARY_DEFAULT
#endif
#endif

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#ifdef __GNUC__
#define GCC_VERSION			(__GNUC__ * 10000 \
			 + __GNUC_MINOR__ * 100 \
			 + __GNUC_PATCHLEVEL__)
#endif

#ifdef __SSE2__

#if !defined(JOHN_NO_SIMD)

#if __AVX512F__
#define SIMD_COEF_32 16
#define SIMD_COEF_64 8
#elif __AVX2__
#define SIMD_COEF_32 8
#define SIMD_COEF_64 4
#elif __SSE2__
#define SIMD_COEF_32 4
#define SIMD_COEF_64 2
#elif __MMX__
#define SIMD_COEF_32 2
#define SIMD_COEF_64 1
#endif

#ifndef SIMD_PARA_MD4
#if defined(__INTEL_COMPILER)
#define SIMD_PARA_MD4			3
#elif defined(__clang__)
#define SIMD_PARA_MD4			4
#elif defined(__llvm__)
#define SIMD_PARA_MD4			3
#elif defined(__GNUC__) && GCC_VERSION < 40405	// 4.4.5
#define SIMD_PARA_MD4			1
#elif defined(__GNUC__) && GCC_VERSION < 40500	// 4.5.0
#define SIMD_PARA_MD4			3
#elif defined(__GNUC__) && (GCC_VERSION < 40600 || defined(__XOP__)) // 4.6.0
#define SIMD_PARA_MD4			2
#else
#define SIMD_PARA_MD4			3
#endif
#endif

#ifndef SIMD_PARA_MD5
#if defined(__INTEL_COMPILER)
#define SIMD_PARA_MD5			3
#elif defined(__clang__)
#define SIMD_PARA_MD5			5
#elif defined(__llvm__)
#define SIMD_PARA_MD5			3
#elif defined(__GNUC__) && GCC_VERSION == 30406	// 3.4.6
#define SIMD_PARA_MD5			3
#elif defined(__GNUC__) && GCC_VERSION < 40405	// 4.4.5
#define SIMD_PARA_MD5			1
#elif defined(__GNUC__) && GCC_VERSION < 40500	// 4.5.0
#define SIMD_PARA_MD5			3
#elif defined(__GNUC__) && (GCC_VERSION < 40600 || defined(__XOP__)) // 4.6.0
#define SIMD_PARA_MD5			2
#else
#define SIMD_PARA_MD5			3
#endif
#endif

#ifndef SIMD_PARA_SHA1
#if defined(__INTEL_COMPILER)
#define SIMD_PARA_SHA1			1
#elif defined(__clang__)
#define SIMD_PARA_SHA1			2
#elif defined(__llvm__)
#define SIMD_PARA_SHA1			2
#elif defined(__GNUC__) && GCC_VERSION < 40504	// 4.5.4
#define SIMD_PARA_SHA1			1
#elif !defined(__AVX__) && defined(__GNUC__) && GCC_VERSION > 40700 // 4.7.0
#define SIMD_PARA_SHA1			1
#else
#define SIMD_PARA_SHA1			1
#endif
#endif

#ifndef SIMD_PARA_SHA256
#if __XOP__
#define SIMD_PARA_SHA256 2
#else
#define SIMD_PARA_SHA256 1
#endif
#endif
#ifndef SIMD_PARA_SHA512
#define SIMD_PARA_SHA512 1
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

#define NT_X86_64

#endif	/* !defined(JOHN_NO_SIMD) */

#define SHA_BUF_SIZ			16

#endif /* __SSE2__ */

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
 *
 * In Jumbo, we may get BF_X2 from autoconf (after testing ht cpuid flag).
 */
#ifndef BF_X2
#if !defined(JOHN_NO_SIMD) && __AVX__ && HAVE_HT && _OPENMP
#define BF_X2				1
#else
#define BF_X2				3
#endif
#endif

#endif

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
#define CPU_REQ				0

#ifdef __AVX512F__
#define JOHN_AVX512F
#elif defined(__AVX2__)
#define JOHN_AVX2
#elif defined(__XOP__)
#define JOHN_XOP
#elif defined(__AVX__)
#define JOHN_AVX
#endif

#if defined(JOHN_AVX512F) || defined(JOHN_AVX2) || defined(JOHN_XOP)
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
#undef CPU_REQ
#define CPU_REQ				1
#ifdef JOHN_AVX512F
#define DES_BS_VECTOR			8
#undef DES_BS
#define DES_BS				4
#define DES_BS_ALGORITHM_NAME		"DES 512/512 AVX512F"
#define CPU_REQ_AVX512F
#define CPU_NAME			"AVX512F"
#define CPU_FALLBACK_BINARY_DEFAULT	"john-non-avx512"
#elif defined(JOHN_AVX2)
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"DES 256/256 AVX2"
#define CPU_REQ_AVX2
#define CPU_NAME			"AVX2"
#define CPU_FALLBACK_BINARY_DEFAULT	"john-non-avx2"
#else
#define DES_BS_VECTOR			2
#ifdef JOHN_XOP
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"DES 128/128 XOP"
#define CPU_REQ_XOP
#define CPU_NAME			"XOP"
#define CPU_FALLBACK_BINARY_DEFAULT	"john-non-xop"
#else
#define DES_BS_ALGORITHM_NAME		"DES 128/128 AVX"
#define CPU_NAME			"AVX"
#define CPU_FALLBACK_BINARY_DEFAULT	"john-non-avx"
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

#ifndef CPU_FALLBACK
#define CPU_FALLBACK			0
#endif
#if !defined(CPU_FALLBACK_BINARY) && defined(CPU_FALLBACK_BINARY_DEFAULT)
#define CPU_FALLBACK_BINARY		CPU_FALLBACK_BINARY_DEFAULT
#endif

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#define BF_ASM				0
#define BF_SCALE			1
#define BF_X2				3

#endif

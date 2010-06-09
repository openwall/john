/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2005,2006,2008,2010 by Solar Designer
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

#if defined(__CYGWIN32__) || defined(__BEOS__)
#define OS_TIMER			0
#else
#define OS_TIMER			1
#endif
#define OS_FLOCK			1

#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_NAME			"SSE2"
#ifndef CPU_FALLBACK
#define CPU_FALLBACK			0
#endif
#if CPU_FALLBACK
#define CPU_FALLBACK_BINARY		"john-non-sse"
#endif

#define DES_ASM				1
#define DES_128K			0
#define DES_X2				1
#define DES_MASK			1
#define DES_SCALE			0
#define DES_EXTB			0
#define DES_COPY			1
#define DES_STD_ALGORITHM_NAME		"48/64 4K MMX"
#if defined(__SSE2__) && 0
#define DES_BS_ASM			0
#if 1
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2"
#elif 0
#define DES_BS_VECTOR			6
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2 + 64/64 BS MMX"
#elif 0
#define DES_BS_VECTOR			5
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2 + 32/32 BS"
#else
#define DES_BS_VECTOR			7
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2 + 64/64 BS MMX + 32/32 BS"
#endif
#else
#define DES_BS_ASM			1
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2"
#endif
#define DES_BS				1
#define DES_BS_EXPAND			1

#define MD5_ASM				1
#define MD5_X2				0
#define MD5_IMM				1

#ifdef _OPENMP
#define BF_ASM				0
#define BF_X2				1
#else
#define BF_ASM				1
#define BF_X2				0
#endif
#define BF_SCALE			1

#endif

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2008,2010,2011 by Solar Designer
 */

/*
 * Architecture specific parameters for x86.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#if AC_BUILT
#include "autoconfig.h"
#else
#define ARCH_WORD			long
#define ARCH_SIZE			4
#define ARCH_BITS			32
#define ARCH_BITS_LOG			5
#define ARCH_BITS_STR			"32"
#define ARCH_LITTLE_ENDIAN		1
#define ARCH_INT_GT_32			0
#endif

#if !defined(ARCH_ALLOWS_UNALIGNED)
#define ARCH_ALLOWS_UNALIGNED		1
#endif
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define CPU_DETECT			1
#define CPU_REQ				0

#define DES_ASM				1
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			0
#define DES_EXTB			0
#define DES_COPY			1
#define DES_BS_ASM			0
#ifdef _OPENMP
#define DES_BS				2
#else
#define DES_BS				0
#endif
#define DES_BS_VECTOR			0
#define DES_BS_EXPAND			0

#ifdef _OPENMP
#define MD5_ASM				0
#else
#define MD5_ASM				1
#endif
#define MD5_X2				0
#define MD5_IMM				1

#ifdef _OPENMP
#define BF_ASM				0
#ifndef BF_X2
#define BF_X2				1
#endif
#else
#define BF_ASM				1
#define BF_X2				0
#endif
#define BF_SCALE			1

#endif

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2008,2010,2011 by Solar Designer
 *
 * ...with changes in the jumbo patch for mingw and MSC, by JimF.
 * ...and introduction of MMX_TYPE and MMX_COEF by Simon Marechal.
 * ...and various little things by magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Architecture specific parameters for x86 with MMX.
 *
 * NOTE, all *-mmx.S functionality has been removed. There still
 * are MMX code within DES/BF, etc, but the SHA1/MD[45] no longer
 * have any MMX support.  MMX_COEF logic removed.  (June, 2014, JimF)
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
#define CPU_REQ				1
#define CPU_NAME			"MMX"
#ifndef CPU_FALLBACK
#define CPU_FALLBACK			0
#endif
#if CPU_FALLBACK && !defined(CPU_FALLBACK_BINARY)
#define CPU_FALLBACK_BINARY		"john-non-mmx"
#endif

#define DES_ASM				1
#define DES_128K			0
#define DES_X2				1
#define DES_MASK			1
#define DES_SCALE			0
#define DES_EXTB			0
#define DES_COPY			1
#define DES_STD_ALGORITHM_NAME		"DES 48/64 4K MMX"
#if defined(__MMX__) && defined(_OPENMP)
#define DES_BS_ASM			0
#else
#define DES_BS_ASM			1
#endif
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"DES 64/64 MMX"
#define DES_BS				1
#define DES_BS_EXPAND			1

#ifdef _OPENMP
#define MD5_ASM				0
#else
#define MD5_ASM				1
#endif
#define MD5_X2				0
#define MD5_IMM				1

#if defined(_OPENMP) || defined(_MSC_VER) || \
    (defined(__GNUC__) && \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 2)))
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

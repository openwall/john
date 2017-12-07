/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2005,2008 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Architecture specific parameters for 32-bit PowerPC.
 *   (On configure builds, this header may passthru to ppc32alt.h)
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#if defined (JOHN_ALTIVEC)
// in autoconfig builds, we always link to this header,
// but later KNOW that we are ALTIVEC, so once we know
// we then include the proper header
#undef _JOHN_ARCH_H
#include "ppc32alt.h"

#else

// Settings for a NON ALTIVEC build.

#if AC_BUILT
#include "autoconfig.h"
#else
#define ARCH_WORD			long
#define ARCH_SIZE			4
#define ARCH_BITS			32
#define ARCH_BITS_LOG			5
#define ARCH_BITS_STR			"32"
#define ARCH_LITTLE_ENDIAN		0
#define ARCH_INT_GT_32			0
#endif

#define ARCH_ALLOWS_UNALIGNED		0
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define CPU_DETECT			0

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			0
#define DES_EXTB			1
#define DES_COPY			0
#define DES_BS_ASM			0
#define DES_BS				1
#define DES_BS_EXPAND			1
#define DES_BS_VECTOR			0

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM			0

#define BF_ASM				0
#define BF_SCALE			0
#define BF_X2				0

#define SHA_BUF_SIZ			16

#endif
#endif
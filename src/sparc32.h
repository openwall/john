/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2005,2008 by Solar Designer
 */

/*
 * Architecture specific parameters for SPARC V8, 32-bit.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#define ARCH_WORD			long
#define ARCH_SIZE			4
#define ARCH_BITS			32
#define ARCH_BITS_LOG			5
#define ARCH_BITS_STR			"32"
#define ARCH_LITTLE_ENDIAN		0
#define ARCH_INT_GT_32			0
#define ARCH_ALLOWS_UNALIGNED		0
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define OS_TIMER			1
#define OS_FLOCK			1

#define CPU_DETECT			0

/*
 * Let's not use the old assembly file (developed in 1996) because it uses
 * registers reserved by the SPARC ABI (%g5-%g7) and this no longer works
 * with glibc 2.3.x.  Also, the performance improvement with it is minimal
 * on UltraSPARC processors (which may be made to run a 32-bit build of
 * John for whatever reason).
 */
#define DES_ASM				0
/*
 * Let's also not bother trying 128 KB SPE tables with the old-fashioned DES
 * implementation, despite them resulting in better performance on some
 * systems.  We're using bitslice DES for the most important (most common)
 * DES-based hash types anyway.
 */
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			0
#define DES_COPY			1
#define DES_BS_ASM			0
#define DES_BS				1
#define DES_BS_VECTOR			0
#define DES_BS_EXPAND			1

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				0

#define BF_ASM				0
#define BF_SCALE			0
#define BF_X2				1

#endif

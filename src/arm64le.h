/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013,2019 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Architecture specific parameters for 64-bit ARM in little-endian mode.
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
#define ARCH_ALLOWS_UNALIGNED		0
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define CPU_DETECT			0

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			0
#define DES_COPY			0
#define DES_BS_ASM			0
#if 1
/*
 * Here we assume that we're on AArch64, which implies we have Advanced SIMD.
 *
 * We do have native vandn() and vsel() for this architecture, but the timings
 * are often such that it might be better to minimize use of vandn() and avoid
 * vsel() altogether.  Otherwise, the best setting would have been DES_BS=3.
 */
#define DES_BS				2
#if 1
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"DES 128/128 ASIMD"
#else
#define DES_BS_VECTOR			1
#define DES_BS_ALGORITHM_NAME		"DES 64/64 ASIMD"
#endif
#else
#define DES_BS				2
#define DES_BS_VECTOR			0
#endif
#define DES_BS_EXPAND			1

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#define BF_ASM				0
#define BF_SCALE			0
#define BF_X2				1

#endif

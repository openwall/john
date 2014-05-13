/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Architecture specific parameters for 32-bit ARM in little-endian mode.
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
#define ARCH_ALLOWS_UNALIGNED		0
#endif
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define CPU_DETECT			0

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			0
#define DES_SCALE			1
#define DES_EXTB			0
#define DES_COPY			1
#define DES_BS_ASM			0
#define DES_BS				1
#ifdef __ARM_NEON__
#if 0
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"DES 64/64 NEON"
#elif 0
#define DES_BS_VECTOR			3
#define DES_BS_VECTOR_SIZE		4
#define DES_BS_ALGORITHM_NAME		"DES 64/64 NEON + 32/32"
#elif 0
#define DES_BS_2X64
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"DES 64/64 X2 NEON"
#elif 1
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"DES 128/128 NEON"
#elif 0
#define DES_BS_VECTOR			5
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"DES 128/128 NEON + 32/32"
#else
#define DES_BS_VECTOR			8
#define DES_BS_ALGORITHM_NAME		"DES 128/128 X2 NEON"
#endif
#else
#define DES_BS_VECTOR			0
#endif
#define DES_BS_EXPAND			1

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				0

#define BF_ASM				0
#define BF_SCALE			1
#define BF_X2				0

#endif

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2008 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Architecture specific parameters for PA-RISC.
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

#define CPU_DETECT			0

#define DES_ASM				0
#define DES_128K			1
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			1
#define DES_COPY			0
#define DES_BS_ASM			0
#define DES_BS				1
#define DES_BS_VECTOR			8
#define DES_BS_EXPAND			0
#define DES_BS_ALGORITHM_NAME		"DES 32/32 X8"

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				0

#define BF_ASM				0
#define BF_SCALE			1
#define BF_X2				0

#endif

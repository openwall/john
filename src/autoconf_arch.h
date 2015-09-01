/*
 * This file is Copyright (C) 2014 magnum,
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

/*
 * Architecture specific parameters for autoconf target.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#include "autoconfig.h"

/* Do we need an autoconf test for this? */
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

/* We could do an autoconf test for this */
#define CPU_DETECT			0

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			0
#define DES_SCALE			1
#define DES_EXTB			0
#define DES_COPY			0
#define DES_BS_ASM			0
#define DES_BS				1
#define DES_BS_VECTOR			0
#define DES_BS_EXPAND			1

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#define BF_ASM				0
#define BF_SCALE			0
#ifndef BF_X2
#define BF_X2				1
#endif

#endif

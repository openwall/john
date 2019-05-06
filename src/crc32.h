/*
 * This is a tiny implementation of CRC-32.
 *
 * This software was written by Solar Designer in 1998 and revised in 2005.
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 1998,2005 by Solar Designer and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */

#ifndef _JOHN_CRC32_H
#define _JOHN_CRC32_H

typedef unsigned int CRC32_t;

/*
 * When called for the first time, allocates memory for and initializes
 * the internal table.  Always initializes the CRC-32 value to all 1's.
 */
extern void CRC32_Init(CRC32_t *value);

/*
 * Updates the current CRC-32 value with the supplied data block.
 */
extern void CRC32_Update(CRC32_t *value, void *data, unsigned int size);

/*
 * Finalizes the CRC-32 value by inverting all bits and saving it as
 * little-endian.
 */
extern void CRC32_Final(unsigned char *out, CRC32_t value);

/*
 * initialze the table function.  (Jumbo function)
 */

void CRC32_Init_tab();

/*
 * This is the data, so our macro can access it also. (jumbo only)
 */
extern CRC32_t JTR_CRC32_table[256];
extern CRC32_t JTR_CRC32_tableC[256];

/*
 * This is the data, so our macro can access it also. (jumbo only)
 */
#define jtr_crc32(crc,byte) (JTR_CRC32_table[(unsigned char)((crc)^(byte))] ^ ((crc) >> 8))

/*
 * Function and macro for CRC-32C polynomial. (jumbo only)
 * If using the function, then use the CRC32_Init() and CRC32_Update() function.
 * just make sure to use either the CRC32_UpdateC() function or the jtr_crc32c() macro.
 */
extern void CRC32_UpdateC(CRC32_t *value, void *data, unsigned int size);

#if !JOHN_NO_SIMD && __SSE4_2__
#include "simd-intrinsics.h"
#define jtr_crc32c(crc,byte) (_mm_crc32_u8(crc, byte))

#if __AVX__
#define CRC32_C_ALGORITHM_NAME			"AVX"
#else
#define CRC32_C_ALGORITHM_NAME			"SSE4.2"
#endif

#else
#define jtr_crc32c(crc,byte) (JTR_CRC32_tableC[(unsigned char)((crc)^(byte))] ^ ((crc) >> 8))
#define CRC32_C_ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#endif

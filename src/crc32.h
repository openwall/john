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

#endif

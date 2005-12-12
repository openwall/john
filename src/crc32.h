/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1998,2005 by Solar Designer
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

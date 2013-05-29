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

#include <stdio.h>

#include "memory.h"
#include "crc32.h"

#define POLY 0xEDB88320
#define ALL1 0xFFFFFFFF

static CRC32_t *table = NULL;

void CRC32_Init(CRC32_t *value)
{
	unsigned int index, bit;
	CRC32_t entry;

	*value = ALL1;

	if (table) return;
/* mem_alloc() doesn't return on failure.  If replacing this with plain
 * malloc(3), error checking would need to be added. */
	table = mem_alloc(sizeof(*table) * 0x100);

	for (index = 0; index < 0x100; index++) {
		entry = index;

		for (bit = 0; bit < 8; bit++)
		if (entry & 1) {
			entry >>= 1;
			entry ^= POLY;
		} else
			entry >>= 1;

		table[index] = entry;
	}
}

void CRC32_Update(CRC32_t *value, void *data, unsigned int size)
{
	unsigned char *ptr;
	unsigned int count;
	CRC32_t result;

	result = *value;
	ptr = data;
	count = size;

	if (count)
	do {
		result = (result >> 8) ^ table[(result ^ *ptr++) & 0xFF];
	} while (--count);

	*value = result;
}

void CRC32_Final(unsigned char *out, CRC32_t value)
{
	value = ~value;
	out[0] = value;
	out[1] = value >> 8;
	out[2] = value >> 16;
	out[3] = value >> 24;
}

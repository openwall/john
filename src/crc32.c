/*
 * This is a tiny implementation of CRC-32.
 *
 * Written by Solar Designer <solar at openwall.com> in 1998, revised in
 * 2005 for use in John the Ripper, and placed in the public domain.
 * There's absolutely no warranty.
 */

#include <stdio.h>

#include "memory.h"
#include "crc32.h"

#define POLY 0xEDB88320
#define ALL1 0xFFFFFFFF

static CRC32_t table[256];
static int bInit=0;
void CRC32_Init(CRC32_t *value)
{
	unsigned int index, bit;
	CRC32_t entry;

	*value = ALL1;

	if (bInit) return;
	bInit = 1;
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

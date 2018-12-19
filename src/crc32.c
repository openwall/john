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

#define POLY  0xEDB88320
#define POLYC 0x82F63B78 // CRC-32C
#define ALL1  0xFFFFFFFF

CRC32_t JTR_CRC32_table[256];
CRC32_t JTR_CRC32_tableC[256];
static int bInit=0;

void CRC32_Init_tab()
{
	unsigned int index, bit;
	CRC32_t entry;

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

		JTR_CRC32_table[index] = entry;
	}
	for (index = 0; index < 0x100; index++) {
		entry = index;

		for (bit = 0; bit < 8; bit++)
		if (entry & 1) {
			entry >>= 1;
			entry ^= POLYC;
		} else
			entry >>= 1;

		JTR_CRC32_tableC[index] = entry;
	}
}

void CRC32_Init(CRC32_t *value)
{
	*value = ALL1;
}

void CRC32_Update(CRC32_t *value, void *data, unsigned int count)
{
	unsigned char *ptr = (unsigned char*)data;
	CRC32_t result = *value;

	if (count)
	do {
		result = JTR_CRC32_table[(result ^ *ptr++) & 0xFF] ^ (result >> 8);
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

void CRC32_UpdateC(CRC32_t *value, void *data, unsigned int count)
{
	unsigned char *ptr = (unsigned char*)data;
	CRC32_t result = *value;

	if (count)
	do {
		result = JTR_CRC32_tableC[(result ^ *ptr++) & 0xFF] ^ (result >> 8);
	} while (--count);

	*value = result;
}

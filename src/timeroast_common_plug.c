/*
 * SNTP-MS "Timeroast" patch for john
 *
 * This software is Copyright (c) 2023 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <stdio.h>

#include "formats.h"
#include "memory.h"
#include "common.h"
#include "unicode.h"
#include "johnswap.h"
#include "timeroast_common.h"

struct fmt_tests timeroast_tests[] = {
	{"$sntp-ms$55265c2d9510284b3ad62ab7d5cae532$1c0111e900000000000a24124c4f434ce6e13d4de4200050e1b8428bffbfcd0ae6e16cdc7817804fe6e16cdc7817f412", "legacycomp1"},
	{NULL}
};

int timeroast_valid(char *ciphertext, struct fmt_main *self)
{
	int i;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ciphertext += FORMAT_TAG_LEN;

	for (i = 0; i < 2 * BINARY_SIZE; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;
	if (ciphertext[i] != '$')
		return 0;

	ciphertext += i + 1;
	for (i = 0; i < 2 * SALT_SIZE; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;
	if (ciphertext[i] != 0)
		return 0;

	return 1;
}

void *timeroast_binary(char *ciphertext)
{
	static uint32_t binary[BINARY_SIZE / sizeof(uint32_t)];
	char *hash = ciphertext + FORMAT_TAG_LEN;
	uint32_t i, v;

	for (i = 0; i < BINARY_SIZE / sizeof(uint32_t); i++) {
		v  = ((unsigned int)(atoi16[ARCH_INDEX(hash[0])])) << 4;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[1])]));

		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[2])])) << 12;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[3])])) << 8;

		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[4])])) << 20;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[5])])) << 16;

		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[6])])) << 28;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[7])])) << 24;
		hash += 8;

		binary[i] = v;
	}
	return binary;
}

void *timeroast_salt(char *ciphertext)
{
	static uint32_t salt[SALT_SIZE / sizeof(uint32_t)];
	char *hash = ciphertext + FORMAT_TAG_LEN + 2 * BINARY_SIZE + 1;
	uint32_t i, v;

	for (i = 0; i < SALT_SIZE / sizeof(uint32_t); i++) {
		v  = ((unsigned int)(atoi16[ARCH_INDEX(hash[0])])) << 4;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[1])]));

		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[2])])) << 12;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[3])])) << 8;

		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[4])])) << 20;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[5])])) << 16;

		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[6])])) << 28;
		v |= ((unsigned int)(atoi16[ARCH_INDEX(hash[7])])) << 24;
		hash += 8;

		salt[i] = v;
	}
	return salt;
}

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "formats.h"
#include "johnswap.h"
#include "base64_convert.h"
#include "rawSHA384_common.h"

struct fmt_tests sha384_common_tests_rawsha384[] = {
	{"a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7", "password"},
	{FORMAT_TAG "a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7", "password"},
	{"8cafed2235386cc5855e75f0d34f103ccc183912e5f02446b77c66539f776e4bf2bf87339b4518a7cb1c2441c568b0f8", "12345678"},
	{FORMAT_TAG "8cafed2235386cc5855e75f0d34f103ccc183912e5f02446b77c66539f776e4bf2bf87339b4518a7cb1c2441c568b0f8", "12345678"},
	{"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", ""},
	{FORMAT_TAG "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", ""},
	{"94e75dd8e1f16d7df761d76c021ad98c283791008b98368e891f411fc5aa1a83ef289e348abdecf5e1ba6971604a0cb0", "UPPERCASE"},
	{"47f05d367b0c32e438fb63e6cf4a5f35c2aa2f90dc7543f8a41a0f95ce8a40a313ab5cf36134a2068c4c969cb50db776", "1"},
	{"1e237288d39d815abc653befcab0eb70966558a5bbc10a24739c116ed2f615be31e81670f02af48fe3cf5112f0fa03e8", "12"},
	{"9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f", "123"},
	{"504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c", "1234"},
	{"0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a", "12345"},
	{"0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454", "123456"},
	{"826227b9dfb593ae4ddbd3f5b7e24b6cb92e342c951cce56546fa68a2e56557b5ebac824a5e778438a7f35c985dfe082", "1234567"},
	{NULL}
};

static uint64_t H[8] = {
	0xcbbb9d5dc1059ed8LL,
	0x629a292a367cd507LL,
	0x9159015a3070dd17LL,
	0x152fecd8f70e5939LL,
	0x67332667ffc00b31LL,
	0x8eb44a8768581511LL,
	0xdb0c2e0d64f98fa7LL,
	0x47b5481dbefa4fa4LL
};

/* ------- Check if the ciphertext if a valid SHA384 hash ------- */
int sha384_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

/* ------- Binary ------- */
void *sha384_common_binary(char *ciphertext)
{
	static unsigned char * out;
	char *p;
	int i;

	if (!out) out = mem_calloc_tiny(DIGEST_SIZE, BINARY_ALIGN);

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#if defined(SIMD_COEF_64) && ARCH_LITTLE_ENDIAN==1
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
#endif
	return out;
}

void *sha384_common_binary_BE(char *ciphertext)
{
	static unsigned char * out;
	char *p;
	int i;

	if (!out) out = mem_calloc_tiny(DIGEST_SIZE, BINARY_ALIGN);

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
	return out;
}

void *sha384_common_binary_rev(char *ciphertext)
{
	static union {
		unsigned char out[DIGEST_SIZE];
		uint64_t x;
	} x;
	unsigned char *out = x.out;
	char *p;
	int i;
	uint64_t *b;

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	b = (uint64_t*)out;
	for (i = 0; i < 8; i++) {
		uint64_t t = JOHNSWAP64(b[i])-H[i];
		b[i] = JOHNSWAP64(t);
	}
	return out;
}

/* ------- Split ------- */
char * sha384_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpylwr(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

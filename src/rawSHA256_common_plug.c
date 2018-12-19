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
#include "rawSHA256_common.h"
#include "misc.h"

/* ------- Check if the ciphertext if a valid SHA2 hash ------- */
static int valid_cisco(char *ciphertext)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, CISCO_TAG, CISCO_TAG_LEN))
		p += CISCO_TAG_LEN;

	q = p;
	while (atoi64[ARCH_INDEX(*q)] != 0x7F && q - p <= CISCO_CIPHERTEXT_LENGTH)
		q++;
	return !*q && q - p == CISCO_CIPHERTEXT_LENGTH;
}

static int valid_hex(char *ciphertext)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, HEX_TAG, HEX_TAG_LEN))
		p += HEX_TAG_LEN;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F && q - p <= HEX_CIPHERTEXT_LENGTH)
		q++;
	return !*q && q - p == HEX_CIPHERTEXT_LENGTH;
}

int sha256_common_valid(char *ciphertext, struct fmt_main *self)
{
	return (valid_hex(ciphertext) || valid_cisco(ciphertext));
}

/* ------- Binary ------- */
void * sha256_common_binary(char *ciphertext)
{
	static unsigned char * out;
	char *p;
	int i;

	if (!out) out = mem_calloc_tiny(DIGEST_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + HEX_TAG_LEN;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#ifdef SIMD_COEF_32
	alter_endianity (out, DIGEST_SIZE);
#endif
	return out;
}

void *sha256_common_binary_BE(char *ciphertext)
{
	static unsigned char * out;
	char *p;
	int i;

	if (!out) out = mem_calloc_tiny(DIGEST_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + HEX_TAG_LEN;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	alter_endianity (out, DIGEST_SIZE);
	return out;
}

/* ------- Prepare ------- */
/* Convert Cisco hashes to hex ones, so .pot entries are compatible */
char * sha256_common_prepare(char *split_fields[10], struct fmt_main *self)
{
	static char * out;
	char *o, *p = split_fields[1];

	if (!out) out = mem_calloc_tiny(HEX_TAG_LEN + HEX_CIPHERTEXT_LENGTH + 1,
	                                MEM_ALIGN_WORD);

	if (!valid_cisco(p))
		return p;

	if (!strncmp(p, CISCO_TAG, CISCO_TAG_LEN))
		p += CISCO_TAG_LEN;

	strcpy(out, HEX_TAG);
	o = out + HEX_TAG_LEN;

	while(*p) {
		unsigned int ch, b;

		// Get 1st byte of input (1st and 2nd)
		ch = *p++;
		b = ((atoi64[ch] << 2) & 252) +
			(atoi64[ARCH_INDEX(*p)] >> 4 & 0x03);
		*o++ = itoa16[b >> 4];
		*o++ = itoa16[b & 0x0f];

		// Get 2nd byte of input (2nd and 3rd)
		ch = *p++;
		b = ((atoi64[ch] << 4) & 240) +
			(atoi64[ARCH_INDEX(*p)] >> 2 & 0x0f);
		*o++ = itoa16[b >> 4];
		*o++ = itoa16[b & 0x0f];

		if (!p[1])
			return out;

		// Get 3rd byte of input (3rd and 4th)
		ch = *p++;
		b = ((atoi64[ch] << 6) & 192) +
			(atoi64[ARCH_INDEX(*p++)] & 0x3f);
		*o++ = itoa16[b >> 4];
		*o++ = itoa16[b & 0x0f];
	}
	error_msg("Error in prepare()");
}

/* ------- Split ------- */
char * sha256_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char * out;

	if (!out) out = mem_calloc_tiny(HEX_TAG_LEN + HEX_CIPHERTEXT_LENGTH + 1,
	                                MEM_ALIGN_WORD);

	if (!strncmp(ciphertext, HEX_TAG, HEX_TAG_LEN))
		ciphertext += HEX_TAG_LEN;

	memcpy(out, HEX_TAG, HEX_TAG_LEN);
	memcpylwr(out + HEX_TAG_LEN, ciphertext, HEX_CIPHERTEXT_LENGTH + 1);
	return out;
}

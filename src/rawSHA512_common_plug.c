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
#include "rawSHA512_common.h"
#include "memdbg.h"

/* ------- Check if the ciphertext if a valid SHA2 hash ------- */
int sha512_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += 8;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

int sha512_common_valid_xsha(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	/* Require lowercase hex digits (assume ASCII) */
	pos = ciphertext;
	if (strncmp(pos, XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH))
		return 0;
	pos += 6;
	while (atoi16[ARCH_INDEX(*pos)] != 0x7F && (*pos <= '9' || *pos >= 'a'))
		pos++;
	return !*pos && pos - ciphertext == XSHA512_CIPHERTEXT_LENGTH+6;
}

/* ------- Binary ------- */
void * sha512_common_binary(char *ciphertext)
{
	static unsigned char * out;
	char *p;
	int i;

	if (!out) out = mem_calloc_tiny(DIGEST_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#ifdef SIMD_COEF_64
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
#endif
	return out;
}

void * sha512_common_binary_xsha(char *ciphertext)
{
	static unsigned char * out;
	char *p;
	int i;

	if (!out) out = mem_calloc_tiny(DIGEST_SIZE, MEM_ALIGN_WORD);

	ciphertext += 6;
	p = ciphertext + 8;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#ifdef SIMD_COEF_64
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
#endif
	return out;
}

/* ------- Prepare ------- */
/* Convert Cisco hashes to hex ones, so .pot entries are compatible */
char * sha512_common_prepare_xsha(char *split_fields[10], struct fmt_main *self)
{
	char Buf[200];
	if (!strncmp(split_fields[1], XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH))
		return split_fields[1];
	if (split_fields[0] && strlen(split_fields[0]) == XSHA512_CIPHERTEXT_LENGTH) {
		sprintf(Buf, "%s%s", XSHA512_FORMAT_TAG, split_fields[0]);

		if (sha512_common_valid_xsha(Buf, self)) {
			static char *cp;
			if (!cp) cp = mem_calloc_tiny(XSHA512_CIPHERTEXT_LENGTH+7, 1);
			strcpy(cp, Buf);
			return cp;
		}
	}
	if (strlen(split_fields[1]) == XSHA512_CIPHERTEXT_LENGTH) {
		sprintf(Buf, "%s%s", XSHA512_FORMAT_TAG, split_fields[1]);

		if (sha512_common_valid_xsha(Buf, self)) {
			static char *cp;
			if (!cp) cp = mem_calloc_tiny(XSHA512_CIPHERTEXT_LENGTH+7, 1);
			strcpy(cp, Buf);
			return cp;
		}
	}
	return split_fields[1];
}

/* ------- Split ------- */
char * sha512_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + TAG_LENGTH);
	return out;
}

char * sha512_common_split_xsha(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char * out;

	if (!out) out = mem_calloc_tiny(8 + XSHA512_CIPHERTEXT_LENGTH + 1, MEM_ALIGN_WORD);

	if (!strncmp(ciphertext, XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH))
		return ciphertext;

	memcpy(out, XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH);
	memcpy(out + XSHA512_TAG_LENGTH, ciphertext, XSHA512_CIPHERTEXT_LENGTH + 1);
	strlwr(out + XSHA512_TAG_LENGTH);
	return out;
}

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _COMMON_RAWSHA512_H
#define _COMMON_RAWSHA512_H

/* ------ Contains (at least) prepare(), valid() and split() ------ */
#define XSHA512_FORMAT_TAG              "$LION$"
#define XSHA512_TAG_LENGTH              (sizeof(XSHA512_FORMAT_TAG) - 1)
#define XSHA512_CIPHERTEXT_LENGTH	136

#define FORMAT_TAG			"$SHA512$"
#define TAG_LENGTH			(sizeof(FORMAT_TAG) - 1)
#define CIPHERTEXT_LENGTH		128

/* ------- Check if the ciphertext if a valid SHA2 hash ------- */
#ifdef _RAWSHA512_H
static int valid(char *ciphertext, struct fmt_main *self)
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
#endif

#ifdef _XSHA512_H
static int valid_xsha512(char *ciphertext, struct fmt_main *self)
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
#endif

/* ------- Split ------- */
#ifdef _RAWSHA512_H
static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + TAG_LENGTH);
	return out;
}
#endif

#ifdef _XSHA512_H
static char *split_xsha512(char *ciphertext, int index, struct fmt_main *pFmt) {
	static char * out;

	if (!out) out = mem_alloc_tiny(8 + XSHA512_CIPHERTEXT_LENGTH + 1, MEM_ALIGN_WORD);

	if (!strncmp(ciphertext, XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH))
		return ciphertext;

	memcpy(out, XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH);
	memcpy(out + XSHA512_TAG_LENGTH, ciphertext, XSHA512_CIPHERTEXT_LENGTH + 1);
	strlwr(out + XSHA512_TAG_LENGTH);
	return out;
}
#endif

/* ------- Binary ------- */
#ifdef _RAWSHA512_H
static void *binary(char *ciphertext)
{
	static unsigned char *out;
	int i;

	if (!out)
		out = mem_alloc_tiny(BINARY_SIZE, 8);

	ciphertext += TAG_LENGTH;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = atoi16[ARCH_INDEX(ciphertext[i*2])] * 16 +
                 atoi16[ARCH_INDEX(ciphertext[i*2 + 1])];
	}
#ifdef SIMD_COEF_64
	alter_endianity_to_BE64 (out, BINARY_SIZE/8);
#endif
	return out;
}
#endif

#ifdef _XSHA512_H
static void *binary_xsha512(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD_64 dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	ciphertext += 6;
	p = ciphertext + 8;
	for (i = 0; i < sizeof(buf.c); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#ifdef SIMD_COEF_64
	alter_endianity_to_BE64 (out, BINARY_SIZE/8);
#endif
	return out;
}
#endif

/* ------- Prepare ------- */
#ifdef _XSHA512_H
static char *prepare_xsha512(char *split_fields[10], struct fmt_main *self) {
	char Buf[200];
	if (!strncmp(split_fields[1], XSHA512_FORMAT_TAG, XSHA512_TAG_LENGTH))
		return split_fields[1];
	if (split_fields[0] && strlen(split_fields[0]) == XSHA512_CIPHERTEXT_LENGTH) {
		sprintf(Buf, "%s%s", XSHA512_FORMAT_TAG, split_fields[0]);

		if (valid_xsha512(Buf, self)) {
			char *cp = mem_alloc_tiny(XSHA512_CIPHERTEXT_LENGTH+7,
				MEM_ALIGN_NONE);
			strcpy(cp, Buf);
			return cp;
		}
	}
	if (strlen(split_fields[1]) == XSHA512_CIPHERTEXT_LENGTH) {
		sprintf(Buf, "%s%s", XSHA512_FORMAT_TAG, split_fields[1]);

		if (valid_xsha512(Buf, self)) {
			char *cp = mem_alloc_tiny(XSHA512_CIPHERTEXT_LENGTH+7,
				MEM_ALIGN_NONE);
			strcpy(cp, Buf);
			return cp;
		}
	}
	return split_fields[1];
}
#endif

#endif

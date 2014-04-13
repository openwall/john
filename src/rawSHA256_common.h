/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _COMMON_RAWSHA256_H
#define _COMMON_RAWSHA256_H

/* ------ Contains (at least) prepare(), valid() and split() ------ */
/* Note: Cisco hashes are truncated at length 25. We currently ignore this. */
#define HEX_CIPHERTEXT_LENGTH   64
#define CISCO_CIPHERTEXT_LENGTH 43

#define HEX_TAG                 "$SHA256$"
#define CISCO_TAG               "$cisco4$"

#define HEX_TAG_LEN             (sizeof(HEX_TAG) - 1)
#define CISCO_TAG_LEN           (sizeof(CISCO_TAG) - 1)

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1

/* ------- Check if the ciphertext if a valid SHA2 hash ------- */
static int valid_cisco(char *ciphertext)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, CISCO_TAG, CISCO_TAG_LEN))
		p += CISCO_TAG_LEN;

	q = p;
	while (atoi64[ARCH_INDEX(*q)] != 0x7F)
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
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == HEX_CIPHERTEXT_LENGTH;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return (valid_hex(ciphertext) || valid_cisco(ciphertext));
}

/* Convert Cisco hashes to hex ones, so .pot entries are compatible */
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[HEX_TAG_LEN + HEX_CIPHERTEXT_LENGTH + 1];
	char *o, *p = split_fields[1];

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
	printf("Error in prepare()");
	exit(1);
}

/* ------- Split ------- */
static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[HEX_TAG_LEN + HEX_CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, HEX_TAG, HEX_TAG_LEN))
		return ciphertext;

	memcpy(out, HEX_TAG, HEX_TAG_LEN);
	memcpy(out + HEX_TAG_LEN, ciphertext, HEX_CIPHERTEXT_LENGTH + 1);
	strlwr(out + HEX_TAG_LEN);
	return out;
}
#endif

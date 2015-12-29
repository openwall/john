/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2015 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _COMMON_QNX_H
#define _COMMON_QNX_H

#include "base64_convert.h"

/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT          1000

#define FORMAT_NAME		"qnx hash"
#define BENCHMARK_COMMENT	" (rounds=1000)"
#define BENCHMARK_LENGTH	-1
#define CIPHERTEXT_LENGTH	43

// binary size is 'max' which is for sha512
#define BINARY_SIZE		64
#define BINARY_SIZE_MD5		16
#define BINARY_SIZE_SHA256	16
#define BINARY_ALIGN		4
#define SALT_LENGTH		32
#define SALT_ALIGN		4

/* ------- Check if the ciphertext if a valid QNX crypt ------- */
static int valid(char *ciphertext, struct fmt_main *self) {
	char *origptr = strdup(ciphertext), *ct = origptr;
	int len;
	if (*ct != '@')
		return 0;
	ct = strtokm(&ct[1], "@");
	// Only allow @m @s or @S signatures.
	if (*ct == 'm') len = 32;
	else if (*ct == 's') len = 64;
	else if (*ct == 'S') len = 128;
	else return 0;

	// If ANYTHING follows the signtuare, it must be ",decimal" However
	// having nothing following is valid, and specifies default of ,1000
	if (ct[1]) {
		if (ct[1] != ',' || isdec(&ct[2]))
			return 0;
	}
	ct = strtokm(NULL, "@");
	if (!ishex(ct) || strlen(ct) != len)
		return 0;
	ct = strtokm(NULL, "@");
	if (!ishex(ct) || strlen(ct) > SALT_LENGTH)
		return 0;
	MEM_FREE(origptr);
	return 1;
}

static void *get_binary(char *ciphertext) {
	static ARCH_WORD_32 outbuf[BINARY_SIZE/4];
	unsigned char *out = (unsigned char*)outbuf;
	memset(outbuf, 0, sizeof(outbuf));
	ciphertext = strchr(&ciphertext[1], '@') + 1;
	base64_convert(ciphertext, e_b64_hex, strchr(ciphertext, '@')-ciphertext, out, e_b64_raw, BINARY_SIZE, 0);
	return (void *)outbuf;
}

/* here is our 'unified' tests array. */
#ifdef __QNX_CREATE_PROPER_TESTS_ARRAY__
static struct fmt_tests tests[] = {
	{"@m@bde10f1a1119328c64594c52df3165cf@6e1f9a390d50a85c", "password"},
	{"@s@1de2b7922fa592a0100a1b2b43ea206427cc044917bf9ad219f17c5db0af0452@36bdb8080d25f44f", "password"},
	//{"@S@386d4be6fe9625c014b2486d8617ccfc521566be190d8a982b93698b99e0e3e3a18464281a514d5dda3ec5581389086f42b5dde023e934221bbe2e0106674cf7@129b6761", "password"},
	//{"@S@60653c9f515eb8480486450c82eaad67f894e2f4828b6340fa28f47b7c84cc2b8bc451e37396150a1ab282179c6fe4ca777a7c1a17511b5d83f0ce23ca28da5d@caa3cc118d2deb23", "password"},
	{NULL}
};
#endif

#endif

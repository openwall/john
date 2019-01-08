/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2015 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <string.h>

#include "arch.h"
#include "common.h"
#include "misc.h"
#include "base64_convert.h"

/* This is the base64 that is used in crypt(3). It differs from MIME Base64
   and the latter can be found in base64.[ch] */
const char itoa64[64] = BASE64_CRYPT;
unsigned char atoi64[0x100];
const char itoa16[16]  = HEXCHARS_lc;
const char itoa16u[16] = HEXCHARS_uc;

unsigned char atoi16[0x100], atoi16l[0x100], atoi16u[0x100];

static int initialized = 0;

void common_init(void)
{
	const char *pos;

	if (initialized) return;

	memset(atoi64, 0x7F, sizeof(atoi64));
	for (pos = itoa64; pos <= &itoa64[63]; pos++)
		atoi64[ARCH_INDEX(*pos)] = pos - itoa64;

	memset(atoi16, 0x7F, sizeof(atoi16));
	for (pos = itoa16; pos <= &itoa16[15]; pos++)
		atoi16[ARCH_INDEX(*pos)] = pos - itoa16;

	memcpy(atoi16l, atoi16, sizeof(atoi16l));

	atoi16['A'] = atoi16['a'];
	atoi16['B'] = atoi16['b'];
	atoi16['C'] = atoi16['c'];
	atoi16['D'] = atoi16['d'];
	atoi16['E'] = atoi16['e'];
	atoi16['F'] = atoi16['f'];

	memset(atoi16u, 0x7F, sizeof(atoi16u));
	for (pos = itoa16u; pos <= &itoa16u[15]; pos++)
		atoi16u[ARCH_INDEX(*pos)] = pos - itoa16u;

	initialized = 1;
}

int ishex(const char *q)
{
	const char *p=q;

	if (!q || !*q)
		return 0;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		++q;
	return !*q && !(((q-p))&1);
}
int ishex_oddOK(const char *q)
{
	// Sometimes it is 'ok' to have odd length hex.  Usually not.  If odd is
	// allowed, then the format will have to properly handle odd length.
	if (!q || !*q)
		return 0;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		++q;
	return !*q;
}

int ishexuc(const char *q)
{
	const char *p=q;

	if (!q || !*q)
		return 0;
	while (atoi16u[ARCH_INDEX(*q)] != 0x7F)
		++q;
	return !*q && !(((p-q))&1);
}

int ishexlc(const char *q)
{
	const char *p=q;

	if (!q || !*q)
		return 0;
	while (atoi16l[ARCH_INDEX(*q)] != 0x7F)
		++q;
	return !*q && !(((p-q))&1);
}

int ishexn(const char *q, int n)
{
	const char *p=q;

	if (!q || !*q)
		return 0;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		++q;
	return (q-p) >= n;
}

int ishexucn(const char *q, int n)
{
	const char *p=q;

	if (!q || !*q)
		return 0;
	while (atoi16u[ARCH_INDEX(*q)] != 0x7F)
		++q;
	return (q-p) >= n;
}

int ishexlcn(const char *q, int n)
{
	const char *p=q;

	if (!q || !*q)
		return 0;
	while (atoi16l[ARCH_INDEX(*q)] != 0x7F)
		++q;
	return (q-p) >= n;
}

int ishexuc_oddOK(const char *q)
{
	if (!q || !*q)
		return 0;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'a' && *q <= 'f')
			return 0;
		++q;
	}
	return !*q ;
}

int ishexlc_oddOK(const char *q)
{
	if (!q || !*q)
		return 0;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'A' && *q <= 'F')
			return 0;
		++q;
	}
	return !*q ;
}

static MAYBE_INLINE size_t _hexlen(const char *q, unsigned char dic[0x100], int *extra_chars)
{
	const char *s = q;
	size_t len = strlen(q);

	if (len&1) --len;

	while (dic[ARCH_INDEX(*q)] != 0x7F)
		++q;
	if ((size_t)(q - s)&1) --q;
	if (extra_chars)
		*extra_chars = (*q != 0);
	return (q - s);
}

size_t hexlen(const char *q, int *extra_chars)
{
	if (!q || !*q)
		return 0;
	return _hexlen(q, atoi16, extra_chars);
}

size_t hexlenu(const char *q, int *extra_chars)
{
	if (!q || !*q)
		return 0;
	return _hexlen(q, atoi16u, extra_chars);
}

size_t hexlenl(const char *q, int *extra_chars)
{
	if (!q || !*q)
		return 0;
	return _hexlen(q, atoi16l, extra_chars);
}

static int isdec_len(const char *q, const char *mxv)
{
	const char *p = q;

	if (!q || !*q)
		return 0;
	do {
		if (*p < '0' || *p > '9' || p - q >= 10)
			return 0;
	} while (*++p);
	return p - q < 10 || strcmp(q, mxv) <= 0;
}

int isdec(const char *q)
{
	if (!q || !*q)
		return 0;
	return isdec_len(q, "2147483647");
}

int isdec_negok(const char *q)
{
	if (!q || !*q)
		return 0;
	return *q == '-' ? isdec_len(q + 1, "2147483648") : isdec(q);
}

int isdecu(const char *q)
{
	if (!q || !*q)
		return 0;
	return isdec_len(q, "4294967295");
}

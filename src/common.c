/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <string.h>

#include "arch.h"
#include "common.h"
#include "memdbg.h"

/* This is the base64 that is used in crypt(3). It differs from MIME Base64
   and the latter can be found in base64.[ch] */
const char itoa64[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
char atoi64[0x100];

const char itoa16[16] =
	"0123456789abcdef";
const char itoa16u[16] =
	"0123456789ABCDEF";
char atoi16[0x100];

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

	atoi16['A'] = atoi16['a'];
	atoi16['B'] = atoi16['b'];
	atoi16['C'] = atoi16['c'];
	atoi16['D'] = atoi16['d'];
	atoi16['E'] = atoi16['e'];
	atoi16['F'] = atoi16['f'];

	initialized = 1;
}

int ishex(char *q)
{
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		++q;
	return !*q;
}
int ishexuc(char *q)
{
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'a' && *q <= 'f') return 0;
		++q;
	}
	return !*q;
}
int ishexlc(char *q)
{
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'A' && *q <= 'F') return 0;
		++q;
	}
	return !*q;
}
/*
 * if full string is HEX, then return is positive. If there is something
 * other than hex characters, then the return is negative but is the length
 * of 'valid' hex characters that start the string.
 */
int hexlen(char *q)
{
	char *s = q;
	size_t len = strlen(q);

	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		++q;
	return (len == (size_t)(q - s)) ? (int)(q - s) : -1 - (int)(q - s);
}
int isdec(char *q)
{
	char buf[24];
	int x = atoi(q);
	sprintf(buf, "%d", x);
	return !strcmp(q,buf) && *q != '-';
}
int isdec_negok(char *q)
{
	char buf[24];
	int x = atoi(q);
	sprintf(buf, "%d", x);
	return !strcmp(q,buf);
}
int isdecu(char *q)
{
	char buf[24];
	unsigned int x = atou(q);
	sprintf(buf, "%u", x);
	return !strcmp(q,buf);
}

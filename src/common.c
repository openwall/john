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

const char itoa64[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
unsigned char atoi64[0x100];

const char itoa16[16] =
	"0123456789abcdef";
unsigned char atoi16[0x100], atoi16l[0x100];

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

	initialized = 1;
}

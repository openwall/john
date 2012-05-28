/*
 * This file is part of John the Ripper password cracker,
 *
 * Written by Jim Fougeron <jfoug at cox.net> in 2011.  No copyright
 * is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2011 Jim Fougeron and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  This format is:   8hex:8hex  The first 8 hex is the 'starting' crc value
 *  So, if you have a file and its CRC is XYZ, then you would put that value
 *  here, then when the password(s) are found, append them to the file, and get
 *  the final CRC value.  If you want to find a password with the 'proper' CRC
 *  value, then put 0 into the first field.
 *
 *  The 2nd 8 hex value is what we are looking for.
 *
 */

#include <string.h>

#include "common.h"
#include "formats.h"
#include "pkzip.h"  // includes the 'inline' crc table.

#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL			"crc32"
#define FORMAT_NAME			"CRC-32"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		31

#define BINARY_SIZE			4
#define SALT_SIZE			4

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		8192 // per thread

static struct fmt_tests tests[] = {
	{"$crc32$00000000.fa455f6b", "ripper"},
	{"$crc32$00000000.4ff4f23f", "dummy"},
//	{"$crc32$00000000.00000000", ""},         // this one ends up skewing the benchmark time, WAY too much.
	{"$crc32$4ff4f23f.ce6eb863", "password"}, // this would be for file with contents:   'dummy'  and we want to find a password to append that is 'password'
	{"$crc32$fa455f6b.c59b2aeb", "123456"},   // ripper123456
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crcs);
static ARCH_WORD_32 crcsalt;

static void init(struct fmt_main *pFmt)
{
#ifdef _OPENMP
	int n = omp_get_max_threads();
	if (n > 4) {
		n = 4; // it just won't scale further
		omp_set_num_threads(n);
	}
	pFmt->params.max_keys_per_crypt = MAX_KEYS_PER_CRYPT * n;
#endif
	//printf("Using %u x %u = %u keys per crypt\n", MAX_KEYS_PER_CRYPT, n, pFmt->params.max_keys_per_crypt);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crcs = mem_calloc_tiny(sizeof(*crcs) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *p, *q;
	int i;

	if (strncmp(ciphertext, "$crc32$", 7))
		return 0;

	p = strrchr(ciphertext, '$');
	q = strchr(p, '.');
	if (!q || q-p != 9)
		return 0;
	for (i = 0; i < 8; ++i) {
		int c1 = ARCH_INDEX(ciphertext[7+i]);
		int c2 = ARCH_INDEX(ciphertext[16+i]);
		if (atoi16[c1] == 0x7F || atoi16[c2] == 0x7F)
			return 0;
/* We don't support uppercase hex digits here, or else we'd need to implement
 * split() and set FMT_SPLIT_UNIFIES_CASE. */
		if (c1 >= 'A' && c1 <= 'F')
			return 0;
		if (c2 >= 'A' && c2 <= 'F')
			return 0;
	}
	return 1;
}

static int binary_hash_0(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xf; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xff; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfff; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffff; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfffff; }

static int get_hash_0(int index) { return crcs[index] & 0xf; }
static int get_hash_1(int index) { return crcs[index] & 0xff; }
static int get_hash_2(int index) { return crcs[index] & 0xfff; }
static int get_hash_3(int index) { return crcs[index] & 0xffff; }
static int get_hash_4(int index) { return crcs[index] & 0xfffff; }

static void *binary(char *ciphertext)
{
	static ARCH_WORD_32 *out;
	if (!out)
		out = mem_alloc_tiny(sizeof(ARCH_WORD_32), MEM_ALIGN_WORD);
	sscanf(&ciphertext[16], "%x", out);
	// Performing the complement here, allows us to not have to complement
	// at the end of each crypt_all call.
	*out = ~(*out);
	return out;
}

static void *salt(char *ciphertext)
{
	static ARCH_WORD_32 *out;
	if (!out)
		out = mem_alloc_tiny(sizeof(ARCH_WORD_32), MEM_ALIGN_WORD);
	sscanf(&ciphertext[7], "%x", out);
	// since we ask for the crc of a file, or zero, we need to complement here,
	// to get it into 'proper' working order.
	*out = ~(*out);
	return out;
}

static void set_salt(void *salt)
{
	crcsalt = *((ARCH_WORD_32 *)salt);
}

static void set_key(char *key, int index)
{
	char *p = saved_key[index];
	while ( (*p++ = *key++) )
		;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static void crypt_all(int count)
{
	int i;
#ifdef _OPENMP
#pragma omp parallel for private(i)
#endif
	for (i = 0; i < count; ++i) {
		ARCH_WORD_32 crc = crcsalt;
		unsigned char *p = (unsigned char*)saved_key[i];
		while (*p)
			crc = pkzip_crc32(crc, *p++);
		//crcs[i] = ~crc;
		crcs[i] = crc;
	}
}

static int cmp_all(void *binary, int count)
{
	ARCH_WORD_32 crc=*((ARCH_WORD_32*)binary), i;
	for (i = 0; i < count; ++i)
		if (crc == crcs[i]) return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *((ARCH_WORD_32*)binary) == crcs[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_crc32 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_NOT_EXACT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		cmp_all,
		cmp_one,
		cmp_exact,
		fmt_default_get_source
	}
};

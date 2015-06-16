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
 * If you want alternate plaintexts, run with --keep-guessing option.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_crc32;
#elif FMT_REGISTERS_H
john_register_one(&fmt_crc32);
#else

/* Uncomment to try out a non-SSE4.2 build */
//#undef __SSE4_2__

#include <string.h>

#include "common.h"
#include "formats.h"
#include "crc32.h"
#include "loader.h"

#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE       256	// tuned on core i7
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL			"CRC32"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"CRC32 32/" ARCH_BITS_STR " CRC-32C " CRC32_C_ALGORITHM_NAME
#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		31

#define BINARY_SIZE			4
#define BINARY_ALIGN			4
#define SALT_SIZE			5
#define SALT_ALIGN			4

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		8192 // per thread

static struct fmt_tests tests[] = {
	{"$crc32$00000000.fa455f6b", "ripper"},
	{"$crc32$00000000.4ff4f23f", "dummy"},
//	{"$crc32$00000000.00000000", ""},         // this one ends up skewing the benchmark time, WAY too much.
	{"$crc32$4ff4f23f.ce6eb863", "password"}, // this would be for file with contents:   'dummy'  and we want to find a password to append that is 'password'
	{"$crc32$fa455f6b.c59b2aeb", "123456"},   // ripper123456
	{"$crc32c$00000000.98a61e94", "ripper"},
	{"$crc32c$00000000.d62b95de", "dummy"},
//	{"$crc32c$00000000.00000000", ""},         // this one ends up skewing the benchmark time, WAY too much.
	{"$crc32c$d62b95de.1439c9f9", "password"}, // this would be for file with contents:   'dummy'  and we want to find a password to append that is 'password'
	{"$crc32c$98a61e94.77f23179", "123456"},   // ripper123456
	{NULL}
};

static struct fmt_main *pFmt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static CRC32_t (*crcs);
static CRC32_t crcsalt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int n = omp_get_max_threads();
	if (n > 4) {
		n = 4; // it just won't scale further
		omp_set_num_threads(n);
	}
	self->params.max_keys_per_crypt *= (n*OMP_SCALE);
#endif
	//printf("Using %u x %u = %u keys per crypt\n", MAX_KEYS_PER_CRYPT, n, self->params.max_keys_per_crypt);
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crcs      = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crcs));

	pFmt = self;
}

static void done(void)
{
	MEM_FREE(crcs);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;
	int i;

	if (strncmp(ciphertext, "$crc32$", 7) && strncmp(ciphertext, "$crc32c$", 8))
		return 0;

	p = strrchr(ciphertext, '$');
	q = strchr(p, '.');
	if (!q || q-p != 9)
		return 0;
	for (i = 0; i < 8; ++i) {
		int c1 = ARCH_INDEX(p[1+i]);
		int c2 = ARCH_INDEX(p[10+i]);
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

static int get_hash_0(int index) { return crcs[index] & 0xf; }
static int get_hash_1(int index) { return crcs[index] & 0xff; }
static int get_hash_2(int index) { return crcs[index] & 0xfff; }
static int get_hash_3(int index) { return crcs[index] & 0xffff; }
static int get_hash_4(int index) { return crcs[index] & 0xfffff; }
static int get_hash_5(int index) { return crcs[index] & 0xffffff; }
static int get_hash_6(int index) { return crcs[index] & 0x7ffffff; }

static void *get_binary(char *ciphertext)
{
	static ARCH_WORD_32 *out;
	char *p;
	if (!out)
		out = mem_alloc_tiny(sizeof(ARCH_WORD_32), MEM_ALIGN_WORD);
	p = strchr(ciphertext, '.');
	sscanf(&p[1], "%x", out);
	// Performing the complement here, allows us to not have to complement
	// at the end of each crypt_all call.
	*out = ~(*out);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static ARCH_WORD_32 *out;
	char *cp;

	if (!out)
		out = mem_alloc_tiny(sizeof(ARCH_WORD_32)*2, MEM_ALIGN_WORD);
	cp = strrchr(ciphertext, '$');
	sscanf(&cp[1], "%x", out);
	// since we ask for the crc of a file, or zero, we need to complement here,
	// to get it into 'proper' working order.
	*out = ~(*out);
	if (!strncmp(ciphertext, "$crc32$", 7))
		((char*)out)[4] = 0;
	else
		((char*)out)[4] = 1;
	return out;
}

#if 0 // Not possible with current interface
static char *source(struct db_password *pw, char Buf[LINE_BUFFER_SIZE] )
{
	ARCH_WORD_32 s = *(ARCH_WORD_32*)(pw->source);
	ARCH_WORD_32 b = *(ARCH_WORD_32*)(pw->binary);
	s = ~s;
	b = ~b;
	sprintf(Buf, "$crc32$%08x.%08x", s,b);
	return Buf;
}
#endif

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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
#ifdef _OPENMP
#pragma omp parallel for private(i)
#endif
	for (i = 0; i < count; ++i) {
		CRC32_t crc = crcsalt;
		unsigned char *p = (unsigned char*)saved_key[i];
		while (*p)
			crc = jtr_crc32(crc, *p++);
		crcs[i] = crc;
	}
	return count;
}

static int crypt_allc(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
#ifdef _OPENMP
#pragma omp parallel for private(i)
#endif
	for (i = 0; i < count; ++i) {
		CRC32_t crc = crcsalt;
		unsigned char *p = (unsigned char*)saved_key[i];
		while (*p)
			crc = jtr_crc32c(crc, *p++);
		crcs[i] = crc;
		//printf("In: '%s' Out: %08x\n", saved_key[i], ~crc);
	}
	return count;
}

static void set_salt(void *salt)
{
	crcsalt = *((ARCH_WORD_32 *)salt);
	if (((char*)salt)[4] == 0)
		pFmt->methods.crypt_all = crypt_all;
	else
		pFmt->methods.crypt_all = crypt_allc;

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

#if FMT_MAIN_VERSION > 11
static unsigned int crc32_ver(void *salt)
{
	char *my_salt = (char*)salt;

	return (unsigned int)my_salt[4];
}
#endif

struct fmt_main fmt_crc32 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
			"version: 0 = CRC-32, 1 = CRC-32C",
		},
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			crc32_ver,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
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
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

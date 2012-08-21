/* PST cracker patch for JtR. Hacked together during July of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * Optimizations and shift to pkzip CRC32 code done by JimF
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Uses code from crc32_fmt_plug.c written by JimF */

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "pkzip.h"  // includes the 'inline' crc table.
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               8
static int omp_t = 1;
#endif

#define FORMAT_LABEL			"pst"
#define FORMAT_NAME			"PST custom CRC-32"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		8
#define BINARY_SIZE			4
#define SALT_SIZE			0
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		256

static struct fmt_tests tests[] = {
	{"$pst$a9290513", "openwall"}, /* "jfuck jw" works too ;) */
	{"$pst$50e099bc", "password"},
	{"$pst$00000000", ""},
	{"$pst$e3da3318", "xxx"},
	{"$pst$a655dd18", "XYz123"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out);

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$pst$", 5);
}

static void set_key(char *key, int index) {
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH+1);
}

static int cmp_all(void *binary, int count)
{
	ARCH_WORD_32 crc=*((ARCH_WORD_32*)binary), i;
	for (i = 0; i < count; ++i)
		if (crc == crypt_out[i]) return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *((ARCH_WORD_32*)binary) == crypt_out[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void crypt_all(int count)
{
	int i;
#ifdef _OPENMP
#pragma omp parallel for private(i)
#endif
	for (i = 0; i < count; ++i) {
		ARCH_WORD_32 crc = 0;
		unsigned char *p = (unsigned char*)saved_key[i];
		while (*p)
			crc = pkzip_crc32(crc, *p++);
		crypt_out[i] = crc;
	}
}

static void *get_binary(char *ciphertext)
{
	static ARCH_WORD_32 *out;
	if (!out)
		out = mem_alloc_tiny(sizeof(ARCH_WORD_32), MEM_ALIGN_WORD);
	sscanf(&ciphertext[5], "%x", out);
	return out;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int binary_hash_0(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xf; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xff; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfff; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffff; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfffff; }

static int get_hash_0(int index) { return crypt_out[index] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index] & 0xfffff; }

struct fmt_main pst_fmt = {
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
		get_binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
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
		cmp_exact
	}
};

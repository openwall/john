/*
 * PST cracker patch for JtR. Hacked together during July of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * Optimizations and shift to pkzip CRC32 code done by JimF.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Uses code from crc32_fmt_plug.c written by JimF.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pst;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pst);
#else

#include <string.h>

#include "arch.h"
#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif
#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "crc32.h"

#define FORMAT_LABEL            "PST"
#define FORMAT_NAME             "custom CRC-32"
#define FORMAT_TAG              "$pst$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        8
#define BINARY_SIZE             4
#define SALT_SIZE               0
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1024

#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE               1024
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               16 // Tuned w/ MKPC for core i7
#endif
#endif

static struct fmt_tests tests[] = {
	{"$pst$a9290513", "openwall"}, /* "jfuck jw" works too ;) */
	{"$pst$50e099bc", "password"},
	{"$pst$00000000", ""},
	{"$pst$e3da3318", "xxx"},
	{"$pst$a655dd18", "XYz123"},
	{"$pst$29b14070", "thisisalongstring"},
	{"$pst$25b44615", "string with space"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out);

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	p = ciphertext + FORMAT_TAG_LEN;
	if (hexlenl(p, &extra) != BINARY_SIZE * 2 || extra)
		return 0;
	return 1;
}

static void set_key(char *key, int index) {
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static int cmp_all(void *binary, int count)
{
	uint32_t crc=*((uint32_t*)binary), i;

	for (i = 0; i < count; ++i)
		if (crc == crypt_out[i]) return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *((uint32_t*)binary) == crypt_out[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;

#ifdef _OPENMP
#pragma omp parallel for private(i)
#endif
	for (i = 0; i < count; ++i) {
		CRC32_t crc = 0;
		unsigned char *p = (unsigned char*)saved_key[i];
		while (*p)
			crc = jtr_crc32(crc, *p++);
		crypt_out[i] = crc;
	}
	return count;
}

static void *get_binary(char *ciphertext)
{
	static uint32_t *out;

	if (!out)
		out = mem_alloc_tiny(sizeof(uint32_t), MEM_ALIGN_WORD);
	sscanf(&ciphertext[FORMAT_TAG_LEN], "%x", out);

	return out;
}

static char *get_key(int index)
{
	return saved_key[index];
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

struct fmt_main fmt_pst = {
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_TRUNC | FMT_8_BIT | FMT_NOT_EXACT,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
		{ NULL },
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
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

/* This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright magnum 2013,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_mdb;
#elif FMT_REGISTERS_H
john_register_one(&fmt_mdb);
#else

#include <string.h>
#include <errno.h>
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif
#include "arch.h"
#include "md5.h"
#include "common.h"
#include "formats.h"
#include "params.h"

#define FORMAT_LABEL            "md5-broken"
#define FORMAT_NAME             "Broken MD5"
#define FORMAT_TAG              "$md5-broken$"
#define TAG_LENGTH              12
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             32
#define SALT_SIZE               0
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests md5_broken_tests[] = {
	{"5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{"?a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{"??????8b9d40e1329780d62ea2265d8a", "test1"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
	                            self->params.max_keys_per_crypt,
	                            MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
	                            self->params.max_keys_per_crypt,
	                            MEM_ALIGN_WORD);
}

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	if (strlen(p) != 32 && strlen(p) != 64)
		return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE + 1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = strrchr(ciphertext, '$') + 1;
	else
		p = ciphertext;

	strcpy((char*)out, p);

	return out;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char hash[16];
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		MD5_Final(hash, &ctx);
		hex_encode(hash, 16, (unsigned char*)crypt_out[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	int any_matched = 0;
	int i;
	for (; index < count; index++) {
		int matched = 1;
		unsigned char *p = (unsigned char*)binary;
		unsigned char *q = (unsigned char*)crypt_out[index];
		for (i = 0; i < BINARY_SIZE; i++) {
			if (p[i] != q[i] && p[i] != '?') {
				matched = 0;
				break;
			}
		}
		if (matched)
			any_matched = 1;
	}

	return any_matched;
}

static int cmp_one(void *binary, int index)
{
	int i;
	unsigned char *p = (unsigned char*)binary;
	unsigned char *q = (unsigned char*)crypt_out[index];
	for (i = 0; i < BINARY_SIZE; i++)
		if (p[i] != q[i] && p[i] != '?')
			return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	int saved_key_length = strlen(key);

	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_mdb = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		md5_broken_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

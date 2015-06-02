/* Cracker for MySQL network authentication hashes. Hacked together
 * during May of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_mysqlna;
#elif FMT_REGISTERS_H
john_register_one(&fmt_mysqlna);
#else

#include "sha.h"
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1024// tuned K8-dual HT
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"mysqlna"
#define FORMAT_NAME		"MySQL Network Authentication"
#define ALGORITHM_NAME		"SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define HEX_LENGTH		40
#define CIPHERTEXT_LENGTH	90
#define BINARY_SIZE		20
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		MEM_ALIGN_NONE
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests mysqlna_tests[] = {
	{"$mysqlna$2D52396369653E4626293B2F75244D3871507A39*7D63098BEE381A51AA6DF11E307E46BD4F8B6E0C", "openwall"},
	{"$mysqlna$615c2b5e79656f7d4931594e5b5d416c7b483365*c3a70da2874db890eb2f0a5e3ea80b2ed17da0d0", "openwall"},
	{"$mysqlna$295a687c59275452214b366b39776d3f31757b2e*7343f45c94cccd646a1b29bbfad064a9ee5c0380", "overlord magnum"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	char unsigned scramble[20];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
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
	char *p, *q;
	if (strncmp(ciphertext, "$mysqlna$", 9))
		return 0;
	p = ciphertext + 9;
	q = strstr(ciphertext, "*");
	if(!q)
		return 0;
	if (q - p != HEX_LENGTH)
		return 0;
	while (atoi16[ARCH_INDEX(*p)] != 0x7F && p < q)
		p++;
	if (q - p != 0)
		return 0;
	if(strlen(p) < HEX_LENGTH)
		return 0;
	q = p + 1;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p - 1 == HEX_LENGTH;
}

static char* split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	strncpy(out, ciphertext, sizeof(out));
	strlwr(out);

	return out;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	ctcopy += 9;	/* skip over "$mysqlna$" */
	p = strtokm(ctcopy, "*");
	for (i = 0; i < 20; i++)
		cs.scramble[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char stage1_hash[20];
		unsigned char inner_hash[20];
		unsigned char token[20];
		SHA_CTX ctx;
		int i;
		unsigned char *p = (unsigned char*)crypt_out[index];
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA1_Final(stage1_hash, &ctx);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, stage1_hash, 20);
		SHA1_Final(inner_hash, &ctx);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->scramble, 20);
		SHA1_Update(&ctx, inner_hash, 20);
		SHA1_Final(token, &ctx);
		for(i = 0; i < 20; i++) {
			p[i] = token[i] ^ stage1_hash[i];
		}
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void mysqlna_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_mysqlna = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		mysqlna_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
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
		fmt_default_salt_hash,
		NULL,
		set_salt,
		mysqlna_set_key,
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

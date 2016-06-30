/* Collection of miscellaneous formats, inspired from InsidePro!
 *
 * This software is Copyright (c) 2015, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_social_engine;
#elif FMT_REGISTERS_H
john_register_one(&fmt_social_engine);
#else

#include "arch.h"
#include "sha.h"
#include "md5.h"

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               8 // tuned on core i7
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"SocialEngine"
#define FORMAT_NAME		""
#define ALGORITHM_NAME		"MD5(Social Engine)"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define BINARY_ALIGN		sizeof(ARCH_WORD_32)
#define SALT_ALIGN		sizeof(int)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	64
#define FORMAT_TAG              "$social_engine$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

static struct fmt_tests social_engine_tests[] = {
	{"$social_engine$12345678$1733c88974ffc1845267d3215ff8b21e", "123"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
        unsigned char salt[41];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	static int omp_t = 1;
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
	char *p = ciphertext;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;
	if(!p)
		return 0;
	p = strrchr(ciphertext, '$');
	if (!p)
		return 0;
	p = p + 1;
	if (!ishex(p))
		return 0;
	if (strlen(p) != BINARY_SIZE * 2)
		return 0;

	return 1;
}


static void *get_salt(char *ciphertext)
{
	char *p, *q;
        static struct custom_salt cs;
        memset(&cs, 0, sizeof(cs));

        p = ciphertext;
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;
	q = strchr(p, '$');
        strncpy((char *)cs.salt, p, q - p);

        return (void *)&cs;
}

static void set_salt(void *salt)
{
        cur_salt = (struct custom_salt *)salt;

}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p = ciphertext;
	int i;

	p = strrchr(ciphertext, '$') + 1;

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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		MD5_CTX ctx;

		MD5_Init(&ctx);
		MD5_Update(&ctx, "1234", 4); // first 4 bytes
		MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		MD5_Update(&ctx, cur_salt->salt + 4, 4); // last 4 bytes
		MD5_Final((unsigned char*)crypt_out[index], &ctx);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (*((ARCH_WORD_32*)binary) == crypt_out[index][0])
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

static void social_engine_set_key(char *key, int index)
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

struct fmt_main fmt_social_engine = {
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
		{ NULL },
#endif
		social_engine_tests
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
		social_engine_set_key,
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

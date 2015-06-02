/*
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * https://www.trustwave.com/Resources/SpiderLabs-Blog/Changes-in-Oracle-Database-12c-password-hashes/
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_oracle12c;
#elif FMT_REGISTERS_H
john_register_one(&fmt_oracle12c);
#else

#include "arch.h"
#include <openssl/sha.h>
#include <string.h>
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#define PBKDF2_HMAC_SHA512_ALSO_INCLUDE_CTX
#include "pbkdf2_hmac_sha512.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               8 // XXX
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"Oracle12C"
#define FORMAT_NAME		""
#define ALGORITHM_NAME		"PBKDF2-SHA-512 " SHA512_ALGORITHM_NAME
#define PLAINTEXT_LENGTH	125 // XXX
#define CIPHERTEXT_LENGTH	160
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		sizeof(ARCH_WORD_32)
#define BINARY_SIZE		64
#define BINARY_ALIGN		sizeof(ARCH_WORD_32)
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define FORMAT_TAG		"$oracle12c$"
#define FORMAT_TAG_LENGTH	(sizeof(FORMAT_TAG) - 1)

static struct fmt_tests tests[] = {
{"$oracle12c$e3243b98974159cc24fd2c9a8b30ba62e0e83b6ca2fc7c55177c3a7f82602e3bdd17ceb9b9091cf9dad672b8be961a9eac4d344bdba878edc5dcb5899f689ebd8dd1be3f67bff9813a464382381ab36b", "epsilon"},
	{NULL}
};

static struct custom_salt {
	unsigned char salt[16 + 22 + 1];
	int saltlen;
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

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

	if (strncasecmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;

	if (strlen(ciphertext) > (FORMAT_TAG_LENGTH + CIPHERTEXT_LENGTH))
		return 0;

	p = strrchr(ciphertext, '$');
	if (!p)
		return 0;

	p = p + 1;
	if (strlen(p) != (BINARY_SIZE * 2 + 32))
		return 0;

	if (!ishex(p))
		goto error;

	return 1;

error:
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p;
	int i;

	memset(cs.salt, 0, sizeof(cs.salt));

	p = ciphertext + FORMAT_TAG_LENGTH + 2 * BINARY_SIZE;
	// AUTH_VFR_DATA is variable, and 16 bytes in length
	for(i = 0; i < 16; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

	strncpy((char*)cs.salt + 16, "AUTH_PBKDF2_SPEEDY_KEY", 22);  // add constant string to the salt
	cs.saltlen = 16 + 22;

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	int i;
	char *p;

	p = ciphertext + FORMAT_TAG_LENGTH;
	for (i = 0; i < BINARY_SIZE && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
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
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
#endif
	for (i = 0; i < count; i += MAX_KEYS_PER_CRYPT)
	{
		SHA512_CTX ctx;
		pbkdf2_sha512((const unsigned char*)saved_key[i], strlen(saved_key[i]), cur_salt->salt, cur_salt->saltlen, 4096, (unsigned char*)crypt_out[i], BINARY_SIZE, 0);

		SHA512_Init(&ctx);
		SHA512_Update(&ctx, (unsigned char*)crypt_out[i], BINARY_SIZE);
		SHA512_Update(&ctx, cur_salt->salt, 16); // AUTH_VFR_DATA. first 16 bytes
		SHA512_Final((unsigned char*)crypt_out[i], &ctx);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
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

static void set_key(char *key, int index)
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

struct fmt_main fmt_oracle12c = {
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

/*
 * This software is Copyright (c) 2016, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_mongodb_scram;
#elif FMT_REGISTERS_H
john_register_one(&fmt_mongodb_scram);
#else

#include <openssl/sha.h>
#include <string.h>
#include "arch.h"
#undef SIMD_COEF_32
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "sha.h"
#include "base64.h"
#include "base64_convert.h"
#include "pbkdf2_hmac_sha1.h"
#include "hmac_sha.h"
#include "md5.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL            "scram"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "SCRAM PBKDF2-SHA1 32/" ARCH_BITS_STR
#define PLAINTEXT_LENGTH        125
#define HASH_LENGTH             28
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(ARCH_WORD_32)
#define BINARY_SIZE             20
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define FORMAT_TAG              "$scram$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)
#define MAX_USERNAME_LENGTH     128

static struct fmt_tests tests[] = {
	{"$scram$someadmin$10000$wf42AF7JaU1NSeBaSmkKzw==$H6A5RF0qz6DrcWNNX4xe+wIeVEw=", "secret"},
	{"$scram$admin$10000$ouQdw5om9Uc5gxulO9F/8w==$DSnATYsgoE8InL5Petfjp8MWGh4=", "test@12345"},
	{NULL}
};

static struct custom_salt {
	int saltlen;
	int iterations;
	char username[MAX_USERNAME_LENGTH + 1];
	unsigned char salt[18 + 1]; /* base64 decoding, 24 / 4 * 3 = 18 */
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
	char *ctcopy, *keeptr, *p;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* username */
		goto err;
	if (strlen(p) >= MAX_USERNAME_LENGTH)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (strlen(p)-2 != base64_valid_length(p, e_b64_mime, flg_Base64_MIME_TRAIL_EQ, 0) || strlen(p) > 24)
		goto err;
	if ((p = strtokm(NULL, "")) == NULL)	/* hash */
		goto err;
	if (strlen(p)-1 != base64_valid_length(p, e_b64_mime, flg_Base64_MIME_TRAIL_EQ, 0) || strlen(p) > HASH_LENGTH)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy, *keeptr, *p;

	memset(&cs, 0, sizeof(cs));
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	strncpy(cs.username, p, 128);
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "$");
	base64_decode(p, strlen(p), (char*)cs.salt);
	MEM_FREE(keeptr);

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE + 1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;

	p = strrchr(ciphertext, '$') + 1;
	base64_decode(p, strlen(p), (char*)out);

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int index;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
	{
		SHA_CTX ctx;
		MD5_CTX mctx;
		unsigned char hexhash[32] = { 0 };
		unsigned char hash[16];
		unsigned char out[BINARY_SIZE];

		MD5_Init(&mctx);
		MD5_Update(&mctx, cur_salt->username, strlen((char*)cur_salt->username));
		MD5_Update(&mctx, ":mongo:", 7);
		MD5_Update(&mctx, saved_key[index], strlen(saved_key[index]));
		MD5_Final(hash, &mctx);
		hex_encode(hash, 16, hexhash);

		pbkdf2_sha1(hexhash, 32, cur_salt->salt, 16, 
				cur_salt->iterations, out, BINARY_SIZE, 0);

		hmac_sha1(out, BINARY_SIZE, (unsigned char*)"Client Key", 10, out, BINARY_SIZE);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, out, BINARY_SIZE);
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
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

struct fmt_main fmt_mongodb_scram = {
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
		{ NULL },
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

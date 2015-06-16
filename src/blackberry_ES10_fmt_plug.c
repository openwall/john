/* Cracker for BlackBerry Enterprise Server 10 hashes.
 *
 * Thanks to Nicolas RUFF for providing the algorithm details and sample
 * hashes!
 *
 * USE BDSMgmt;
 * SELECT LoginPassword FROM EASUsers;
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_blackberry1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_blackberry1);
#else

#include <string.h>
#include <errno.h>
#include "sha2.h"
#include "arch.h"

//#undef _OPENMP
//#undef SIMD_COEF_64
//#undef SIMD_PARA_SHA512

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "sse-intrinsics.h"

#ifdef _OPENMP
#include <omp.h>
// OMP_SCALE tests (intel core i7)
// 8   - 77766
// 64  - 80075
// 128 - 82016  -test=0 is still almost instant.
// 256 - 81753
// 512 - 80537
#ifndef OMP_SCALE
#define OMP_SCALE		128
#endif
#endif
#include "memdbg.h"

#define FORMAT_TAG 		"$bbes10$"
#define FORMAT_TAG_LENGTH	8
#define FORMAT_LABEL 		"Blackberry-ES10"
#define FORMAT_NAME 		""
#define ALGORITHM_NAME 		"SHA-512 " SHA512_ALGORITHM_NAME

#define BENCHMARK_COMMENT	" (101x)"
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		64
#define BINARY_ALIGN		4
#define MAX_SALT_SIZE		64
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT	(SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT	(SIMD_COEF_64*SIMD_PARA_SHA512)
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif
static struct fmt_tests blackberry_tests[] = {
	{"$bbes10$76BDF6BE760FCF5DEE7B20E27632D1FEDD9D64E1BBCC941F42957E87CBFB96F176324B2E2C71976CEBE67CA6F400F33F001D7453D80F4AF5D80C8A93ED0BA0E6$DB1C19C0", "toulouse"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int iterations;
	char unsigned salt[MAX_SALT_SIZE + 1];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
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
	char *ctcopy, *keeptr;
	char *p;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;

	if (0 < strlen(ctcopy) && '$' == ctcopy[strlen(ctcopy) - 1]) /* Can not end with '$' */
		goto err;
	if ((p = strtokm(ctcopy, "$")) == NULL) /* hash */
		goto err;
	if(strlen(p) != BINARY_SIZE * 2)
		goto err;
	if (!ishexuc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt */
		goto err;
	if(strlen(p) > MAX_SALT_SIZE)
		goto err;
	p = strtokm(NULL, "$");
	if (p)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	p = strrchr(ciphertext, '$') + 1;
	strcpy((char*)cs.salt, p);

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD_32 dummy;
	} buf;
	unsigned char *out = buf.c;
	int i;
	char *p = ciphertext + FORMAT_TAG_LENGTH;

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
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
	{
		int j;
		SHA512_CTX ctx;
#ifdef SIMD_COEF_64
		unsigned int i;
		unsigned char _IBuf[128*MAX_KEYS_PER_CRYPT+MEM_ALIGN_CACHE],
		              *keys, tmpBuf[128];
		ARCH_WORD_64 *keys64, *tmpBuf64=(ARCH_WORD_64*)tmpBuf, *p64;
		keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_CACHE);
		keys64 = (ARCH_WORD_64*)keys;
		memset(keys, 0, 128*MAX_KEYS_PER_CRYPT);

		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, saved_key[index+i], strlen(saved_key[index+i]));
			SHA512_Update(&ctx, cur_salt->salt, strlen((char*)cur_salt->salt));
			SHA512_Final(tmpBuf, &ctx);
			p64 = &keys64[i%SIMD_COEF_64+i/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64];
			for (j = 0; j < 8; ++j)
				p64[j*SIMD_COEF_64] = JOHNSWAP64(tmpBuf64[j]);
			p64[8*SIMD_COEF_64] = 0x8000000000000000ULL;
			p64[15*SIMD_COEF_64] = 0x200;
		}
		for (j = 0; j < 98; j++)
			SSESHA512body(keys, keys64, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);
		// Last one with FLAT_OUT
		SSESHA512body(keys, (ARCH_WORD_64*)crypt_out[index], NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT|SSEi_FLAT_OUT);
#else
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA512_Update(&ctx, cur_salt->salt, strlen((char*)cur_salt->salt));
		SHA512_Final((unsigned char *)crypt_out[index], &ctx);

		/* now "h" (crypt_out[index] becomes our input
		 * total SHA-512 calls => 101 */
		for (j = 0; j < 99; j++) {
			SHA512_CTX ctx;
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, (unsigned char*)crypt_out[index], 64);
			SHA512_Final((unsigned char *)crypt_out[index], &ctx);
		}
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
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

static void blackberry_set_key(char *key, int index)
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

struct fmt_main fmt_blackberry1 = {
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
		blackberry_tests
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
		blackberry_set_key,
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

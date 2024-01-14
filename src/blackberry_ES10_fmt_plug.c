/*
 * Cracker for BlackBerry Enterprise Server 10 hashes.
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

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#define FORMAT_TAG              "$bbes10$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG)-1)
#define FORMAT_LABEL            "Blackberry-ES10"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "SHA-512 " SHA512_ALGORITHM_NAME

#define BENCHMARK_COMMENT       " (101x)"
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             64
#define BINARY_ALIGN            4
#define MAX_SALT_SIZE           64
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              4
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512 * 2)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      2
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               16 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests blackberry_tests[] = {
	{"$bbes10$76BDF6BE760FCF5DEE7B20E27632D1FEDD9D64E1BBCC941F42957E87CBFB96F176324B2E2C71976CEBE67CA6F400F33F001D7453D80F4AF5D80C8A93ED0BA0E6$DB1C19C0", "toulouse"},
	{"$bbes10$57ECCAA65BB087E3E506A8C5CEBEE193DD051538CE44F4156D65F1B44E0266DF49337EA11812DF12E39C8B12EB46F19C291FD9529CD4F09B3C8109BE6F4861E5$0wzWUnuQ", "test"},
	{"$bbes10$217A6A0646ACF599B5A05A3D2B47F96B576353C74E4D28E857A476EFDFB36B27930FEDAA8064FFD17F36C7C854BED49FF95029B3310434BB2D05524043AE6E44$A5Dr4lXa", "ripper"},
	{"$bbes10$DE1A954989FFED2D74900463A1AD7B14D852164D84AA0443F0EC59A0875A911C92CEF73E7C082B13864132644FA49DFEBDCF1D2DA0C9711CD4DC348A855F7285$MnphRIkf", "superbadPass"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	int iterations;
	unsigned char salt[MAX_SALT_SIZE + 1];
} *cur_salt;

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
	char *ctcopy, *keeptr;
	char *p;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;

	if (0 < strlen(ctcopy) && '$' == ctcopy[strlen(ctcopy) - 1]) /* Can not end with '$' */
		goto err;
	if ((p = strtokm(ctcopy, "$")) == NULL) /* hash */
		goto err;
	if (strlen(p) != BINARY_SIZE * 2)
		goto err;
	if (!ishexuc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt */
		goto err;
	if (strlen(p) > MAX_SALT_SIZE)
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
		uint32_t dummy;
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

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		int j;
		SHA512_CTX ctx;
#ifdef SIMD_COEF_64
/* We use SSEi_HALF_IN, so can halve SHA_BUF_SIZ */
#undef SHA_BUF_SIZ
#define SHA_BUF_SIZ 8
		unsigned int i;
		unsigned char _IBuf[8*SHA_BUF_SIZ*MIN_KEYS_PER_CRYPT+MEM_ALIGN_CACHE], *keys;
		uint64_t *keys64, tmpBuf64[SHA_BUF_SIZ], *p64;
		keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_CACHE);
		keys64 = (uint64_t*)keys;

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, saved_key[index+i], strlen(saved_key[index+i]));
			SHA512_Update(&ctx, cur_salt->salt, strlen((char*)cur_salt->salt));
			SHA512_Final((unsigned char *)tmpBuf64, &ctx);
			p64 = &keys64[i%SIMD_COEF_64+i/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64];
			for (j = 0; j < 8; ++j)
#if ARCH_LITTLE_ENDIAN==1
				p64[j*SIMD_COEF_64] = JOHNSWAP64(tmpBuf64[j]);
#else
				p64[j*SIMD_COEF_64] = tmpBuf64[j];
#endif
		}
		uint64_t rounds = 98;
		SIMDSHA512body(keys, keys64, &rounds, SSEi_HALF_IN|SSEi_LOOP);
		SIMDSHA512body(keys, (uint64_t*)crypt_out[index], NULL, SSEi_HALF_IN|SSEi_FLAT_OUT);
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
	int index;

	for (index = 0; index < count; index++)
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
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
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
		{ NULL },
		{ FORMAT_TAG },
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
		blackberry_set_key,
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

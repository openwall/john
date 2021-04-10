/*
 * Format for brute-forcing PGP SDAs (self-decrypting archives).
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pgpsda;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pgpsda);
#else

#include <string.h>
#include <openssl/cast.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               16  // MKPC and OMP_SCALE tuned on Core i7-6600U

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "sha.h"
#include "loader.h"
#include "pgpsda_common.h"

#define FORMAT_LABEL            "pgpsda"
#define ALGORITHM_NAME          "SHA1 " ARCH_BITS_STR
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define BINARY_SIZE             8
#define BINARY_ALIGN            sizeof(uint32_t)
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define FORMAT_TAG              "$pgpsda$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      8

static struct custom_salt *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE * 2 / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out)
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#undef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH 20

static void pgpsda_kdf(char *password, unsigned char *salt, unsigned char *key)
{
	int plen;
	int iterations = cur_salt->iterations;
	SHA_CTX ctx; // SHA1 usage is hardcoded
	uint32_t j = 0; // "j" has type uint8_t in the original code

	plen = strlen(password);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, salt, 8);
	for (j = 0; j < iterations; j++) {
		SHA1_Update(&ctx, password, plen);
#if ARCH_LITTLE_ENDIAN
		SHA1_Update(&ctx, (uint8_t*)&j, 1);
#else
		SHA1_Update(&ctx, ((uint8_t*)&j) + 3, 1);
#endif
	}

	SHA1_Final(key, &ctx);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char key[SHA1_DIGEST_LENGTH];

		CAST_KEY ck;

		pgpsda_kdf(saved_key[index], cur_salt->salt, key);
		CAST_set_key(&ck, 16, key);
		memset((unsigned char*)crypt_out[index], 0, BINARY_SIZE);
		CAST_ecb_encrypt(key, (unsigned char*)crypt_out[index], &ck, CAST_ENCRYPT);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
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
	strnzcpy(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_pgpsda = {
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
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		pgpsda_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		pgpsda_common_valid,
		fmt_default_split,
		get_binary,
		pgpsda_common_get_salt,
		{
			pgpsda_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
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
#endif /* HAVE_LIBCRYPTO */

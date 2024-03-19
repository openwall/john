/*
 * Format for brute-forcing PGP WDE encrypted drives.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pgpwde;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pgpwde);
#else

#include <string.h>

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
#include "loader.h"
#include "pgpwde_common.h"

#define FORMAT_LABEL            "pgpwde"
#define ALGORITHM_NAME          "S2K-SHA1 32/" ARCH_BITS_STR
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      8
#define FORMAT_TAG              "$pgpwde$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

static struct custom_salt *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

// In PGP WDE, s2ktype == 100
static void S2KPGPWDE(char *password, unsigned char *salt, unsigned char *key, int key_length)
{
	SHA_CTX ctx;
	uint32_t num = (key_length - 1) / SHA_DIGEST_LENGTH + 1;
	int i, j;

	uint32_t bytes;
	int slen;
	const unsigned char b = 0;
	uint32_t cbytes = cur_salt->bytes;

	slen = strlen(password);
	if (cbytes < slen + 16)
		cbytes = (uint32_t)(slen + 16);

	for (i = 0; i < num; i++) {
		bytes = cbytes;
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, &b, 1);
		}

		while (bytes > slen + 16) {
			SHA1_Update(&ctx, salt, 16);
			SHA1_Update(&ctx, password, slen);
			bytes -= slen + 16;
		}
		if (bytes <= 16) {
			SHA1_Update(&ctx, salt, bytes);
		} else {
			SHA1_Update(&ctx, salt, 16);
			SHA1_Update(&ctx, password, bytes - 16);
		}
		SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
	}
}

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0]) * count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char key[40];
		int ret;

		S2KPGPWDE(saved_key[index], cur_salt->salt, key, 32);
		ret = pgpwde_decrypt_and_verify(key, cur_salt->esk, 128);
		cracked[index] = (0 == ret);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
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

static unsigned int pgpwde_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int)cs->bytes;
}

struct fmt_main fmt_pgpwde = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		pgpwde_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		pgpwde_valid,
		fmt_default_split,
		fmt_default_binary,
		pgpwde_get_salt,
		{
			pgpwde_iteration_count,
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

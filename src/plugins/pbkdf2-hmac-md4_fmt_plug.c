/*
 * This software is Copyright (c) 2015 magnum and it is hereby released to
 * the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pbkdf2_hmac_md4;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pbkdf2_hmac_md4);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "pbkdf2_hmac_md4.h"
#include "pbkdf2_hmac_common.h"

#define FORMAT_LABEL            "PBKDF2-HMAC-MD4"
#define FORMAT_NAME             ""
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-MD4 " MD4_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-MD4 32/" ARCH_BITS_STR
#endif
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        125

#if SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_32 * SIMD_PARA_MD4)
#define MAX_KEYS_PER_CRYPT      (64 * SIMD_COEF_32 * SIMD_PARA_MD4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               1 // MKPC and scale tuned for i7
#endif

static struct custom_salt {
	unsigned int length;
	unsigned int rounds;
	char salt[PBKDF2_32_MAX_SALT_SIZE];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[PBKDF2_MDx_BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p;
	int saltlen;
	char delim;

	if (!strncmp(ciphertext, PBKDF2_MD4_FORMAT_TAG, sizeof(PBKDF2_MD4_FORMAT_TAG) - 1))
		ciphertext += sizeof(PBKDF2_MD4_FORMAT_TAG) - 1;
	memset(&cs, 0, sizeof(cs));
	cs.rounds = atoi(ciphertext);
	delim = strchr(ciphertext, '.') ? '.' : '$';
	ciphertext = strchr(ciphertext, delim) + 1;
	p = strchr(ciphertext, delim);
	saltlen = 0;
	memset(cs.salt, 0, sizeof(cs.salt));
	while (ciphertext < p) {        /** extract salt **/
		cs.salt[saltlen++] =
			atoi16[ARCH_INDEX(ciphertext[0])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[1])];
		ciphertext += 2;
	}
	cs.length = saltlen;

	return (void*)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#if SIMD_COEF_32
		int lens[SSE_GROUP_SZ_MD4], i;
		unsigned char *pin[SSE_GROUP_SZ_MD4];
		union {
			uint32_t *pout[SSE_GROUP_SZ_MD4];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_MD4; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = crypt_out[index+i];
		}
		pbkdf2_md4_sse((const unsigned char **)pin, lens,
		               (unsigned char*)cur_salt->salt, cur_salt->length,
		               cur_salt->rounds, &(x.poutc),
		               PBKDF2_MDx_BINARY_SIZE, 0);
#else
		pbkdf2_md4((unsigned char*)(saved_key[index]),
		           strlen(saved_key[index]),
		           (unsigned char*)cur_salt->salt, cur_salt->length,
		           cur_salt->rounds, (unsigned char*)crypt_out[index],
		           PBKDF2_MDx_BINARY_SIZE, 0);
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
	return !memcmp(binary, crypt_out[index], PBKDF2_MDx_BINARY_SIZE);
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int cmp_exact(char *source, int index)
{
	/* does a FULL compare, if the binary buffer of the hash is larger than 16 bytes */
	return pbkdf2_hmac_md4_cmp_exact(get_key(index), source, (unsigned char*)cur_salt->salt, cur_salt->length, cur_salt->rounds);
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->rounds;
}

struct fmt_main fmt_pbkdf2_hmac_md4 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		PBKDF2_MDx_BINARY_SIZE,
		PBKDF2_32_BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			"iteration count",
		},
		{ PBKDF2_MD4_FORMAT_TAG },
		pbkdf2_hmac_md4_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		pbkdf2_hmac_md4_valid,
		pbkdf2_hmac_md4_split,
		pbkdf2_hmac_md4_binary,
		get_salt,
		{
			iteration_count,
		},
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
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

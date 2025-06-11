/*
 * H3C/HPE/Huawei format plugin
 *
 * Copyright (c) 2025 SamuraiOcto
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_h3c;
#elif FMT_REGISTERS_H
john_register_one(&fmt_h3c);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "base64_convert.h"
#include "sha2.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL       "h3c"
#define FORMAT_NAME        "H3C/Huawei/HPE"
#define FORMAT_TAG         "$h$6$"
#define TAG_LENGTH         (sizeof(FORMAT_TAG)-1)

#ifdef SIMD_COEF_64
#define ALGORITHM_NAME     SHA512_ALGORITHM_NAME
#define NBKEYS                     (SIMD_COEF_64*SIMD_PARA_SHA512)
#else
#define ALGORITHM_NAME     "64/" ARCH_BITS_STR
#define NBKEYS             1
#endif

#define BENCHMARK_COMMENT  ""
#define BENCHMARK_LENGTH   0x107
#ifdef SIMD_COEF_64
#define PLAINTEXT_LENGTH   ((128-16-8-1)/2-1)
#else
#define PLAINTEXT_LENGTH   125
#endif
#define BINARY_SIZE        DIGEST_SIZE
#define BINARY_ALIGN       8
#define SALT_SIZE          16
#define SALT_ALIGN         1
#define MIN_KEYS_PER_CRYPT NBKEYS
#define MAX_KEYS_PER_CRYPT (64*NBKEYS)
#define DIGEST_SIZE        64
#define CIPHERTEXT_LENGTH  88

#define BASE64_ALPHABET    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

#ifndef OMP_SCALE
#define OMP_SCALE          8
#endif

#ifdef SIMD_COEF_64
#define FMT_IS_64BIT
#endif

static unsigned char cursalt[SALT_SIZE];
static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint64_t(*crypt_out)[DIGEST_SIZE / sizeof(uint64_t)];


static struct fmt_tests h3c_tests[] = {
	{
		FORMAT_TAG "4tWqOiqovcWddOKv$XyFMVgaE46fGiqsZEHbcr+BM/m9tDkvahDbqU7HoNrvmALk2u31z9c/tuUmX7IiQhWRwN5qoZquW82A8XYaDWA==",
		"abc"
	},
	{
		FORMAT_TAG "abcdefghijklmnop$jp3hDbVlf/L1GNDE4n6x4wqvHnFiEr4YrtM6ax1aFXFb6pdu4Nfmpp09pZFOGOH8ID9vw2AOKQA4q8lByhlG4A==",
		"password"
	},
	{ NULL }
};

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt, sizeof(*crypt_out), sizeof(uint64_t));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int len;

	if (strlen(ciphertext) != TAG_LENGTH + SALT_SIZE + 1 + CIPHERTEXT_LENGTH)
		return 0;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;

	ciphertext += TAG_LENGTH;

	if (ciphertext[SALT_SIZE] != '$')
		return 0;

	ciphertext += SALT_SIZE + 1;

	len = strspn(ciphertext, BASE64_ALPHABET);
	if (len != CIPHERTEXT_LENGTH)
		return 0;
	return 1;
}

static void *get_binary(char *ciphertext)
{
	static union {
		char out[DIGEST_SIZE + 8];
		uint64_t x;
	} x;
	char *realcipher = x.out;

	ciphertext += TAG_LENGTH + SALT_SIZE + 1;
	base64_convert(ciphertext, e_b64_mime, strlen(ciphertext), realcipher, e_b64_raw, sizeof(x.out), flg_Base64_NO_FLAGS, 0);

	return (void *)realcipher;
}

static void set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void *get_salt(char *ciphertext)
{
	static char salt[SALT_SIZE];

	memcpy(salt, ciphertext + TAG_LENGTH, SALT_SIZE);
	return (void *)salt;
}

#define COMMON_GET_HASH_64BIT_HASH
#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
	#pragma omp parallel for
#endif
	for (index = 0; index < count; index += NBKEYS) {
#ifdef SIMD_COEF_64
		unsigned char _in[8 * 16 * MIN_KEYS_PER_CRYPT + MEM_ALIGN_SIMD];
		uint64_t *in = (uint64_t *) mem_align(_in, MEM_ALIGN_SIMD);

		for (int i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			int x80_off = (saved_len[index + i] << 1) + 2 + SALT_SIZE;
			unsigned char *cp = (unsigned char *) & (in[16 * i]);
			int key_length = saved_len[index + i] + 1;      //include null byte

			memcpy(cp, saved_key[index + i], key_length);
			memcpy(&cp[key_length], cursalt, SALT_SIZE);
			memcpy(&cp[key_length + SALT_SIZE], saved_key[index + i], key_length);
			cp[x80_off] = 0x80;
			memset(&cp[x80_off + 1], 0, 120 - (x80_off + 1));
			in[i * 16 + 15] = x80_off << 3;
		}

		SIMDSHA512body(in, crypt_out[index], NULL, SSEi_FLAT_IN | SSEi_FLAT_OUT);
#else
		SHA512_CTX ctx;

		SHA512_Init(&ctx);
		SHA512_Update(&ctx, saved_key[index], saved_len[index] + 1);    // include null byte
		SHA512_Update(&ctx, cursalt, SALT_SIZE);
		SHA512_Update(&ctx, saved_key[index], saved_len[index] + 1);    // include null byte
		SHA512_Final((unsigned char *)crypt_out[index], &ctx);
#endif
	}

	return count;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint64_t *) binary)[0] == crypt_out[index][0])
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


struct fmt_main fmt_h3c = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		"SHA512 " ALGORITHM_NAME,
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL},
		{ FORMAT_TAG},
		h3c_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL},
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

#endif                          /* plugin stanza */

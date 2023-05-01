/*
 * JtR format to crack password protected DiskCryptor volumes.
 *
 * This software is Copyright (c) 2018, Ivan Freed <ivan.freed at protonmail.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_diskcryptor;
#elif FMT_REGISTERS_H
john_register_one(&fmt_diskcryptor);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "jumbo.h"
#include "xts.h"
#include "unicode.h"
#include "twofish.h"
#include "diskcryptor_common.h"
#include "pbkdf2_hmac_sha512.h"

#define FORMAT_NAME             "DiskCryptor"
#define FORMAT_LABEL            "diskcryptor"
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "PBKDF2-SHA512 " SHA512_ALGORITHM_NAME
#else
#if ARCH_BITS >= 64
#define ALGORITHM_NAME          "PBKDF2-SHA512 64/" ARCH_BITS_STR
#else
#define ALGORITHM_NAME          "PBKDF2-SHA512 32/" ARCH_BITS_STR
#endif
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        125
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA512 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

/* Original password */
static char (*orig_key)[PLAINTEXT_LENGTH + 1];
/* Password encoded in UCS-2 */
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
/* UCS-2 password length, in octets */
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	orig_key = mem_calloc(sizeof(*orig_key), self->params.max_keys_per_crypt);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_alloc(self->params.max_keys_per_crypt * sizeof(*saved_len));

	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);

	Twofish_initialise();
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

static void diskcryptor_set_key(char *key, int index)
{
	int len;

	/* store original */
	len = strnzcpyn(orig_key[index], key, sizeof(orig_key[index]));

	/* convert key to UTF-16LE and fill with nulls */
	memset(saved_key[index], 0, PLAINTEXT_LENGTH);
	len = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (unsigned char*)key, len);
	if (len < 0)
		len = strlen16(saved_key[index]);
	saved_len[index] = len << 1;
}

static char *get_key(int index)
{
	return orig_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char seed[MIN_KEYS_PER_CRYPT][128];
		int i;
#ifdef SIMD_COEF_64
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
#endif
		// kdf
#ifdef SIMD_COEF_64
		i = 0;
		do {
			lens[i] = saved_len[index+i];
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = seed[i];
			++i;
		} while (i < MIN_KEYS_PER_CRYPT && index+i < count);
		for (; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = 0;
			pin[i] = pin[0];
			pout[i] = seed[i];
		}
		pbkdf2_sha512_sse((const unsigned char**)pin, lens, cur_salt->salt, cur_salt->saltlen, 1000, pout, 64, 0);
#else

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			pbkdf2_sha512((unsigned char *)saved_key[index+i], saved_len[index+i], cur_salt->salt, cur_salt->saltlen, 1000, seed[i], 64, 0);
		}
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			int success = diskcryptor_decrypt_data(seed[i], cur_salt);

			if (success) {
				cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_diskcryptor = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT | FMT_UNICODE | FMT_ENC,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		diskcryptor_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		diskcryptor_valid,
		fmt_default_split,
		fmt_default_binary,
		diskcryptor_get_salt,
		{
			diskcryptor_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		diskcryptor_set_key,
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

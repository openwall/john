/*
 * Format for cracking SAP's PSE files.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * All credit goes to Martin Gallo's https://github.com/CoreSecurity/pysap project
 * for making this work possible.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sappse;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sappse);
#else

#include <string.h>
#include <openssl/des.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               2  // tuned on i7-7820HQ

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "loader.h"
#include "sap_pse_common.h"
#include "simd-intrinsics.h"
#include "pkcs12.h"

#define FORMAT_LABEL            "sappse"
#define FORMAT_NAME             "SAP PSE"
#define ALGORITHM_NAME          "PKCS#12 PBE (SHA1) " SHA1_ALGORITHM_NAME " 3DES"
// I could not get openssl to use passwords > 48 bytes, so we will cut support at this length.
#define PLAINTEXT_LENGTH        48
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define BINARY_ALIGN            1
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define FORMAT_TAG              "$pse$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA1 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      16
#endif

struct custom_salt *cur_salt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int *cracked;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

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
		unsigned char key[MIN_KEYS_PER_CRYPT][24];
		unsigned char iv[MIN_KEYS_PER_CRYPT][8];
		int i;
#ifdef SIMD_COEF_32
		size_t lens[MIN_KEYS_PER_CRYPT];
		size_t clens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT], *iout[MIN_KEYS_PER_CRYPT];

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = saved_len[i+index];
			clens[i] = saved_len[i+index];
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = key[i];
			iout[i] = iv[i];
		}
		pkcs12_pbe_derive_key_simd_sha1(
				cur_salt->iterations,
				MBEDTLS_PKCS12_DERIVE_KEY, (const unsigned char **)pin, lens,
				cur_salt->salt, cur_salt->salt_size, pout, 24);

		pkcs12_pbe_derive_key_simd_sha1(
				cur_salt->iterations,
				MBEDTLS_PKCS12_DERIVE_IV, (const unsigned char **)pin, clens,
				cur_salt->salt, cur_salt->salt_size, iout, 8);
#else
		for (i = 0; i < MIN_KEYS_PER_CRYPT; i++) {
			// derive key
			pkcs12_pbe_derive_key(1, cur_salt->iterations,
					MBEDTLS_PKCS12_DERIVE_KEY,
					(unsigned char*)saved_key[index+i],
					saved_len[index+i], cur_salt->salt,
					cur_salt->salt_size, key[i], 24);
			// derive iv
			pkcs12_pbe_derive_key(1, cur_salt->iterations,
					MBEDTLS_PKCS12_DERIVE_IV,
					(unsigned char*)saved_key[index+i],
					saved_len[index+i], cur_salt->salt,
					cur_salt->salt_size, iv[i], 8);
		}
#endif

		for (i = 0; i < MIN_KEYS_PER_CRYPT; i++) {
			unsigned char out[16];
			unsigned char input[PLAINTEXT_LENGTH + 8];
			int padbyte;
			DES_cblock ivec;
			DES_key_schedule ks1, ks2, ks3;

			// pin encryption
			DES_set_key_unchecked((DES_cblock *) key[i], &ks1);
			DES_set_key_unchecked((DES_cblock *) (key[i]+8), &ks2);
			DES_set_key_unchecked((DES_cblock *) (key[i]+16), &ks3);
			memcpy(ivec, iv[i], 8);
			memcpy(input, saved_key[index+i], saved_len[index+i]);
			padbyte = 8 - (saved_len[index+i] % 8);
			if (padbyte < 8 && padbyte > 0)
				memset(input + saved_len[index+i], padbyte, padbyte);
			DES_ede3_cbc_encrypt(input, out, 8, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);  // is a 8 bytes verifier enough?

			cracked[index+i] = !memcmp(out, cur_salt->encrypted_pin, 8);
		}
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

static void sappse_set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_sappse = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_OMP,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		sappse_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		sappse_common_valid,
		fmt_default_split,
		fmt_default_binary,
		sappse_common_get_salt,
		{
			sappse_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		sappse_set_key,
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

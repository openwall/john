/*
 * JtR format to crack FileVault 2 hashes.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Big thanks to Omar Choudary, Felix Grobert and Joachim Metz for making this
 * format possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_fvde;
#elif FMT_REGISTERS_H
john_register_one(&fmt_fvde);
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
#include "johnswap.h"
#include "aes.h"
#include "pbkdf2_hmac_sha256.h"
#include "jumbo.h"
#include "fvde_common.h"

#define FORMAT_LABEL            "FVDE"
#define FORMAT_NAME             "FileVault 2"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA256 AES " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256 AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(uint64_t)

#ifndef OMP_SCALE
#define OMP_SCALE               1 // MKPC and scale tuned for i7
#endif

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;
static fvde_custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key),  self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (fvde_custom_salt *)salt;
}

static void fvde_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

/*
 * Unwrap data using AES Key Wrap (RFC3394)
 *
 * Translated from "AESUnwrap" function in aeswrap.py from https://github.com/dinosec/iphone-dataprotection project.
 *
 * The C implementation "aes_key_unwrap" in ramdisk_tools/bsdcrypto/key_wrap.c doesn't look any better.
 *
 * "libfvde_encryption_aes_key_unwrap" isn't great to look at either.
 */
static int fvde_decrypt(fvde_custom_salt *cur_salt, unsigned char *key)
{
	uint64_t *C = cur_salt->blob.qword; // len(C) in blocks == 3 or 5
	int n = BLOBLEN / 8 - 1;  // len(C) - 1
	uint64_t R[5]; // n + 1 = 5
	union {
		uint64_t qword[2];
		unsigned char stream[16];
	} todecrypt;
	int i, j;
	AES_KEY akey;
	uint64_t A = C[0];

	if (cur_salt->type == 1) {
		AES_set_decrypt_key(key, 128, &akey);
		n = 2;  // note
	} else {
		AES_set_decrypt_key(key, 256, &akey);
	}

	for (i = 0; i < n + 1; i++)
		R[i] = C[i];

	for (j = 5; j >= 0; j--) { // 5 is fixed!
		for (i = n; i >=1; i--) { // i = n
#if ARCH_LITTLE_ENDIAN
			todecrypt.qword[0] = JOHNSWAP64(A ^ (n*j+i));
			todecrypt.qword[1] = JOHNSWAP64(R[i]);
			AES_ecb_encrypt(todecrypt.stream, todecrypt.stream, &akey, AES_DECRYPT);
			A = JOHNSWAP64(todecrypt.qword[0]);
			R[i] = JOHNSWAP64(todecrypt.qword[1]);
#else
			todecrypt.qword[0] = A ^ (n*j+i);
			todecrypt.qword[1] = R[i];
			AES_ecb_encrypt(todecrypt.stream, todecrypt.stream, &akey, AES_DECRYPT);
			A = todecrypt.qword[0];
			R[i] = todecrypt.qword[1];
#endif
		}
	}

	if (A == 0xa6a6a6a6a6a6a6a6ULL)
		return 1; // success!

	return 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
	int outlen  = 16;

	if (cur_salt-> type == 2)
		outlen = 32;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char master[MIN_KEYS_PER_CRYPT][32];
		int i;
#ifdef SIMD_COEF_32
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = master[i];
		}
		pbkdf2_sha256_sse((const unsigned char**)pin, lens, cur_salt->salt, cur_salt->salt_length, cur_salt->iterations, pout, outlen, 0);
#else
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			pbkdf2_sha256((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]), cur_salt->salt, cur_salt->salt_length, cur_salt->iterations, master[i], outlen, 0);
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			cracked[index+i] = fvde_decrypt(cur_salt, master[i]);
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

struct fmt_main fmt_fvde = {
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
		fvde_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		fvde_common_valid,
		fmt_default_split,
		fmt_default_binary,
		fvde_common_get_salt,
		{
			fvde_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		fvde_set_key,
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

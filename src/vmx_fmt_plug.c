/*
 * JtR format to crack VMware VMX files.
 *
 * This software is Copyright (c) 2019, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_vmx;
#elif FMT_REGISTERS_H
john_register_one(&fmt_vmx);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "jumbo.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "vmx_common.h"
#include "aes.h"
#include "pbkdf2_hmac_sha1.h"

#ifndef OMP_SCALE
#define OMP_SCALE               1	// MKPC and OMP_SCALE tuned for core i7
#endif

#define FORMAT_LABEL            "vmx"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;
static struct custom_salt *cur_salt;

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
	cur_salt = (struct custom_salt *)salt;
}

static void vmx_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int vmx_decrypt(struct custom_salt *cur_salt, unsigned char *key, unsigned char *data)
{
	unsigned char out[16];
	unsigned char ivec[16];
	AES_KEY aes_decrypt_key;

	memcpy(ivec, data, 16);
	AES_set_decrypt_key(key, 256, &aes_decrypt_key);
	AES_cbc_encrypt(cur_salt->blob + 16, out, 16, &aes_decrypt_key, ivec, AES_DECRYPT);

	return memcmp(out, "type=key:cipher=", 16) == 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0]) * cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
		unsigned char master[MAX_KEYS_PER_CRYPT][32];
		int i;
#ifdef SIMD_COEF_32
		int lens[MAX_KEYS_PER_CRYPT];
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char**)pin, lens, cur_salt->salt, cur_salt->salt_length, cur_salt->iterations, pout, 32, 0);
#else
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			pbkdf2_sha1((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]), cur_salt->salt, cur_salt->salt_length, cur_salt->iterations, master[i], 32, 0);
		}
#endif
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			cracked[index+i] = vmx_decrypt(cur_salt, master[i], cur_salt->blob);
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

struct fmt_main fmt_vmx = {
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
		vmx_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		vmx_common_valid,
		fmt_default_split,
		fmt_default_binary,
		vmx_common_get_salt,
		{
			vmx_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		vmx_set_key,
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

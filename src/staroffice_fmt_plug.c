/*
 * SXC cracker patch for JtR. Hacked together during Summer of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This format also works for other StarOffice file formats.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sxc;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sxc);
#else

#include <string.h>
#include <openssl/blowfish.h>

#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               2 // tuned on core i7
#endif
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "sha.h"
#include "staroffice_common.h"
#define PBKDF2_HMAC_SHA1_ALSO_INCLUDE_CTX
#include "pbkdf2_hmac_sha1.h"
#include "memdbg.h"

#define FORMAT_LABEL            "sxc"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "SHA1 " SHA1_ALGORITHM_NAME " Blowfish"
#else
#define ALGORITHM_NAME          "SHA1 Blowfish 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
// keep plaintext length under 52 to avoid having to deal with the Libra/Star office SHA1 bug
#define PLAINTEXT_LENGTH        51
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
// we store a 'good' SHA1 and a possible bad SHA1 value here (first 4 bytes only)
static uint32_t (*crypt_out)[8 / sizeof(uint32_t)];

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_autotune(self, OMP_SCALE);
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

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

// See "ZipFile::StaticHasValidPassword" from package/source/zipapi/ZipFile.cxx from LibreOffice
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
		unsigned char key[MAX_KEYS_PER_CRYPT][32];
		unsigned char hash[MAX_KEYS_PER_CRYPT][32];
		BF_KEY bf_key;
		int bf_ivec_pos;
		unsigned char ivec[8];
		unsigned char output[1024];
		int i;
		SHA_CTX ctx;

		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, (unsigned char *)saved_key[index+i], strlen(saved_key[index+i]));
			SHA1_Final((unsigned char *)hash[i], &ctx);
		}
#ifdef SIMD_COEF_32
		{
			int lens[MAX_KEYS_PER_CRYPT];
			unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];

			for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
				lens[i] = 20;
				pin[i] = (unsigned char*)hash[i];
				pout[i] = key[i];
			}
			pbkdf2_sha1_sse((const unsigned char**)pin, lens, cur_salt->salt,
				   cur_salt->salt_length,
				   cur_salt->iterations, pout,
				   cur_salt->key_size, 0);
		}
#else
		pbkdf2_sha1(hash[0], 20, cur_salt->salt,
		       cur_salt->salt_length,
		       cur_salt->iterations, key[0],
		       cur_salt->key_size, 0);
#endif
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			unsigned int crypt[5];
			bf_ivec_pos = 0;
			memcpy(ivec, cur_salt->iv, 8);
			BF_set_key(&bf_key, cur_salt->key_size, key[i]);
			BF_cfb64_encrypt(cur_salt->content, output, cur_salt->length, &bf_key, ivec, &bf_ivec_pos, 0);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, output, cur_salt->original_length);
			SHA1_Final((unsigned char*)crypt, &ctx);
			if (cur_salt->original_length % 64 >= 52 && cur_salt->original_length % 64 <= 55) {
				SHA1_Libre_Buggy(output, cur_salt->original_length, crypt);
			}
			crypt_out[index+i][1] = crypt[0];
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++) {
		if (!memcmp(binary, crypt_out[index], 4))
			return 1;
		if (!memcmp(binary, &crypt_out[index][1], 4))
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (!memcmp(binary, crypt_out[index], 4))
		return 1;
	if (!memcmp(binary, &crypt_out[index][1], 4))
		return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	unsigned char key[32];
	unsigned char hash[20];
	unsigned char *binary;
	BF_KEY bf_key;
	int bf_ivec_pos;
	unsigned char ivec[8];
	unsigned char output[1024];
	unsigned int crypt[5];
	SHA_CTX ctx;

	binary = staroffice_get_binary(source);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (unsigned char *)saved_key[index], strlen(saved_key[index]));
	SHA1_Final(hash, &ctx);
	pbkdf2_sha1(hash, 20, cur_salt->salt,
		       cur_salt->salt_length,
		       cur_salt->iterations, key,
		       cur_salt->key_size, 0);
	bf_ivec_pos = 0;
	memcpy(ivec, cur_salt->iv, 8);
	BF_set_key(&bf_key, cur_salt->key_size, key);
	BF_cfb64_encrypt(cur_salt->content, output, cur_salt->length, &bf_key, ivec, &bf_ivec_pos, 0);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, output, cur_salt->original_length);
	SHA1_Final((unsigned char*)crypt, &ctx);
	if (!memcmp(crypt, binary, 20))
		return 1;
	// try the buggy version.
	if (cur_salt->original_length % 64 >= 52 && cur_salt->original_length % 64 <= 55) {
		SHA1_Libre_Buggy(output, cur_salt->original_length, crypt);
		if (!memcmp(crypt, binary, 20))
			return 1;
	}
	return 0;
}

static void sxc_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int) my_salt->iterations;
}

struct fmt_main fmt_sxc = {
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
		staroffice_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		staroffice_valid,
		fmt_default_split,
		staroffice_get_binary,
		staroffice_get_salt,
		{
			iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		sxc_set_key,
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

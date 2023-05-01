/*
 * ODF cracker patch for JtR. Hacked together during Summer of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This also works for various OpenDocument, OpenOffice and LibreOffice file
 * formats.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * This work is based on Udo Schuermann's "Ringlord Technologies ODF Java Library".
 *
 * See https://github.com/kuschuermann/rltodfjlib and http://ringlord.com/odfdecrypt.html
 * for details.
 *
 * Also look at "odfencrypt.groovy" for OpenDocument encryption details.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_odf;
#elif FMT_REGISTERS_H
john_register_one(&fmt_odf);
#else

#include <openssl/blowfish.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha.h"
#include "sha2.h"
#include "aes.h"
#include "odf_common.h"
#include "pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL            "ODF"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME " BF/AES"
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 BF/AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
// keep plaintext length under 52 to avoid having to deal with the Libre/Star office SHA1 bug
#define PLAINTEXT_LENGTH        51
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_SIZE             8
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               1 // Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt *cur_salt;

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
		unsigned char key[MIN_KEYS_PER_CRYPT][32];
		unsigned char hash[MIN_KEYS_PER_CRYPT][32];
		BF_KEY bf_key;
		int bf_ivec_pos, i;
		unsigned char ivec[8];
		unsigned char output[1024];
		SHA_CTX ctx;
#ifdef SIMD_COEF_32
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
#endif
		if (cur_salt->checksum_type == 0 && cur_salt->cipher_type == 0) {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, (unsigned char *)saved_key[index+i], strlen(saved_key[index+i]));
				SHA1_Final((unsigned char *)(hash[i]), &ctx);
			}
#ifdef SIMD_COEF_32
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				lens[i] = 20;
				pin[i] = hash[i];
				pout[i] = key[i];
			}
			pbkdf2_sha1_sse((const unsigned char**)pin, lens, cur_salt->salt,
			       cur_salt->salt_length,
			       cur_salt->iterations, pout,
			       cur_salt->key_size, 0);
#else
			pbkdf2_sha1(hash[0], 20, cur_salt->salt,
			       cur_salt->salt_length,
			       cur_salt->iterations, key[0],
			       cur_salt->key_size, 0);
#endif

			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				unsigned int crypt[5];
				bf_ivec_pos = 0;
				memcpy(ivec, cur_salt->iv, 8);
				BF_set_key(&bf_key, cur_salt->key_size, key[i]);
				BF_cfb64_encrypt(cur_salt->content, output, cur_salt->content_length, &bf_key, ivec, &bf_ivec_pos, BF_DECRYPT);
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, output, cur_salt->original_length);
				SHA1_Final((unsigned char*)crypt, &ctx);
				crypt_out[index+i][0] = crypt[0];
				if (cur_salt->original_length % 64 >= 52 && cur_salt->original_length % 64 <= 55)
					SHA1_odf_buggy(output, cur_salt->original_length, crypt);
				crypt_out[index+i][1] = crypt[0];
			}
		}
		else {
			SHA256_CTX ctx;
			AES_KEY akey;
			unsigned char iv[16];
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				SHA256_Init(&ctx);
				SHA256_Update(&ctx, (unsigned char *)saved_key[index+i], strlen(saved_key[index+i]));
				SHA256_Final((unsigned char *)hash[i], &ctx);
			}
#ifdef SIMD_COEF_32
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				lens[i] = 32;
				pin[i] = hash[i];
				pout[i] = key[i];
			}
			pbkdf2_sha1_sse((const unsigned char**)pin, lens, cur_salt->salt,
			       cur_salt->salt_length,
			       cur_salt->iterations, pout,
			       cur_salt->key_size, 0);
#else
			pbkdf2_sha1(hash[0], 32, cur_salt->salt,
			       cur_salt->salt_length,
			       cur_salt->iterations, key[0],
			       cur_salt->key_size, 0);
#endif
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				unsigned int crypt[8];
				memcpy(iv, cur_salt->iv, 16);
				AES_set_decrypt_key(key[i], 256, &akey);
				AES_cbc_encrypt(cur_salt->content, output, cur_salt->content_length, &akey, iv, AES_DECRYPT);
				SHA256_Init(&ctx);
				SHA256_Update(&ctx, output, cur_salt->content_length);
				SHA256_Final((unsigned char*)crypt, &ctx);
				crypt_out[index+i][0] = crypt[0];
				crypt_out[index+i][1] = crypt[0];
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++) {
		if (*((uint32_t*)binary) == crypt_out[index][0])
			return 1;
		if (*((uint32_t*)binary) == crypt_out[index][1])
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (*((uint32_t*)binary) == crypt_out[index][0])
		return 1;
	if (*((uint32_t*)binary) == crypt_out[index][1])
		return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	return odf_common_cmp_exact(source, saved_key[index], cur_salt);
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_odf = {
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
			"crypto [0=Blowfish 1=AES]",
		},
		{ FORMAT_TAG },
		odf_tests
	}, {
		init,
		done,
		fmt_default_reset,
		odf_prepare,
		odf_valid,
		fmt_default_split,
		odf_get_binary,
		odf_get_salt,
		{
			odf_iteration_count,
			odf_crypto,
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

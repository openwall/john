/*
 * KeePass cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * Support for cracking KeePass databases, which use key file(s), was added by
 * m3g9tr0n (Spiros Fraganastasis) and Dhiru Kholia in September of 2014.
 *
 * Support for all types of keyfile within Keepass 1.x ans Keepass 2.x was
 * added by Fist0urs <eddy.maaalou at gmail.com>
 *
 * This software is
 * Copyright (c) 2012 Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Copyright (c) 2014 m3g9tr0n (Spiros Fraganastasis),
 * Copyright (c) 2016 Fist0urs <eddy.maaalou at gmail.com>, and
 * Copyright (c) 2017 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_KeePass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_KeePass);
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
#include "params.h"
#include "options.h"
#include "keepass_common.h"
#include "sha2.h"
#include "aes.h"
#include "twofish.h"
#include "chacha.h"

#ifndef OMP_SCALE
#define OMP_SCALE               4 // This and MKPC tuned for core i7
#endif

#define FORMAT_LABEL            "KeePass"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "SHA256 AES 32/" ARCH_BITS_STR

static keepass_salt_t *cur_salt;
static int any_cracked, *cracked;
static size_t cracked_size;

// GenerateKey32 from CompositeKey.cs
static void transform_key(char *masterkey, keepass_salt_t *csp,
                          unsigned char *final_key)
{
	SHA256_CTX ctx;
	unsigned char hash[32];
	int i;
	AES_KEY akey;

	// First, hash the masterkey
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, masterkey, strlen(masterkey));
	SHA256_Final(hash, &ctx);

	if (csp->version == 2 && cur_salt->have_keyfile == 0) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Final(hash, &ctx);
	}

	if (cur_salt->have_keyfile) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Update(&ctx, cur_salt->keyfile, 32);
		SHA256_Final(hash, &ctx);
	}

	// Next, encrypt the created hash
	AES_set_encrypt_key(csp->transf_randomseed, 256, &akey);
	i = csp->key_transf_rounds >> 2;
	while (i--) {
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
	}
	i = csp->key_transf_rounds & 3;
	while (i--) {
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
	}

	// Finally, hash it again...
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final(hash, &ctx);

	// ...and hash the result together with the random seed
	SHA256_Init(&ctx);
	if (csp->version == 1) {
		SHA256_Update(&ctx, csp->final_randomseed, 16);
	}
	else {
		SHA256_Update(&ctx, csp->final_randomseed, 32);
	}
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final(final_key, &ctx);
}

static void init(struct fmt_main *self)
{

	omp_autotune(self, OMP_SCALE);

	keepass_key = mem_calloc(self->params.max_keys_per_crypt,
				sizeof(*keepass_key));
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);

	Twofish_initialise();
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(keepass_key);
}

static void set_salt(void *salt)
{
	cur_salt = (keepass_salt_t*)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char final_key[32];
		unsigned char *decrypted_content;
		SHA256_CTX ctx;
		unsigned char iv[16];
		unsigned char out[32];
		int pad_byte;
		int datasize;
		AES_KEY akey;
		Twofish_key tkey;
		struct chacha_ctx ckey;

		// derive and set decryption key
		transform_key(keepass_key[index], cur_salt, final_key);
		if (cur_salt->algorithm == 0) {
			/* AES decrypt cur_salt->contents with final_key */
			memcpy(iv, cur_salt->enc_iv, 16);
			AES_set_decrypt_key(final_key, 256, &akey);
		} else if (cur_salt->algorithm == 1) {
			memcpy(iv, cur_salt->enc_iv, 16);
			memset(&tkey, 0, sizeof(Twofish_key));
			Twofish_prepare_key(final_key, 32, &tkey);
		} else if (cur_salt->algorithm == 2) { // ChaCha20
			memcpy(iv, cur_salt->enc_iv, 16);
			chacha_keysetup(&ckey, final_key, 256);
			chacha_ivsetup(&ckey, iv, NULL, 12);
		}

		if (cur_salt->version == 1 && cur_salt->algorithm == 0) {
			decrypted_content = mem_alloc(cur_salt->contentsize);
			AES_cbc_encrypt(cur_salt->contents, decrypted_content,
			                cur_salt->contentsize, &akey, iv, AES_DECRYPT);
			pad_byte = decrypted_content[cur_salt->contentsize - 1];
			datasize = cur_salt->contentsize - pad_byte;
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, decrypted_content, datasize);
			SHA256_Final(out, &ctx);
			MEM_FREE(decrypted_content);
			if (!memcmp(out, cur_salt->contents_hash, 32)) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
		else if (cur_salt->version == 2 && cur_salt->algorithm == 0) {
			unsigned char dec_buf[32];

			AES_cbc_encrypt(cur_salt->contents, dec_buf, 32,
			                &akey, iv, AES_DECRYPT);
			if (!memcmp(dec_buf, cur_salt->expected_bytes, 32)) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
		else if (cur_salt->version == 2 && cur_salt->algorithm == 2) {
			unsigned char dec_buf[32];

			chacha_decrypt_bytes(&ckey, cur_salt->contents, dec_buf, 32, 20);
			if (!memcmp(dec_buf, cur_salt->expected_bytes, 32)) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}

		}
		else if (cur_salt->version == 1 && cur_salt->algorithm == 1) { /* KeePass 1.x with Twofish */
			int crypto_size;

			decrypted_content = mem_alloc(cur_salt->contentsize);
			crypto_size = Twofish_Decrypt(&tkey, cur_salt->contents,
			                              decrypted_content,
			                              cur_salt->contentsize, iv);
			datasize = crypto_size;  // awesome, right?
			if (datasize <= cur_salt->contentsize && datasize > 0) {
				SHA256_Init(&ctx);
				SHA256_Update(&ctx, decrypted_content, datasize);
				SHA256_Final(out, &ctx);
				if (!memcmp(out, cur_salt->contents_hash, 32)) {
					cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
					any_cracked |= 1;
				}
			}
			MEM_FREE(decrypted_content);
		} else {
			// KeePass version 2 with Twofish is TODO. Twofish support under KeePass version 2
			// requires a third-party plugin. See http://keepass.info/plugins.html for details.
			error_msg("KeePass v2 w/ Twofish not supported yet");
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
	return cracked[index];
}

struct fmt_main fmt_KeePass = {
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
			"version",
			"algorithm [0=AES 1=TwoFish 2=ChaCha]",
		},
		{ FORMAT_TAG },
		keepass_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		keepass_valid,
		fmt_default_split,
		fmt_default_binary,
		keepass_get_salt,
		{
			keepass_iteration_count,
			keepass_version,
			keepass_algorithm,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		keepass_set_key,
		keepass_get_key,
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

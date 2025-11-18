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
 * Copyright (c) 2017-2024 magnum,
 * Copyright (c) 2016 Fist0urs <eddy.maaalou at gmail.com>, and
 * Copyright (c) 2014 m3g9tr0n (Spiros Fraganastasis),
 * Copyright (c) 2012 Dhiru Kholia <dhiru.kholia at gmail.com>,
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
#define THREAD_NUMBER omp_get_thread_num()
#define NUM_THREADS   omp_get_max_threads()
#else
#define THREAD_NUMBER 0
#define NUM_THREADS   1
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "aes.h"
#include "twofish.h"
#include "chacha.h"
#include "hmac_sha.h"
#include "argon2.h"

#define KEEPASS_AES                     1
#define KEEPASS_ARGON2                  1
#define KEEPASS_REAL_COST_TEST_VECTORS  0
#include "keepass_common.h"

#ifndef OMP_SCALE
#define OMP_SCALE               1
#endif

#define FORMAT_LABEL            "KeePass"
#define FORMAT_NAME             ""
#if !defined (JOHN_NO_SIMD) && defined(__AVX512F__)
#define ALGORITHM_NAME          "AES/Argon2 512/512 AVX512F"
#elif !defined (JOHN_NO_SIMD) && defined(__AVX2__)
#define ALGORITHM_NAME          "AES/Argon2 256/256 AVX2"
#elif !defined (JOHN_NO_SIMD) && defined(__XOP__)
#define ALGORITHM_NAME          "AES/Argon2 128/128 XOP"
#elif !defined (JOHN_NO_SIMD) && defined(__SSE2__)
#define ALGORITHM_NAME          "AES/Argon2 128/128 SSE2"
#else
#define ALGORITHM_NAME          "AES/Argon2 32/" ARCH_BITS_STR
#endif

struct argon2_memory {
	region_t region;
	int used;
	char padding[MEM_ALIGN_CACHE - sizeof(region_t) - sizeof(int)];
};

static struct argon2_memory *thread_mem;

static keepass_salt_t *cur_salt;
static int any_cracked, *cracked;
static size_t cracked_size;

static void init(struct fmt_main *self)
{
	int i;

	omp_autotune(self, OMP_SCALE);

	thread_mem = mem_calloc(NUM_THREADS, sizeof(struct argon2_memory));
	keepass_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*keepass_key));
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);
	any_cracked = 0;

	for (i = 0; i < NUM_THREADS; i++)
		init_region(&thread_mem[i].region);

	Twofish_initialise();
}

static void done(void)
{
	int i;

	MEM_FREE(cracked);
	MEM_FREE(keepass_key);
	for (i = 0; i < NUM_THREADS; i++)
		free_region(&thread_mem[i].region);
	MEM_FREE(thread_mem);
}

static int allocate(uint8_t **memory, size_t size)
{
	if (THREAD_NUMBER < 0 || THREAD_NUMBER > NUM_THREADS) {
		fprintf_color(color_error, stderr, "Error: KeePass: Thread number %d out of range\n", THREAD_NUMBER);
		goto fail;
	}
	if (thread_mem[THREAD_NUMBER].used) {
		fprintf_color(color_error, stderr, "Error: KeePass: Thread %d: Memory allocated twice\n", THREAD_NUMBER);
		goto fail;
	}

	if (thread_mem[THREAD_NUMBER].region.aligned_size < size) {
		if (free_region(&thread_mem[THREAD_NUMBER].region) ||
		    !alloc_region(&thread_mem[THREAD_NUMBER].region, size))
			goto fail;
	}

	thread_mem[THREAD_NUMBER].used = 1;
	*memory = thread_mem[THREAD_NUMBER].region.aligned;

	return 0;

fail:
	*memory = NULL;
	return -1;
}

static void deallocate(uint8_t *memory, size_t size)
{
	if (THREAD_NUMBER < 0 || THREAD_NUMBER > NUM_THREADS) {
		fprintf_color(color_error, stderr, "Error: KeePass: Thread number %d out of range\n", THREAD_NUMBER);
		return;
	}

	if (!thread_mem[THREAD_NUMBER].used)
		fprintf_color(color_error, stderr, "Error: KeePass: Thread %d: Freed memory not in use\n", THREAD_NUMBER);

	if (thread_mem[THREAD_NUMBER].region.aligned_size < size)
		fprintf_color(color_error, stderr, "Error: KeePass: Thread %d: Freeing incorrect size %zu, was %zu\n",
		    THREAD_NUMBER, size, thread_mem[THREAD_NUMBER].region.aligned_size);

	thread_mem[THREAD_NUMBER].used = 0;
}

static void set_key(char *key, int index)
{
	strnzcpy(keepass_key[index], key, KEEPASS_PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return keepass_key[index];
}

static void set_salt(void *salt)
{
	cur_salt = *((keepass_salt_t**)salt);
}

// GenerateKey32 from CompositeKey.cs
static int transform_key(char *masterkey, unsigned char *final_key)
{
	SHA256_CTX ctx;
	unsigned char hash[32];
	int ret = 0;

	// First, hash the masterkey
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, masterkey, strlen(masterkey));
	SHA256_Final(hash, &ctx);

	// Add the keyfile, hash again to get the composite key
	if (cur_salt->have_keyfile) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Update(&ctx, cur_salt->keyfile, 32);
		SHA256_Final(hash, &ctx);
	} else if (cur_salt->kdbx_ver > 1) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Final(hash, &ctx);
	}

	// Next, encrypt the composite key to get the transformed key (only for AES-KDF)
	if (cur_salt->kdf == 0) {
		AES_KEY akey;
		AES_set_encrypt_key(cur_salt->transf_randomseed, 256, &akey);

		unsigned int rounds = cur_salt->t_cost;
		while (rounds--) {
			AES_encrypt(hash, hash, &akey);
			AES_encrypt(hash+16, hash+16, &akey);
		}

		// Finally, hash it again to get the master key
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Final(final_key, &ctx);

		if (cur_salt->kdbx_ver < 4) {
			// ...and hash the result together with the random seed
			SHA256_Init(&ctx);
			if (cur_salt->kdbx_ver == 1)
				SHA256_Update(&ctx, cur_salt->final_randomseed, 16);
			else
				SHA256_Update(&ctx, cur_salt->final_randomseed, 32);
			SHA256_Update(&ctx, final_key, 32);
			SHA256_Final(final_key, &ctx);
		}
	} else if (cur_salt->kdf == 1) { // Argon2
		argon2_error_codes error_code;
		argon2_context context = {
			.out = (uint8_t*)final_key,
			.outlen = 32,
			.pwd = (uint8_t*)hash,
			.pwdlen = 32,
			.salt = (uint8_t*)cur_salt->transf_randomseed,
			.saltlen = 32,
			.t_cost = cur_salt->t_cost,
			.m_cost = cur_salt->m_cost,
			.lanes = cur_salt->lanes,
			.threads = cur_salt->lanes,
			.allocate_cbk = &allocate,
			.free_cbk = &deallocate,
			.flags = ARGON2_DEFAULT_FLAGS,
			.version = ARGON2_VERSION_13
		};
		error_code = argon2_ctx(&context, cur_salt->type);
		if (error_code != ARGON2_OK) {
			ret = -1;
			fprintf_color(color_error, stderr, "Error: Keepass: Argon2 failed: %s\n",
			        argon2_error_message(error_code));
		}
	}

	return ret;
}

static void hmacBaseKey(const void *master_seed, const void *finalKey, void *result)
{
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, master_seed, 32);
	SHA512_Update(&ctx, finalKey, 32);
	SHA512_Update(&ctx, "\x01", 1);
	SHA512_Final(result, &ctx);
}

static void hmacKey(uint64_t blockIndex, const void *basekey, void *result)
{
	const void *indexBytes = &blockIndex;
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, indexBytes, sizeof(uint64_t));
	SHA512_Update(&ctx, basekey, 64);
	SHA512_Final(result, &ctx);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int failed = 0;
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

		// derive and set decryption key
		if (transform_key(keepass_key[index], final_key)) {
			failed = -1;
#ifndef _OPENMP
			break;
#endif
		}

		if (cur_salt->kdbx_ver == 4) {
			uint8_t hmac_base_key[64];
			hmacBaseKey(cur_salt->master_seed, final_key, hmac_base_key);

			uint8_t hmac_key[64];
			hmacKey(UINT64_MAX, hmac_base_key, hmac_key);

			uint8_t calc_hmac[32];
			hmac_sha256(hmac_key, 64, cur_salt->contents, cur_salt->content_size, calc_hmac, 32);

			if (!memcmp(cur_salt->header_hmac, calc_hmac, 32)) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		} else {
			unsigned char *decrypted_content;
			SHA256_CTX ctx;
			unsigned char iv[16];
			unsigned char out[32];
			int pad_byte;
			int datasize;
			AES_KEY akey;
			Twofish_key tkey;
			struct chacha_ctx ckey;

			memcpy(iv, cur_salt->enc_iv, 16);
			if (cur_salt->cipher == 0) {
				/* AES decrypt cur_salt->contents with final_key */
				AES_set_decrypt_key(final_key, 256, &akey);
			} else if (cur_salt->cipher == 1) {
				memset(&tkey, 0, sizeof(Twofish_key));
				Twofish_prepare_key(final_key, 32, &tkey);
			} else /*if (cur_salt->cipher == 2)*/ { // ChaCha20
				chacha_keysetup(&ckey, final_key, 256);
				chacha_ivsetup(&ckey, iv, NULL, 12);
			}

			if (cur_salt->kdbx_ver == 1 && cur_salt->cipher == 0) {
				if (allocate(&decrypted_content, cur_salt->content_size)) {
					failed = -1;
#ifndef _OPENMP
					break;
#endif
				}
				AES_cbc_encrypt(cur_salt->contents, decrypted_content,
				                cur_salt->content_size, &akey, iv, AES_DECRYPT);
				pad_byte = decrypted_content[cur_salt->content_size - 1];
				datasize = cur_salt->content_size - pad_byte;
				SHA256_Init(&ctx);
				SHA256_Update(&ctx, decrypted_content, datasize);
				SHA256_Final(out, &ctx);
				deallocate(decrypted_content, cur_salt->content_size);
				if (!memcmp(out, cur_salt->contents_hash, 32)) {
					cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
					any_cracked |= 1;
				}
			}
			else if (cur_salt->kdbx_ver == 2 && cur_salt->cipher == 0) {
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
			else if (cur_salt->kdbx_ver == 2 && cur_salt->cipher == 2) {
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
			else { //if (cur_salt->kdbx_ver == 1 && cur_salt->cipher == 1)
				/* KeePass 1.x with Twofish */
				int crypto_size;

				if (allocate(&decrypted_content, cur_salt->content_size)) {
					failed = -1;
#ifndef _OPENMP
					break;
#endif
				}

				crypto_size = Twofish_Decrypt(&tkey, cur_salt->contents,
				                              decrypted_content,
				                              cur_salt->content_size, iv);
				datasize = crypto_size;  // awesome, right?
				if (datasize <= cur_salt->content_size && datasize > 0) {
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
				deallocate(decrypted_content, cur_salt->content_size);
			}
		}
	}
	if (failed) {
#ifdef _OPENMP
		fprintf_color(color_error, stderr, "Error: Keepass: Argon2 or alloc_region failed in some threads\n");
#endif
		error();
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
		KEEPASS_BENCHMARK_COMMENT,
		KEEPASS_BENCHMARK_LENGTH,
		0,
		KEEPASS_PLAINTEXT_LENGTH,
		KEEPASS_BINARY_SIZE,
		KEEPASS_BINARY_ALIGN,
		KEEPASS_SALT_SIZE,
		KEEPASS_SALT_ALIGN,
		KEEPASS_MIN_KEYS_PER_CRYPT,
		KEEPASS_MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"t (rounds)",
			"m",
			"p",
			"KDF [0=Argon2d 2=Argon2id 3=AES]",
		},
		{ KEEPASS_FORMAT_TAG },
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
			keepass_cost_t,
			keepass_cost_m,
			keepass_cost_p,
			keepass_kdf,
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

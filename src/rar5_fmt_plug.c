/* RAR 5.0 cracker patch for JtR. Hacked together during May of 2013 by Dhiru
 * Kholia.
 *
 * http://www.rarlab.com/technote.htm
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the
 * following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * $rar5$<salt_len>$<salt>$<iter_log2>$<iv>$<pswcheck_len>$<pswcheck>
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rar5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rar5);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               1 // tuned on core i7
#endif

#include "arch.h"
#include "johnswap.h"
#include "stdint.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "rar5_common.h"
#define PBKDF2_HMAC_SHA256_ALSO_INCLUDE_CTX
#include "pbkdf2_hmac_sha256.h"

#include "memdbg.h"

#define FORMAT_LABEL		"RAR5"
#define FORMAT_NAME		""
#define ALGORITHM_NAME		"PBKDF2-SHA256 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define SALT_SIZE		sizeof(struct custom_salt)
#ifdef MMX_COEF_SHA256
#define MIN_KEYS_PER_CRYPT	MMX_COEF_SHA256
#define MAX_KEYS_PER_CRYPT	MMX_COEF_SHA256
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void hmac_sha256(unsigned char * pass, int passlen, unsigned char * salt,
                        int saltlen, int add, unsigned char * ret,
                        SHA256_CTX saved_ctx[2])
{
	uint8_t i, ipad[64], opad[64];
	SHA256_CTX ctx;

	if (!add) {
		memset(ipad, 0x36, 64);
		memset(opad, 0x5c, 64);

		for (i = 0; i < passlen; i++) {
			ipad[i] ^= pass[i];
			opad[i] ^= pass[i];
		}

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, ipad, 64);
		memcpy(&saved_ctx[0], &ctx, sizeof(SHA256_CTX));
	} else
		memcpy(&ctx, &saved_ctx[0], sizeof(SHA256_CTX));

	SHA256_Update(&ctx, salt, saltlen);
	SHA256_Final(ret, &ctx);

	if (!add) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, opad, 64);
		memcpy(&saved_ctx[1], &ctx, sizeof(SHA256_CTX));
	} else
		memcpy(&ctx, &saved_ctx[1], sizeof(SHA256_CTX));

	SHA256_Update(&ctx, ret, 32);
	SHA256_Final(ret, &ctx);
}

#if old_rar_kdf
// PBKDF2 for 32 unsigned char key length. We generate the key for specified
// number of iteration count also as two supplementary values (key for
// checksums and password verification) for iterations+16 and iterations+32.
static void rar5kdf(unsigned char *Pwd, size_t PwdLength,
            unsigned char *Salt, size_t SaltLength,
            unsigned char *Key, unsigned char *V1, unsigned char *V2, int Count)
{
	unsigned char SaltData[MaxSalt+4];
	unsigned char U1[SHA256_DIGEST_SIZE];
	unsigned char U2[SHA256_DIGEST_SIZE];
	int I;
	int J;
	int K;
	int CurCount[] = { Count-1, 16, 16 };
	unsigned char *CurValue[] = { Key    , V1, V2 };
	unsigned char Fn[SHA256_DIGEST_SIZE]; // Current function value.
	SHA256_CTX saved_ctx[2];

	memcpy(SaltData, Salt, Min(SaltLength,MaxSalt));

	SaltData[SaltLength + 0] = 0; // Salt concatenated to 1.
	SaltData[SaltLength + 1] = 0;
	SaltData[SaltLength + 2] = 0;
	SaltData[SaltLength + 3] = 1;

	// First iteration: HMAC of password, salt and block index (1).
	hmac_sha256(Pwd, PwdLength, SaltData, SaltLength + 4, 0, U1, saved_ctx);
	memcpy(Fn, U1, sizeof(Fn)); // Function at first iteration.

	for (I = 0; I < 3; I++) // For output key and 2 supplementary values.
	{
		for (J = 0; J < CurCount[I]; J++) {
			hmac_sha256(Pwd, PwdLength, U1, sizeof(U1), 1, U2,
			            saved_ctx); // U2 = PRF (P, U1).
			memcpy(U1, U2, sizeof(U1));
			for (K = 0; K < sizeof(Fn); K++) // Function ^= U.
				Fn[K] ^= U1[K];
		}
		memcpy(CurValue[I], Fn, SHA256_DIGEST_SIZE);
	}
}

#else
static void rar5kdf(unsigned char *Pwd, size_t PwdLength,
            unsigned char *Salt, size_t SaltLength,
            unsigned char *Key, unsigned char *V1, unsigned char *V2, int Count)
{
	int K, i;
	unsigned char SaltData[MaxSalt+4];
	unsigned char tmp_hash[SHA256_DIGEST_LENGTH];
	unsigned char U1[SHA256_DIGEST_SIZE];
	unsigned char U2[SHA256_DIGEST_SIZE];
	unsigned char Fn[SHA256_DIGEST_SIZE];
	SHA256_CTX saved_ctx[2];

	pbkdf2_sha256_owned_tmp(Pwd, PwdLength, Salt, SaltLength, Count, Key, SHA256_DIGEST_SIZE, 0, tmp_hash);

	//since we did not build our own hmac, we have to 'seed' the ctx's properly.
	memcpy(SaltData, Salt, Min(SaltLength,MaxSalt));
	SaltData[SaltLength+0] = 0; SaltData[SaltLength+1] = 0; SaltData[SaltLength+2] = 0; SaltData[SaltLength+3] = 1;
	// First iteration: HMAC of password, salt and block index (1). We only want the saved_ctx set, we discard the output.
	hmac_sha256(Pwd, PwdLength, SaltData, SaltLength + 4, 0, U1, saved_ctx);

	// this is the internal value from the pbkdf2 loop.  We need to put that into OUR temp value, and use it.
	// Our ctx's are ready, our starting hash (temp val) is ready, now we can do the last 32 loops.
	memcpy(U1, tmp_hash, SHA256_DIGEST_SIZE);
	memcpy(Fn, Key, SHA256_DIGEST_SIZE);
	for (i = 0; i < 16; ++i) {
		hmac_sha256(Pwd, PwdLength, U1, SHA256_DIGEST_SIZE, 1, U2, saved_ctx);
		memcpy(U1, U2, SHA256_DIGEST_SIZE);
		for (K = 0; K <SHA256_DIGEST_SIZE; K++)
			Fn[K] ^= U2[K];
	}
	memcpy(V1, Fn, SHA256_DIGEST_SIZE);
	for (i = 0; i < 16; ++i) {
		hmac_sha256(Pwd, PwdLength, U1, SHA256_DIGEST_SIZE, 1, U2, saved_ctx);
		memcpy(U1, U2, SHA256_DIGEST_SIZE);
		for (K = 0; K <SHA256_DIGEST_SIZE; K++)
			Fn[K] ^= U2[K];
	}
	memcpy(V2, Fn, SHA256_DIGEST_SIZE);
}

void rar5_junk_function() {
	pbkdf2_sha256(0,0,0,0,0,0,0,0);  // this is never called. Just here to quiet a 'unused' warning.
	pbkdf2_sha256_sse(0,0,0,0,0,0,0,0); // this 'will' be used later. Right now, we are just doing the oSSL code to get it working.
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		unsigned char Key[32],PswCheckValue[SHA256_DIGEST_SIZE],HashKeyValue[SHA256_DIGEST_SIZE];
		char *password = saved_key[index];
		unsigned char PswCheck[SIZE_PSWCHECK];
		int i;
		rar5kdf((unsigned char*)password, strlen(password),
				cur_salt->salt, SIZE_SALT50,
				Key, HashKeyValue, PswCheckValue,
				cur_salt->iterations);
		// special wtf processing
		memset(PswCheck, 0, sizeof(PswCheck));
		for (i = 0; i < SHA256_DIGEST_SIZE; i++)
			PswCheck[i % SIZE_PSWCHECK] ^= PswCheckValue[i];

		memcpy((void*)crypt_out[index], PswCheck, SIZE_PSWCHECK);
	}
	return count;
}

static void rar5_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return my_salt->iterations;
}
#endif

struct fmt_main fmt_rar5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
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
		set_salt,
		rar5_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

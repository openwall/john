/*
 * This file is part of John the Ripper password cracker. Written to crack
 * QNX shadow hash passwords.  algorithm is func(salt . pass x rounds+1)
 * func is md5, sha256 or sha512. rounds defaults to 1000, BUT can be specified
 * in the hash string and thus is not fixed.
 *
 * This  software is Copyright (c) 2015 JimF, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_qnx;
#elif FMT_REGISTERS_H
john_register_one(&fmt_qnx);
#else

#include "arch.h"

#define _GNU_SOURCE 1
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#undef SIMD_COEF_32
#define FORCE_GENERIC_SHA2 1
#include "sha2.h"
#include "md5.h"

#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "simd-intrinsics.h"
#include "misc.h"

// NOTE, in SSE mode, even if NOT in OMP, we may need to scale, quite a bit, due to needing
// to 'group' passwords based upon length of password.
#ifdef SIMD_COEF_32
#ifdef _OPENMP
#define SIMD_COEF_SCALE     (128/SIMD_COEF_32)
#else
#define SIMD_COEF_SCALE     (256/SIMD_COEF_32)
#endif
#else
#define SIMD_COEF_SCALE     1
#endif

#define FORMAT_LABEL		"qnx"

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#endif

#define PLAINTEXT_LENGTH	48

#define SALT_SIZE		sizeof(struct qnx_saltstruct)

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT		(SIMD_COEF_32*SIMD_PARA_SHA256)
#define MAX_KEYS_PER_CRYPT		(8 * SIMD_COEF_32*SIMD_PARA_SHA256)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		8
#endif

#ifndef OMP_SCALE
#define OMP_SCALE				128
#endif

#define __QNX_CREATE_PROPER_TESTS_ARRAY__
#include "qnx_common.h"

static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

#ifdef SIMD_COEF_32
static int *(sk_by_len[PLAINTEXT_LENGTH+1]);
static int sk_by_lens[PLAINTEXT_LENGTH+1];
#endif

static struct qnx_saltstruct {
	unsigned int len;
	unsigned int type; // 5 for md5, 256 for sha256, 512 for sha512
	unsigned int rounds;
	unsigned char salt[SALT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
	int sc_threads = 1;
	int max_crypts;

	sc_threads = omp_autotune(self, OMP_SCALE);

	max_crypts = SIMD_COEF_SCALE * sc_threads * MAX_KEYS_PER_CRYPT;
	self->params.max_keys_per_crypt = max_crypts;
	// we allocate 1 more than needed, and use that 'extra' value as a zero
	// length PW to fill in the tail groups in MMX mode.
	saved_len = mem_calloc(1 + max_crypts, sizeof(*saved_len));
	saved_key = mem_calloc(1 + max_crypts, sizeof(*saved_key));
	crypt_out = mem_calloc(1 + max_crypts, sizeof(*crypt_out));
#ifdef SIMD_COEF_32
	for (sc_threads = 1; sc_threads <= PLAINTEXT_LENGTH; ++sc_threads)
		sk_by_len[sc_threads] = mem_calloc(1+max_crypts, sizeof(int));
#endif
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static void clear_keys(void) {
#ifdef SIMD_COEF_32
	memset(sk_by_lens, 0, sizeof(sk_by_lens));
#endif
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
#ifdef SIMD_COEF_32
	sk_by_len[len][sk_by_lens[len]++] = index;
#endif
}

static char *get_key(int index)
{
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
	int tot_todo = count, inc = 1, *MixOrder = NULL;
#ifdef SIMD_COEF_32
	int usesse = 0;
	if (cur_salt->type == 5) {
		usesse = 1;
	}
#ifdef SIMD_PARA_SHA256
	if (cur_salt->type == 256) {
		usesse = 1;
	}
#endif
#ifdef SIMD_PARA_SHA512
	if (cur_salt->type == 512)
		usesse = 1;
#endif
	if (usesse) {
		int j, k;
		MixOrder = (int*)mem_calloc((count+PLAINTEXT_LENGTH*MIN_KEYS_PER_CRYPT), sizeof(int));
		tot_todo = 0;
		saved_len[count] = 0; // point all 'tail' MMX buffer elements to this location.
		for (j = 1; j < PLAINTEXT_LENGTH; ++j) {
			for (k = 0; k < sk_by_lens[j]; ++k)
				MixOrder[tot_todo++] = sk_by_len[k];
			while (tot_todo % MIN_KEYS_PER_CRYPT)
				MixOrder[tot_todo++] = count;
		}
	}
#endif

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < tot_todo; index += inc) {
#ifdef SIMD_COEF_32
		if (!MixOrder)
#endif
		{
			int i, len = saved_len[index];
			char *pass = saved_key[index];

			switch (cur_salt->type) {
			case 5:
			{
				MD5_CTX ctx;

				MD5_Init(&ctx);
				MD5_Update(&ctx, cur_salt->salt, cur_salt->len);
				for (i = 0; i <= cur_salt->rounds; ++i)
					MD5_Update(&ctx, pass, len);
				MD5_Final((unsigned char*)(crypt_out[index]), &ctx);
				break;
			}

			case 256:
			{
				SHA256_CTX ctx;

				SHA256_Init(&ctx);
				SHA256_Update(&ctx, cur_salt->salt, cur_salt->len);
				for (i = 0; i <= cur_salt->rounds; ++i)
					SHA256_Update(&ctx, pass, len);
				SHA256_Final((unsigned char*)(crypt_out[index]), &ctx);
				break;
			}

			case 512:
			{
				SHA512_CTX ctx;

				SHA512_Init(&ctx);
				SHA512_Update(&ctx, cur_salt->salt, cur_salt->len);
				if (len && 128 % len == 0 && cur_salt->len+len*cur_salt->rounds > 256) {
					// we can optimize this, by filling buffer (after the
					// first salted buffer), and then simply calling
					// jtr_sha512_hash_block 'natively' never having to
					// refill the buffer again.
					int ex;
					for (i = 0; i <= cur_salt->rounds; ++i) {
						SHA512_Update(&ctx, pass, len);
						if (ctx.total > 128+cur_salt->len)
							break;
					}
					++i;
					ex = (256-ctx.total)/len;
					i += ex;
					ctx.total += ex*len;
					jtr_sha512_hash_block(&ctx, ctx.buffer, 1);
					while (i+128/len <= cur_salt->rounds) {
						ctx.total += 128;
						jtr_sha512_hash_block(&ctx, ctx.buffer, 1);
						i += 128/len;
					}
					for (;i <= cur_salt->rounds; ++i)
						ctx.total += len;
				} else {
					for (i = 0; i <= cur_salt->rounds; ++i)
						SHA512_Update(&ctx, pass, len);
				}
				ctx.bIsQnxBuggy = 1;
				SHA512_Final((unsigned char*)(crypt_out[index]), &ctx);
				break;
			}

			}
		}
	}
	MEM_FREE(MixOrder);
	return count;
}

static void set_salt(void *salt)
{
	cur_salt = salt;
}

static void *get_salt(char *ciphertext)
{
	static struct qnx_saltstruct out;
	char *origptr = xstrdup(ciphertext), *ct = origptr;

	memset(&out, 0, sizeof(out));
	ct = strtokm(&ct[1], "@");
	if (*ct == 'm') out.type = 5;
	else if (*ct == 's') out.type = 256;
	else if (*ct == 'S') out.type = 512;

	if (ct[1] == ',')
		out.rounds = atoi(&ct[2]);
	else
		out.rounds = ROUNDS_DEFAULT;

	ct = strtokm(NULL, "@");
	ct = strtokm(NULL, "@");
	out.len = strlen(ct);
	memcpy(out.salt, ct, out.len);
	MEM_FREE(origptr);
	return &out;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (cur_salt->type == 5)
		return !memcmp(binary, crypt_out[index], BINARY_SIZE_MD5);
	if (cur_salt->type == 256)
		return !memcmp(binary, crypt_out[index], BINARY_SIZE_SHA256);
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static unsigned int iteration_count(void *salt)
{
	return ((struct qnx_saltstruct *)salt)->rounds;
}

static unsigned int algorithm_type(void *salt)
{
	return ((struct qnx_saltstruct *)salt)->type;
}

// Public domain hash function by DJ Bernstein
// We are hashing the entire struct
static int salt_hash(void *salt)
{
	unsigned char *s = (unsigned char *)salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < sizeof(struct qnx_saltstruct); i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_qnx = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		"QNX " ALGORITHM_NAME,
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
			"algorithm [5:MD5 256:SHA256 512:SHA512]",
		},
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			iteration_count,
			algorithm_type,
		},
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
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		clear_keys,
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

#endif /* plugin stanza */

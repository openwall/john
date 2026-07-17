/*
 * age (https://age-encryption.org/) passphrase format for JtR.
 *
 * Hash format:
 *   $age$*1*<logN>*<salt_hex>*<wrapped_key_hex>
 *
 * Uses scrypt and ChaCha20-Poly1305 as defined by the age file format.
 *
 * Copyright (c) 2026 trebla
 * This software is hereby released to the general public under the following
 * terms: Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_age;
#elif FMT_REGISTERS_H
john_register_one(&fmt_age);
#else

#include <string.h>
#include <stdint.h>
#include <errno.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "yescrypt/yescrypt.h"
#include "poly1305-donna/poly1305-donna.h"

#define FORMAT_LABEL        "age"
#define FORMAT_NAME         "age scrypt / ChaCha20-Poly1305"
#define FORMAT_TAG          "$age$*1*"
#define TAG_LENGTH          (sizeof(FORMAT_TAG) - 1)
#if !defined(JOHN_NO_SIMD) && defined(__XOP__)
#define ALGORITHM_NAME      "scrypt XOP"
#elif !defined(JOHN_NO_SIMD) && defined(__AVX512VL__)
#define ALGORITHM_NAME      "scrypt AVX512VL"
#elif !defined(JOHN_NO_SIMD) && defined(__AVX__)
#define ALGORITHM_NAME      "scrypt AVX"
#elif !defined(JOHN_NO_SIMD) && defined(__SSE2__)
#define ALGORITHM_NAME      "scrypt SSE2"
#else
#define ALGORITHM_NAME      "scrypt 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT   " (logN 18, r 8, p 1)"
#define BENCHMARK_LENGTH    0x107
#define PLAINTEXT_LENGTH    MAX_PLAINTEXT_LENGTH
#define BINARY_SIZE         16 /* 16-byte Poly1305 tag */
#define SALT_SIZE           sizeof(struct custom_salt)
#define BINARY_ALIGN        sizeof(ARCH_WORD)
#define SALT_ALIGN          4
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1
#define OMP_SCALE           1

/* "age-encryption.org/v1/scrypt" prepended to the raw salt for scrypt */
#define SCRYPT_LABEL        "age-encryption.org/v1/scrypt"
#define SALT_RAW_LEN        16

/* Test vector: echo "Hello, World!" | age -p  (password: iloveyou) */
static struct fmt_tests age_tests[] = {
	{ "$age$*1*18*b6472554bf10cde54aed18a7a3408ac8*384d2dc0de092a7ea35cf6dbed2f671c2feac6b6f085dc365b450765070676b1",
	  "iloveyou" },
	/* Synthetic test vector (logN=10, r=8, p=1): "John is so Wonderful!", password: password123 */
	{ "$age$*1*18*b5d7cf93eba9a33aa876abb316a1cc76*c81984b0bd4d2fb914d0ed7911a1111f45b93dbf3453c0d15c924de6acbd370c",
	  "password123" },
	{ NULL }
};

static struct custom_salt {
	uint32_t logN;
	uint8_t salt[SALT_RAW_LEN]; /* raw 16-byte salt from stanza */
	uint8_t ct[16];             /* first 16 bytes of wrapped key (ciphertext) */
} *cur_salt;

static int max_threads;
static yescrypt_local_t *local;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

/* ---------- ChaCha20 block function (RFC 8439) -------------------------- */

#define CC20_ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CC20_QR(a, b, c, d) \
    (a) += (b); (d) ^= (a); (d) = CC20_ROTL32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = CC20_ROTL32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = CC20_ROTL32((d),  8); \
    (c) += (d); (b) ^= (c); (b) = CC20_ROTL32((b),  7);

/* ChaCha20 block function, RFC 8439 layout, zero nonce */
static void chacha20_block(const uint8_t key[32], uint32_t counter, uint8_t out[64])
{
	static const uint32_t SIGMA[4] = { 0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u };
	uint32_t s[16], w[16];
	int i;

	s[0] = SIGMA[0];
	s[1] = SIGMA[1];
	s[2] = SIGMA[2];
	s[3] = SIGMA[3];
	for (i = 0; i < 8; i++)
		s[4 + i] = ((uint32_t)key[i * 4 + 0]) | ((uint32_t)key[i * 4 + 1] << 8) |
		           ((uint32_t)key[i * 4 + 2] << 16) | ((uint32_t)key[i * 4 + 3] << 24);
	s[12] = counter;
	s[13] = 0;
	s[14] = 0;
	s[15] = 0; /* 96-bit zero nonce */

	memcpy(w, s, 64);
	for (i = 0; i < 10; i++) {
		/* column rounds */
		CC20_QR(w[0], w[4], w[8], w[12]);
		CC20_QR(w[1], w[5], w[9], w[13]);
		CC20_QR(w[2], w[6], w[10], w[14]);
		CC20_QR(w[3], w[7], w[11], w[15]);
		/* diagonal rounds */
		CC20_QR(w[0], w[5], w[10], w[15]);
		CC20_QR(w[1], w[6], w[11], w[12]);
		CC20_QR(w[2], w[7], w[8], w[13]);
		CC20_QR(w[3], w[4], w[9], w[14]);
	}
	for (i = 0; i < 16; i++) {
		uint32_t v     = w[i] + s[i];
		out[i * 4 + 0] = (uint8_t)(v);
		out[i * 4 + 1] = (uint8_t)(v >> 8);
		out[i * 4 + 2] = (uint8_t)(v >> 16);
		out[i * 4 + 3] = (uint8_t)(v >> 24);
	}
}

/* ChaCha20-Poly1305 AEAD tag with zero nonce and no AAD, 16-byte ciphertext.
 * Poly1305 input: ct[16] || u64le(0) || u64le(16) */
static void age_poly1305_tag(const uint8_t wrapping_key[32], const uint8_t ct[16], uint8_t tag[16])
{
	uint8_t block0[64];
	uint8_t poly_msg[32];

	/* Poly1305 one-time key = first 32 bytes of ChaCha20 block 0 */
	chacha20_block(wrapping_key, 0, block0);

	/* Build Poly1305 input message */
	memcpy(poly_msg, ct, 16); /* ciphertext */
	/* AAD length (64-bit LE) = 0 */
	memset(poly_msg + 16, 0, 8);
	/* CT length (64-bit LE) = 16 = 0x10 */
	poly_msg[24] = 0x10;
	memset(poly_msg + 25, 0, 7);

	poly1305_auth(tag, poly_msg, sizeof(poly_msg), block0);
}

/* ---------- JtR format callbacks --------------------------------------- */

static void init(struct fmt_main *self)
{
	int i;

	omp_autotune(self, OMP_SCALE);

#ifdef _OPENMP
	max_threads = omp_get_max_threads();
#else
	max_threads = 1;
#endif
	local = mem_alloc(sizeof(*local) * max_threads);
	for (i = 0; i < max_threads; i++)
		yescrypt_init_local(&local[i]);

	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));
}

static void done(void)
{
	int i;

	for (i = 0; i < max_threads; i++)
		yescrypt_free_local(&local[i]);
	MEM_FREE(local);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

/*
 * Validate: $age$*1*<logN>*<32 hex>*<64 hex>
 */
static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;

	if (((p = strtokm(ctcopy, "*")) == NULL) || !isdec(p)) /* logN */
		goto err;
	if (((p = strtokm(NULL, "*")) == NULL) || hexlenl(p, &extra) != 32 || extra) /* salt */
		goto err;
	if (((p = strtokm(NULL, "*")) == NULL) || hexlenl(p, &extra) != 64 || extra) /* wrapped key */
		goto err;

	MEM_FREE(keeptr);
	return 1;
err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy           = xstrdup(ciphertext);
	char *keeptr           = ctcopy;
	char *p;
	int i;

	ctcopy += TAG_LENGTH;

	p        = strtokm(ctcopy, "*");
	cs.logN = (uint32_t)atoi(p);

	p = strtokm(NULL, "*");
	for (i = 0; i < SALT_RAW_LEN; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[i * 2])] << 4) | atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.ct[i] = (atoi16[ARCH_INDEX(p[i * 2])] << 4) | atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		uint8_t c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	/* last field: ct[16] || tag[16]; skip ct to get the Poly1305 tag */
	char *p = strrchr(ciphertext, '*') + 1 + 32;
	int i;

	for (i = 0; i < BINARY_SIZE; i++) {
		buf.c[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return buf.c;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;
	int failed               = 0;
	yescrypt_params_t params = { .N = 1ULL << cur_salt->logN, .r = 8, .p = 1 };
	/* Full salt = label || raw_salt */
	uint8_t full_salt[sizeof(SCRYPT_LABEL) - 1 + SALT_RAW_LEN];
	memcpy(full_salt, SCRYPT_LABEL, sizeof(SCRYPT_LABEL) - 1);
	memcpy(full_salt + sizeof(SCRYPT_LABEL) - 1, cur_salt->salt, SALT_RAW_LEN);

#ifdef _OPENMP
#pragma omp parallel for default(none) private(index) \
	shared(count, failed, params, full_salt, max_threads, local, saved_key, cur_salt, crypt_out)
#endif
	for (index = 0; index < count; index++) {
#ifdef _OPENMP
		int t = omp_get_thread_num();
		if (t >= max_threads) {
			failed = -1;
			continue;
		}
#else
		const int t = 0;
#endif
		uint8_t wrapping_key[32];

		if (yescrypt_kdf(NULL, &local[t], (const uint8_t *)saved_key[index], strlen(saved_key[index]),
		                 full_salt, sizeof(full_salt), &params, wrapping_key, sizeof(wrapping_key))) {
			failed = errno ? errno : EINVAL;
#ifndef _OPENMP
			break;
#endif
		}

		age_poly1305_tag(wrapping_key, cur_salt->ct, (uint8_t *)crypt_out[index]);
	}

	if (failed) {
#ifdef _OPENMP
		if (failed < 0) {
			fprintf(stderr, "OpenMP thread number out of range\n");
			error();
		}
#endif
		fprintf(stderr, "scrypt failed: %s\n", strerror(failed));
		error();
	}

	return count;
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
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void age_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int tunable_cost_N(void *salt)
{
	return (unsigned int)((struct custom_salt *)salt)->logN;
}

struct fmt_main fmt_age = {
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
			"N log2",
		},
		{ "$age$" },
		age_tests
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
			tunable_cost_N,
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
		fmt_default_salt_hash,
		NULL,
		set_salt,
		age_set_key,
		get_key,
		fmt_default_clear_keys,
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

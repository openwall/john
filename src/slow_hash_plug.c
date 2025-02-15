// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Changes from Cryptonote's (AES-NI usage and other optimizations) are
// Copyright (c) 2025 by Solar Designer
// Same license as above, or alternatively (for the changes only):
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/aesni.h"
#if MBEDTLS_AESNI_HAVE_CODE == 2
#include <immintrin.h>
#endif

#include "memory.h"
#include "int-util.h"
#include "oaes_lib.h"
#include "blake256.h"
#include "groestl.h"
#include "jh.h"
#include "keccak.h"
#include "sph_skein.h"

union hash_state {
	uint8_t b[200];
	uint64_t w[25];
};

void hash_permutation(union hash_state *state);
void hash_process(union hash_state *state, const uint8_t *buf, size_t count);

enum {
	HASH_SIZE = 32
};

void cn_slow_hash(const void *data, size_t length, char *hash);

void hash_extra_blake(const void *data, size_t length, char *hash);
void hash_extra_groestl(const void *data, size_t length, char *hash);
void hash_extra_jh(const void *data, size_t length, char *hash);
void hash_extra_skein(const void *data, size_t length, char *hash);

static void (*const extra_hashes[4])(const void *, size_t, char *) = {
	hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein
};

void hash_extra_blake(const void *data, size_t length, char *hash)
{
	blake256_hash((uint8_t*)hash, data, length);
}

void hash_extra_groestl(const void *data, size_t length, char *hash)
{
	groestl(data, length * 8, (uint8_t*)hash);
}

void hash_extra_jh(const void *data, size_t length, char *hash)
{
	jh_hash(HASH_SIZE * 8, data, 8 * length, (uint8_t*)hash);
}

void hash_extra_skein(const void *data, size_t length, char *hash)
{
	sph_skein256_context ctx;

	sph_skein256_init(&ctx);
	sph_skein256(&ctx, data, length);
	sph_skein256_close(&ctx, (unsigned char*)hash);
}

#define MEMORY         (1 << 21) /* 2 MiB */
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

typedef union {
	uint8_t b[AES_BLOCK_SIZE];
	uint64_t u64[AES_BLOCK_SIZE / 8];
#if MBEDTLS_AESNI_HAVE_CODE == 2
	__m128i v;
#endif
} block;

static inline size_t e2i(block *a, size_t count) { return (a->u64[0] / AES_BLOCK_SIZE) & (count - 1); }

static inline void mul(const block *a, const block *b, block *res) {
	uint64_t a0, b0;
	uint64_t hi, lo;

	a0 = SWAP64LE(a->u64[0]);
	b0 = SWAP64LE(b->u64[0]);
	lo = mul128(a0, b0, &hi);
	res->u64[0] = SWAP64LE(hi);
	res->u64[1] = SWAP64LE(lo);
}

static inline void sum_half_blocks(block *a, const block *b) {
#if 0 && MBEDTLS_AESNI_HAVE_CODE == 2
	a->v = _mm_add_epi64(a->v, b->v);
#else
	uint64_t a0, a1, b0, b1;

	a0 = SWAP64LE(a->u64[0]);
	a1 = SWAP64LE(a->u64[1]);
	b0 = SWAP64LE(b->u64[0]);
	b1 = SWAP64LE(b->u64[1]);
	a0 += b0;
	a1 += b1;
	a->u64[0] = SWAP64LE(a0);
	a->u64[1] = SWAP64LE(a1);
#endif
}

static inline void xor_blocks(block *a, const block *b) {
#if 1 && MBEDTLS_AESNI_HAVE_CODE == 2
	a->v = _mm_xor_si128(a->v, b->v);
#else
	a->u64[0] ^= b->u64[0];
	a->u64[1] ^= b->u64[1];
#endif
}

#pragma pack(push, 1)
union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint64_t k[8];
		uint8_t init[INIT_SIZE_BYTE];
	};
};
#pragma pack(pop)

void hash_permutation(union hash_state *state)
{
	keccakf((uint64_t*)state, 24);
}

void hash_process(union hash_state *state, const uint8_t *buf, size_t count)
{
	keccak1600(buf, count, (uint8_t*)state);
}

#if MBEDTLS_AESNI_HAVE_CODE == 2
static inline void aesni_pseudo_encrypt_ecb(OAES_CTX *ctx, block * restrict c)
{
	struct {
		size_t data_len;
		uint8_t *data;
		size_t exp_data_len;
		__m128i *exp_data;
	} *key = *(void **)ctx;
	__m128i cv = c->v;
	cv = _mm_aesenc_si128(cv, key->exp_data[0]);
	cv = _mm_aesenc_si128(cv, key->exp_data[1]);
	cv = _mm_aesenc_si128(cv, key->exp_data[2]);
	cv = _mm_aesenc_si128(cv, key->exp_data[3]);
	cv = _mm_aesenc_si128(cv, key->exp_data[4]);
	cv = _mm_aesenc_si128(cv, key->exp_data[5]);
	cv = _mm_aesenc_si128(cv, key->exp_data[6]);
	cv = _mm_aesenc_si128(cv, key->exp_data[7]);
	cv = _mm_aesenc_si128(cv, key->exp_data[8]);
	cv = _mm_aesenc_si128(cv, key->exp_data[9]);
	c->v = cv;
}
#endif

void cn_slow_hash(const void *data, size_t length, char *hash)
{
#if MBEDTLS_AESNI_HAVE_CODE == 2
	const int have_aesni = mbedtls_aesni_has_support(MBEDTLS_AESNI_AES);
#endif
	block *long_state = mem_alloc(MEMORY); // This is 2 MiB, too large for stack
	OAES_CTX *aes_ctx = oaes_alloc();
	union cn_slow_hash_state state;
	block text[INIT_SIZE_BLK];
	block a, b, c, d;
	size_t i, j;

	hash_process(&state.hs, data, length);
	memcpy(text, state.init, INIT_SIZE_BYTE);

	oaes_key_import_data(aes_ctx, state.hs.b, AES_KEY_SIZE);
#if MBEDTLS_AESNI_HAVE_CODE == 2
	if (have_aesni)
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++)
			aesni_pseudo_encrypt_ecb(aes_ctx, &text[j]);
		memcpy(&long_state[i * INIT_SIZE_BLK], text, INIT_SIZE_BYTE);
	}
	else
#endif
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++)
			oaes_pseudo_encrypt_ecb(aes_ctx, text[j].b);
		memcpy(&long_state[i * INIT_SIZE_BLK], text, INIT_SIZE_BYTE);
	}

	a.u64[0] = state.k[0] ^ state.k[4];
	a.u64[1] = state.k[1] ^ state.k[5];
	b.u64[0] = state.k[2] ^ state.k[6];
	b.u64[1] = state.k[3] ^ state.k[7];

#if MBEDTLS_AESNI_HAVE_CODE == 2
	/* Dependency chain: address -> read value ------+
	 * written value <-+ hard function (AES or MUL) <+
	 * next address  <-+
	 */
	if (have_aesni)
	for (i = 0; i < ITER / 2; i++) {
		/* Iteration 1 */
		j = e2i(&a, MEMORY / AES_BLOCK_SIZE);
		c = long_state[j];
		c.v = _mm_aesenc_si128(c.v, a.v);
		xor_blocks(&b, &c);
		long_state[j] = b;
		block e = a; a = c;
		/* Iteration 2 */
		j = e2i(&a, MEMORY / AES_BLOCK_SIZE);
		c = long_state[j];
		mul(&a, &c, &d);
		sum_half_blocks(&e, &d);
		long_state[j] = e;
		b = a;
#if 0
		a.v = _mm_xor_si128(c.v, e.v);
#else
		a.u64[0] = c.u64[0] ^ e.u64[0];
		a.u64[1] = c.u64[1] ^ e.u64[1];
#endif
	}
	else
#endif
	for (i = 0; i < ITER / 2; i++) {
		/* Iteration 1 */
		j = e2i(&a, MEMORY / AES_BLOCK_SIZE);
		c = long_state[j];
		oaes_encryption_round(a.b, c.b);
		xor_blocks(&b, &c);
		long_state[j] = b;
		/* Iteration 2 */
		j = e2i(&c, MEMORY / AES_BLOCK_SIZE);
		b = long_state[j];
		mul(&b, &c, &d);
		sum_half_blocks(&a, &d);
		long_state[j] = a;
		a.u64[0] ^= b.u64[0];
		a.u64[1] ^= b.u64[1];
		b = c;
	}

	memcpy(text, state.init, INIT_SIZE_BYTE);
	oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
#if MBEDTLS_AESNI_HAVE_CODE == 2
	if (have_aesni)
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++) {
			xor_blocks(&text[j], &long_state[i * INIT_SIZE_BLK + j]);
			aesni_pseudo_encrypt_ecb(aes_ctx, &text[j]);
		}
	}
	else
#endif
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++) {
			xor_blocks(&text[j], &long_state[i * INIT_SIZE_BLK + j]);
			oaes_pseudo_encrypt_ecb(aes_ctx, text[j].b);
		}
	}
	memcpy(state.init, text, INIT_SIZE_BYTE);
	hash_permutation(&state.hs);
	extra_hashes[state.hs.b[0] & 3](&state, 200, hash);
	oaes_free(&aes_ctx);
	MEM_FREE(long_state);
}

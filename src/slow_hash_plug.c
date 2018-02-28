// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
	HASH_SIZE = 32,
	HASH_DATA_AREA = 136
};

void cn_fast_hash(const void *data, size_t length, char *hash);
void cn_slow_hash(const void *data, size_t length, char *hash);

void hash_extra_blake(const void *data, size_t length, char *hash);
void hash_extra_groestl(const void *data, size_t length, char *hash);
void hash_extra_jh(const void *data, size_t length, char *hash);
void hash_extra_skein(const void *data, size_t length, char *hash);

void tree_hash(const char (*hashes)[HASH_SIZE], size_t count, char *root_hash);

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

static size_t e2i(const uint8_t* a, size_t count) { return (*((uint64_t*)a) / AES_BLOCK_SIZE) & (count - 1); }

static void mul(const uint8_t* a, const uint8_t* b, uint8_t* res) {
  uint64_t a0, b0;
  uint64_t hi, lo;

  a0 = SWAP64LE(((uint64_t*)a)[0]);
  b0 = SWAP64LE(((uint64_t*)b)[0]);
  lo = mul128(a0, b0, &hi);
  ((uint64_t*)res)[0] = SWAP64LE(hi);
  ((uint64_t*)res)[1] = SWAP64LE(lo);
}

static void sum_half_blocks(uint8_t* a, const uint8_t* b) {
  uint64_t a0, a1, b0, b1;

  a0 = SWAP64LE(((uint64_t*)a)[0]);
  a1 = SWAP64LE(((uint64_t*)a)[1]);
  b0 = SWAP64LE(((uint64_t*)b)[0]);
  b1 = SWAP64LE(((uint64_t*)b)[1]);
  a0 += b0;
  a1 += b1;
  ((uint64_t*)a)[0] = SWAP64LE(a0);
  ((uint64_t*)a)[1] = SWAP64LE(a1);
}

static void copy_block(uint8_t* dst, const uint8_t* src) {
  memcpy(dst, src, AES_BLOCK_SIZE);
}

static void swap_blocks(uint8_t* a, uint8_t* b) {
  size_t i;
  uint8_t t;
  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    t = a[i];
    a[i] = b[i];
    b[i] = t;
  }
}

static void xor_blocks(uint8_t* a, const uint8_t* b) {
  size_t i;
  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    a[i] ^= b[i];
  }
}

#pragma pack(push, 1)
union cn_slow_hash_state {
  union hash_state hs;
  struct {
    uint8_t k[64];
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

void cn_fast_hash(const void *data, size_t length, char *hash)
{
	union hash_state state;
	hash_process(&state, data, length);
	memcpy(hash, &state, HASH_SIZE);
}

void cn_slow_hash(const void *data, size_t length, char *hash)
{
	//uint8_t long_state[MEMORY]; // This is 2 MB, too large for stack
	uint8_t *long_state = mem_alloc(MEMORY);
	union cn_slow_hash_state state;
	uint8_t text[INIT_SIZE_BYTE];
	uint8_t a[AES_BLOCK_SIZE];
	uint8_t b[AES_BLOCK_SIZE];
	uint8_t c[AES_BLOCK_SIZE];
	uint8_t d[AES_BLOCK_SIZE];
	size_t i, j;
	uint8_t aes_key[AES_KEY_SIZE];
	OAES_CTX* aes_ctx;

	hash_process(&state.hs, data, length);
	memcpy(text, state.init, INIT_SIZE_BYTE);
	memcpy(aes_key, state.hs.b, AES_KEY_SIZE);
	aes_ctx = oaes_alloc();

	oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++)
			oaes_pseudo_encrypt_ecb(aes_ctx, &text[AES_BLOCK_SIZE * j]);

		memcpy(&long_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
	}

	for (i = 0; i < 16; i++) {
		a[i] = state.k[     i] ^ state.k[32 + i];
		b[i] = state.k[16 + i] ^ state.k[48 + i];
	}

	for (i = 0; i < ITER / 2; i++) {
		/* Dependency chain: address -> read value ------+
		 * written value <-+ hard function (AES or MUL) <+
		 * next address  <-+
		 */
		/* Iteration 1 */
		j = e2i(a, MEMORY / AES_BLOCK_SIZE);
		copy_block(c, &long_state[j * AES_BLOCK_SIZE]);
		oaes_encryption_round(a, c);
		xor_blocks(b, c);
		swap_blocks(b, c);
		copy_block(&long_state[j * AES_BLOCK_SIZE], c);
		assert(j == e2i(a, MEMORY / AES_BLOCK_SIZE));
		swap_blocks(a, b);
		/* Iteration 2 */
		j = e2i(a, MEMORY / AES_BLOCK_SIZE);
		copy_block(c, &long_state[j * AES_BLOCK_SIZE]);
		mul(a, c, d);
		sum_half_blocks(b, d);
		swap_blocks(b, c);
		xor_blocks(b, c);
		copy_block(&long_state[j * AES_BLOCK_SIZE], c);
		assert(j == e2i(a, MEMORY / AES_BLOCK_SIZE));
		swap_blocks(a, b);
	}

	memcpy(text, state.init, INIT_SIZE_BYTE);
	oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
	for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
		for (j = 0; j < INIT_SIZE_BLK; j++) {
			xor_blocks(&text[j * AES_BLOCK_SIZE], &long_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
			oaes_pseudo_encrypt_ecb(aes_ctx, &text[j * AES_BLOCK_SIZE]);
		}
	}
	memcpy(state.init, text, INIT_SIZE_BYTE);
	hash_permutation(&state.hs);
	extra_hashes[state.hs.b[0] & 3](&state, 200, hash);
	oaes_free(&aes_ctx);
	MEM_FREE(long_state);
}

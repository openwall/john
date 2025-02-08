/*
 * gost.c - an implementation of GOST Hash Function
 * based on the Russian Standard GOST R 34.11-94.
 * See also RFC 4357.
 *
 * Copyright: 2009 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * Porting to OpenCL + optimizations: Copyright (c) 2022 magnum, and those changes
 * hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef GOST94_H
#define GOST94_H

#include "opencl_misc.h"

#if GOST94_USE_LOCAL
#define MAYBE_LOCAL           __local
#else
#define MAYBE_LOCAL
#endif

#if GOST_UNROLL
#define UNROLL8  _Pragma("unroll 8")
#define UNROLL16 _Pragma("unroll 16")
#else
#define UNROLL8
#define UNROLL16
#endif

#define memcpy512(dst, src) do {	  \
		UNROLL16 \
		for (uint i = 0; i < 16; i++) \
			(dst)->DWORD[i] = (src)->DWORD[i]; \
	} while (0)

#define memcpy256(dst, src) do {	  \
		UNROLL8 \
		for (uint i = 0; i < 8; i++) \
			(dst)->DWORD[i] = (src)->DWORD[i]; \
	} while (0)

typedef union {
	uint array[4][256];
	uint flat[4 * 256];
} rhash_gost94_sbox;

#define GOST94_BLOCK_SIZE  32
#define GOST94_HASH_LENGTH 32

#if GOST94_USE_LOCAL
#define THREAD  get_local_id(0)
#define LWS     get_local_size(0)
#endif

/* algorithm context */
typedef struct {
	uint hash[8];  /* algorithm 256-bit state */
	uint sum[8];   /* sum of processed message blocks */
	uchar message[GOST94_BLOCK_SIZE]; /* 256-bit buffer for leftovers */
	uint length;   /* number of processed bytes */
} gost94_ctx;

/**
 * Initialize algorithm context before calculaing hash
 * with test parameters set.
 *
 * @param ctx context to initialize
 */
INLINE void gost94_init(gost94_ctx *ctx)
{
	memset_p(ctx, 0, sizeof(gost94_ctx));
}

/*
 *  A macro that performs a full encryption round of GOST 28147-89.
 *  Temporary variables tmp assumed and variables r and l for left and right
 *  blocks.
 */
#define GOST94_ENCRYPT_ROUND(key1, key2, sbox)	do { \
		tmp = (key1) + r; \
		l ^= (sbox->flat)[tmp & 0xff] ^ ((sbox->flat) + 256)[(tmp >> 8) & 0xff] ^ \
			((sbox->flat) + 512)[(tmp >> 16) & 0xff] ^ ((sbox->flat) + 768)[tmp >> 24]; \
		tmp = (key2) + l; \
		r ^= (sbox->flat)[tmp & 0xff] ^ ((sbox->flat) + 256)[(tmp >> 8) & 0xff] ^ \
			((sbox->flat) + 512)[(tmp >> 16) & 0xff] ^ ((sbox->flat) + 768)[tmp >> 24]; \
	} while (0)

/* encrypt a block with the given key */
#define GOST94_ENCRYPT(result, i, key, hash, sbox)	do { \
		uint l, r, tmp; \
		r = hash[i], l = hash[i + 1]; \
		GOST94_ENCRYPT_ROUND(key[0], key[1], sbox); \
		GOST94_ENCRYPT_ROUND(key[2], key[3], sbox); \
		GOST94_ENCRYPT_ROUND(key[4], key[5], sbox); \
		GOST94_ENCRYPT_ROUND(key[6], key[7], sbox); \
		GOST94_ENCRYPT_ROUND(key[0], key[1], sbox); \
		GOST94_ENCRYPT_ROUND(key[2], key[3], sbox); \
		GOST94_ENCRYPT_ROUND(key[4], key[5], sbox); \
		GOST94_ENCRYPT_ROUND(key[6], key[7], sbox); \
		GOST94_ENCRYPT_ROUND(key[0], key[1], sbox); \
		GOST94_ENCRYPT_ROUND(key[2], key[3], sbox); \
		GOST94_ENCRYPT_ROUND(key[4], key[5], sbox); \
		GOST94_ENCRYPT_ROUND(key[6], key[7], sbox); \
		GOST94_ENCRYPT_ROUND(key[7], key[6], sbox); \
		GOST94_ENCRYPT_ROUND(key[5], key[4], sbox); \
		GOST94_ENCRYPT_ROUND(key[3], key[2], sbox); \
		GOST94_ENCRYPT_ROUND(key[1], key[0], sbox); \
		result[i] = l, result[i + 1] = r; \
	} while (0)

/**
 * The core transformation. Process a 512-bit block.
 *
 * @param hash intermediate message hash
 * @param block the message block to process
 */
INLINE void rhash_gost94_block_compress(gost94_ctx *ctx, const uint* block, MAYBE_LOCAL const rhash_gost94_sbox *sbox)
{
	uint i;
	uint key[8], u[8], v[8], w[8], s[8];

	/* u := hash, v := <256-bit message block> */
	memcpy_pp(u, ctx->hash, sizeof(u));
	memcpy_pp(v, block, sizeof(v));

	/* w := u xor v */
	w[0] = u[0] ^ v[0], w[1] = u[1] ^ v[1];
	w[2] = u[2] ^ v[2], w[3] = u[3] ^ v[3];
	w[4] = u[4] ^ v[4], w[5] = u[5] ^ v[5];
	w[6] = u[6] ^ v[6], w[7] = u[7] ^ v[7];

	/* calculate keys, encrypt hash and store result to the s[] array */
	for (i = 0;; i += 2) {
		/* key generation: key_i := P(w) */
		key[0] = (w[0] & 0x000000ff) | ((w[2] & 0x000000ff) << 8) | ((w[4] & 0x000000ff) << 16) | ((w[6] & 0x000000ff) << 24);
		key[1] = ((w[0] & 0x0000ff00) >> 8) | (w[2] & 0x0000ff00) | ((w[4] & 0x0000ff00) << 8)  | ((w[6] & 0x0000ff00) << 16);
		key[2] = ((w[0] & 0x00ff0000) >> 16) | ((w[2] & 0x00ff0000) >> 8) | (w[4] & 0x00ff0000) | ((w[6] & 0x00ff0000) << 8);
		key[3] = ((w[0] & 0xff000000) >> 24) | ((w[2] & 0xff000000) >> 16) | ((w[4] & 0xff000000) >> 8) | (w[6] & 0xff000000);
		key[4] = (w[1] & 0x000000ff) | ((w[3] & 0x000000ff) << 8) | ((w[5] & 0x000000ff) << 16) | ((w[7] & 0x000000ff) << 24);
		key[5] = ((w[1] & 0x0000ff00) >> 8) | (w[3] & 0x0000ff00) | ((w[5] & 0x0000ff00) << 8)  | ((w[7] & 0x0000ff00) << 16);
		key[6] = ((w[1] & 0x00ff0000) >> 16) | ((w[3] & 0x00ff0000) >> 8) | (w[5] & 0x00ff0000) | ((w[7] & 0x00ff0000) << 8);
		key[7] = ((w[1] & 0xff000000) >> 24) | ((w[3] & 0xff000000) >> 16) | ((w[5] & 0xff000000) >> 8) | (w[7] & 0xff000000);

		/* encryption: s_i := E_{key_i} (h_i) */
		GOST94_ENCRYPT(s, i, key, ctx->hash, sbox);

		if (i == 0) {
			/* w:= A(u) ^ A^2(v) */
			w[0] = u[2] ^ v[4], w[1] = u[3] ^ v[5];
			w[2] = u[4] ^ v[6], w[3] = u[5] ^ v[7];
			w[4] = u[6] ^ (v[0] ^= v[2]);
			w[5] = u[7] ^ (v[1] ^= v[3]);
			w[6] = (u[0] ^= u[2]) ^ (v[2] ^= v[4]);
			w[7] = (u[1] ^= u[3]) ^ (v[3] ^= v[5]);
		} else if ((i & 2) != 0) {
			if (i == 6) break;

			/* w := A^2(u) xor A^4(v) xor C_3; u := A(u) xor C_3 */
			/* C_3=0xff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00 */
			u[2] ^= u[4] ^ 0x000000ff;
			u[3] ^= u[5] ^ 0xff00ffff;
			u[4] ^= 0xff00ff00;
			u[5] ^= 0xff00ff00;
			u[6] ^= 0x00ff00ff;
			u[7] ^= 0x00ff00ff;
			u[0] ^= 0x00ffff00;
			u[1] ^= 0xff0000ff;

			w[0] = u[4] ^ v[0];
			w[2] = u[6] ^ v[2];
			w[4] = u[0] ^ (v[4] ^= v[6]);
			w[6] = u[2] ^ (v[6] ^= v[0]);
			w[1] = u[5] ^ v[1];
			w[3] = u[7] ^ v[3];
			w[5] = u[1] ^ (v[5] ^= v[7]);
			w[7] = u[3] ^ (v[7] ^= v[1]);
		} else {
			/* i==4 here */
			/* w:= A( A^2(u) xor C_3 ) xor A^6(v) */
			w[0] = u[6] ^ v[4], w[1] = u[7] ^ v[5];
			w[2] = u[0] ^ v[6], w[3] = u[1] ^ v[7];
			w[4] = u[2] ^ (v[0] ^= v[2]);
			w[5] = u[3] ^ (v[1] ^= v[3]);
			w[6] = (u[4] ^= u[6]) ^ (v[2] ^= v[4]);
			w[7] = (u[5] ^= u[7]) ^ (v[3] ^= v[5]);
		}
	}

	/* step hash function: x(block, hash) := psi^61(hash xor psi(block xor psi^12(S))) */

	/* 12 rounds of the LFSR and xor in <message block> */
	u[0] = block[0] ^ s[6];
	u[1] = block[1] ^ s[7];
	u[2] = block[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff) ^ (s[1] & 0xffff) ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[7] & 0xffff0000) ^ (s[7] >> 16);
	u[3] = block[3] ^ (s[0] & 0xffff) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^ (s[1] << 16) ^ (s[1] >> 16) ^
		(s[2] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
	u[4] = block[4] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[0] >> 16) ^
		(s[1] & 0xffff0000) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
	u[5] = block[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff0000) ^
		(s[1] & 0xffff) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff0000) ^ (s[7] << 16) ^ (s[7] >> 16);
	u[6] = block[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[3] ^ (s[3] >> 16)
		^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] << 16);
	u[7] = block[7] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^
		(s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[4] ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);

	/* 1 round of the LFSR (a mixing transformation) and xor with <hash> */
	v[0] = ctx->hash[0] ^ (u[1] << 16) ^ (u[0] >> 16);
	v[1] = ctx->hash[1] ^ (u[2] << 16) ^ (u[1] >> 16);
	v[2] = ctx->hash[2] ^ (u[3] << 16) ^ (u[2] >> 16);
	v[3] = ctx->hash[3] ^ (u[4] << 16) ^ (u[3] >> 16);
	v[4] = ctx->hash[4] ^ (u[5] << 16) ^ (u[4] >> 16);
	v[5] = ctx->hash[5] ^ (u[6] << 16) ^ (u[5] >> 16);
	v[6] = ctx->hash[6] ^ (u[7] << 16) ^ (u[6] >> 16);
	v[7] = ctx->hash[7] ^ (u[0] & 0xffff0000) ^ (u[0] << 16) ^ (u[1] & 0xffff0000) ^ (u[1] << 16) ^ (u[6] << 16) ^ (u[7] & 0xffff0000) ^ (u[7] >> 16);

	/* 61 rounds of LFSR, mixing up hash */
	ctx->hash[0] = (v[0] & 0xffff0000) ^ (v[0] << 16) ^ (v[0] >> 16) ^
		(v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^
		(v[3] >> 16) ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[5] ^
		(v[6] >> 16) ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff);
	ctx->hash[1] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^
		(v[1] & 0xffff) ^ v[2] ^ (v[2] >> 16) ^ (v[3] << 16) ^
		(v[4] >> 16) ^ (v[5] << 16) ^ (v[6] << 16) ^ v[6] ^
		(v[7] & 0xffff0000) ^ (v[7] >> 16);
	ctx->hash[2] = (v[0] & 0xffff) ^ (v[0] << 16) ^ (v[1] << 16) ^
		(v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^
		v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[6] ^ (v[6] >> 16) ^
		(v[7] & 0xffff) ^ (v[7] << 16) ^ (v[7] >> 16);
	ctx->hash[3] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^
		(v[1] & 0xffff0000) ^ (v[1] >> 16) ^ (v[2] << 16) ^
		(v[2] >> 16) ^ v[2] ^ (v[3] << 16) ^ (v[4] >> 16) ^ v[4] ^
		(v[5] << 16) ^ (v[6] << 16) ^ (v[7] & 0xffff) ^ (v[7] >> 16);
	ctx->hash[4] = (v[0] >> 16) ^ (v[1] << 16) ^ v[1] ^ (v[2] >> 16) ^ v[2] ^
		(v[3] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^
		(v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16);
	ctx->hash[5] = (v[0] << 16) ^ (v[0] & 0xffff0000) ^ (v[1] << 16) ^
		(v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^ v[2] ^
		(v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[4] >> 16) ^ v[4] ^
		(v[5] << 16) ^ (v[6] << 16) ^ (v[6] >> 16) ^ v[6] ^
		(v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff0000);
	ctx->hash[6] = v[0] ^ v[2] ^ (v[2] >> 16) ^ v[3] ^ (v[3] << 16) ^ v[4] ^
		(v[4] >> 16) ^ (v[5] << 16) ^ (v[5] >> 16) ^ v[5] ^
		(v[6] << 16) ^ (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ v[7];
	ctx->hash[7] = v[0] ^ (v[0] >> 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^
		(v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ v[4] ^
		(v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16) ^ v[7];
}

/**
 * This function calculates hash value by 256-bit blocks.
 * It updates 256-bit check sum as follows:
 *    *(uint256_t)(ctx->sum) += *(uint256_t*)block;
 * and then updates intermediate hash value ctx->hash
 * by calling rhash_gost94_block_compress().
 *
 * @param ctx algorithm context
 * @param block the 256-bit message block to process
 */
INLINE void rhash_gost94_compute_sum_and_hash(gost94_ctx * ctx, const uint* block, MAYBE_LOCAL const rhash_gost94_sbox *sbox)
{
#if !__ENDIAN_LITTLE__
	uint block_le[8]; /* tmp buffer for little endian number */
#define LOAD_BLOCK_LE(i) (block_le[i] = SWAP32(block[i]))
#else
#define block_le block
#define LOAD_BLOCK_LE(i)
#endif

	uint i, carry = 0;

	/* compute the 256-bit sum */
	for (i = 0; i < 8; i++) {
		const uint old = ctx->sum[i];
		LOAD_BLOCK_LE(i);
		ctx->sum[i] += block_le[i] + carry;
		carry = (ctx->sum[i] < old || ctx->sum[i] < block_le[i] ? 1 : 0);
	}

	/* update message hash */
	rhash_gost94_block_compress(ctx, block_le, sbox);
}

#define IS_ALIGNED_32(p) (!(((const char*)(p) - (const char*)0) & 3))

/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param size length of the message chunk
 */
static NOINLINE void gost94_update(gost94_ctx *ctx, const uchar* msg, uint size, MAYBE_LOCAL const rhash_gost94_sbox *sbox)
{
	uint index = ctx->length & 31;
	ctx->length += size;

	/* fill partial block */
	if (index) {
		uint left = GOST94_BLOCK_SIZE - index;
		memcpy_pp(ctx->message + index, msg, (size < left ? size : left));
		if (size < left)
			return;

		/* process partial block */
		rhash_gost94_compute_sum_and_hash(ctx, (uint*)ctx->message, sbox);
		msg += left;
		size -= left;
	}
	while(size >= GOST94_BLOCK_SIZE) {
		uint* aligned_message_block;
		if (IS_ALIGNED_32(msg)) {
			/* the most common case is processing of an already aligned message
			on little-endian CPU without copying it */
			aligned_message_block = (uint*)msg;
		} else {
			memcpy_pp(ctx->message, msg, GOST94_BLOCK_SIZE);
			aligned_message_block = (uint*)ctx->message;
		}

		rhash_gost94_compute_sum_and_hash(ctx, aligned_message_block, sbox);
		msg += GOST94_BLOCK_SIZE;
		size -= GOST94_BLOCK_SIZE;
	}
	if (size) {
		/* save leftovers */
		memcpy_pp(ctx->message, msg, size);
	}
}

#if !__ENDIAN_LITTLE__
INLINE void rhash_u32_swap_copy(void* to, const void* from, uint length) {
	uint i;
	uint *pO, *pI;
	pO = (uint *)to;
	pI = (uint *)from;
	length >>= 2;
	for (i = 0; i < length; ++i) {
		*pO++ = SWAP32(*pI++);
	}
}

#define le32_copy(to, from, length) rhash_u32_swap_copy((to), (from), (length))
#else /* !__ENDIAN_LITTLE__ */
#define le32_copy(to, from, length) memcpy_pp((to), (from), (length))
#endif /* !__ENDIAN_LITTLE__ */

/**
 * Finish hashing and store message digest into given array.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param result calculated hash in binary form
 */
static NOINLINE void gost94_final(gost94_ctx *ctx, uchar *result, MAYBE_LOCAL const rhash_gost94_sbox *sbox)
{
	uint  index = ctx->length & 31;
	uint* msg32 = (uint*)ctx->message;

	/* pad the last block with zeroes and hash it */
	if (index > 0) {
		memset_p(ctx->message + index, 0, 32 - index);
		rhash_gost94_compute_sum_and_hash(ctx, msg32, sbox);
	}

	/* hash the message length and the sum */
	msg32[0] = ctx->length << 3;
	msg32[1] = ctx->length >> 29;
	memset_p(msg32 + 2, 0, sizeof(uint)*6);

	rhash_gost94_block_compress(ctx, msg32, sbox);
	rhash_gost94_block_compress(ctx, ctx->sum, sbox);

	/* convert hash state to result bytes */
	le32_copy(result, ctx->hash, GOST94_HASH_LENGTH);
}

/* ROTL macros rotate a 32-bit word left by n bits */
#define ROTL32(dword, n) rotate(dword, (uint)(n))

#if GOST94_FLAT_INIT
__constant uint precomp_table[1024] = {
	0x00072000U, 0x00075000U, 0x00074800U, 0x00071000U, 0x00076800U, 0x00074000U, 0x00070000U, 0x00077000U,
	0x00073000U, 0x00075800U, 0x00070800U, 0x00076000U, 0x00073800U, 0x00077800U, 0x00072800U, 0x00071800U,
	0x0005a000U, 0x0005d000U, 0x0005c800U, 0x00059000U, 0x0005e800U, 0x0005c000U, 0x00058000U, 0x0005f000U,
	0x0005b000U, 0x0005d800U, 0x00058800U, 0x0005e000U, 0x0005b800U, 0x0005f800U, 0x0005a800U, 0x00059800U,
	0x00022000U, 0x00025000U, 0x00024800U, 0x00021000U, 0x00026800U, 0x00024000U, 0x00020000U, 0x00027000U,
	0x00023000U, 0x00025800U, 0x00020800U, 0x00026000U, 0x00023800U, 0x00027800U, 0x00022800U, 0x00021800U,
	0x00062000U, 0x00065000U, 0x00064800U, 0x00061000U, 0x00066800U, 0x00064000U, 0x00060000U, 0x00067000U,
	0x00063000U, 0x00065800U, 0x00060800U, 0x00066000U, 0x00063800U, 0x00067800U, 0x00062800U, 0x00061800U,
	0x00032000U, 0x00035000U, 0x00034800U, 0x00031000U, 0x00036800U, 0x00034000U, 0x00030000U, 0x00037000U,
	0x00033000U, 0x00035800U, 0x00030800U, 0x00036000U, 0x00033800U, 0x00037800U, 0x00032800U, 0x00031800U,
	0x0006a000U, 0x0006d000U, 0x0006c800U, 0x00069000U, 0x0006e800U, 0x0006c000U, 0x00068000U, 0x0006f000U,
	0x0006b000U, 0x0006d800U, 0x00068800U, 0x0006e000U, 0x0006b800U, 0x0006f800U, 0x0006a800U, 0x00069800U,
	0x0007a000U, 0x0007d000U, 0x0007c800U, 0x00079000U, 0x0007e800U, 0x0007c000U, 0x00078000U, 0x0007f000U,
	0x0007b000U, 0x0007d800U, 0x00078800U, 0x0007e000U, 0x0007b800U, 0x0007f800U, 0x0007a800U, 0x00079800U,
	0x00052000U, 0x00055000U, 0x00054800U, 0x00051000U, 0x00056800U, 0x00054000U, 0x00050000U, 0x00057000U,
	0x00053000U, 0x00055800U, 0x00050800U, 0x00056000U, 0x00053800U, 0x00057800U, 0x00052800U, 0x00051800U,
	0x00012000U, 0x00015000U, 0x00014800U, 0x00011000U, 0x00016800U, 0x00014000U, 0x00010000U, 0x00017000U,
	0x00013000U, 0x00015800U, 0x00010800U, 0x00016000U, 0x00013800U, 0x00017800U, 0x00012800U, 0x00011800U,
	0x0001a000U, 0x0001d000U, 0x0001c800U, 0x00019000U, 0x0001e800U, 0x0001c000U, 0x00018000U, 0x0001f000U,
	0x0001b000U, 0x0001d800U, 0x00018800U, 0x0001e000U, 0x0001b800U, 0x0001f800U, 0x0001a800U, 0x00019800U,
	0x00042000U, 0x00045000U, 0x00044800U, 0x00041000U, 0x00046800U, 0x00044000U, 0x00040000U, 0x00047000U,
	0x00043000U, 0x00045800U, 0x00040800U, 0x00046000U, 0x00043800U, 0x00047800U, 0x00042800U, 0x00041800U,
	0x0000a000U, 0x0000d000U, 0x0000c800U, 0x00009000U, 0x0000e800U, 0x0000c000U, 0x00008000U, 0x0000f000U,
	0x0000b000U, 0x0000d800U, 0x00008800U, 0x0000e000U, 0x0000b800U, 0x0000f800U, 0x0000a800U, 0x00009800U,
	0x00002000U, 0x00005000U, 0x00004800U, 0x00001000U, 0x00006800U, 0x00004000U, 0x00000000U, 0x00007000U,
	0x00003000U, 0x00005800U, 0x00000800U, 0x00006000U, 0x00003800U, 0x00007800U, 0x00002800U, 0x00001800U,
	0x0003a000U, 0x0003d000U, 0x0003c800U, 0x00039000U, 0x0003e800U, 0x0003c000U, 0x00038000U, 0x0003f000U,
	0x0003b000U, 0x0003d800U, 0x00038800U, 0x0003e000U, 0x0003b800U, 0x0003f800U, 0x0003a800U, 0x00039800U,
	0x0002a000U, 0x0002d000U, 0x0002c800U, 0x00029000U, 0x0002e800U, 0x0002c000U, 0x00028000U, 0x0002f000U,
	0x0002b000U, 0x0002d800U, 0x00028800U, 0x0002e000U, 0x0002b800U, 0x0002f800U, 0x0002a800U, 0x00029800U,
	0x0004a000U, 0x0004d000U, 0x0004c800U, 0x00049000U, 0x0004e800U, 0x0004c000U, 0x00048000U, 0x0004f000U,
	0x0004b000U, 0x0004d800U, 0x00048800U, 0x0004e000U, 0x0004b800U, 0x0004f800U, 0x0004a800U, 0x00049800U,
	0x03a80000U, 0x03c00000U, 0x03880000U, 0x03e80000U, 0x03d00000U, 0x03980000U, 0x03a00000U, 0x03900000U,
	0x03f00000U, 0x03f80000U, 0x03e00000U, 0x03b80000U, 0x03b00000U, 0x03800000U, 0x03c80000U, 0x03d80000U,
	0x06a80000U, 0x06c00000U, 0x06880000U, 0x06e80000U, 0x06d00000U, 0x06980000U, 0x06a00000U, 0x06900000U,
	0x06f00000U, 0x06f80000U, 0x06e00000U, 0x06b80000U, 0x06b00000U, 0x06800000U, 0x06c80000U, 0x06d80000U,
	0x05280000U, 0x05400000U, 0x05080000U, 0x05680000U, 0x05500000U, 0x05180000U, 0x05200000U, 0x05100000U,
	0x05700000U, 0x05780000U, 0x05600000U, 0x05380000U, 0x05300000U, 0x05000000U, 0x05480000U, 0x05580000U,
	0x00a80000U, 0x00c00000U, 0x00880000U, 0x00e80000U, 0x00d00000U, 0x00980000U, 0x00a00000U, 0x00900000U,
	0x00f00000U, 0x00f80000U, 0x00e00000U, 0x00b80000U, 0x00b00000U, 0x00800000U, 0x00c80000U, 0x00d80000U,
	0x00280000U, 0x00400000U, 0x00080000U, 0x00680000U, 0x00500000U, 0x00180000U, 0x00200000U, 0x00100000U,
	0x00700000U, 0x00780000U, 0x00600000U, 0x00380000U, 0x00300000U, 0x00000000U, 0x00480000U, 0x00580000U,
	0x04280000U, 0x04400000U, 0x04080000U, 0x04680000U, 0x04500000U, 0x04180000U, 0x04200000U, 0x04100000U,
	0x04700000U, 0x04780000U, 0x04600000U, 0x04380000U, 0x04300000U, 0x04000000U, 0x04480000U, 0x04580000U,
	0x04a80000U, 0x04c00000U, 0x04880000U, 0x04e80000U, 0x04d00000U, 0x04980000U, 0x04a00000U, 0x04900000U,
	0x04f00000U, 0x04f80000U, 0x04e00000U, 0x04b80000U, 0x04b00000U, 0x04800000U, 0x04c80000U, 0x04d80000U,
	0x07a80000U, 0x07c00000U, 0x07880000U, 0x07e80000U, 0x07d00000U, 0x07980000U, 0x07a00000U, 0x07900000U,
	0x07f00000U, 0x07f80000U, 0x07e00000U, 0x07b80000U, 0x07b00000U, 0x07800000U, 0x07c80000U, 0x07d80000U,
	0x07280000U, 0x07400000U, 0x07080000U, 0x07680000U, 0x07500000U, 0x07180000U, 0x07200000U, 0x07100000U,
	0x07700000U, 0x07780000U, 0x07600000U, 0x07380000U, 0x07300000U, 0x07000000U, 0x07480000U, 0x07580000U,
	0x02280000U, 0x02400000U, 0x02080000U, 0x02680000U, 0x02500000U, 0x02180000U, 0x02200000U, 0x02100000U,
	0x02700000U, 0x02780000U, 0x02600000U, 0x02380000U, 0x02300000U, 0x02000000U, 0x02480000U, 0x02580000U,
	0x03280000U, 0x03400000U, 0x03080000U, 0x03680000U, 0x03500000U, 0x03180000U, 0x03200000U, 0x03100000U,
	0x03700000U, 0x03780000U, 0x03600000U, 0x03380000U, 0x03300000U, 0x03000000U, 0x03480000U, 0x03580000U,
	0x06280000U, 0x06400000U, 0x06080000U, 0x06680000U, 0x06500000U, 0x06180000U, 0x06200000U, 0x06100000U,
	0x06700000U, 0x06780000U, 0x06600000U, 0x06380000U, 0x06300000U, 0x06000000U, 0x06480000U, 0x06580000U,
	0x05a80000U, 0x05c00000U, 0x05880000U, 0x05e80000U, 0x05d00000U, 0x05980000U, 0x05a00000U, 0x05900000U,
	0x05f00000U, 0x05f80000U, 0x05e00000U, 0x05b80000U, 0x05b00000U, 0x05800000U, 0x05c80000U, 0x05d80000U,
	0x01280000U, 0x01400000U, 0x01080000U, 0x01680000U, 0x01500000U, 0x01180000U, 0x01200000U, 0x01100000U,
	0x01700000U, 0x01780000U, 0x01600000U, 0x01380000U, 0x01300000U, 0x01000000U, 0x01480000U, 0x01580000U,
	0x02a80000U, 0x02c00000U, 0x02880000U, 0x02e80000U, 0x02d00000U, 0x02980000U, 0x02a00000U, 0x02900000U,
	0x02f00000U, 0x02f80000U, 0x02e00000U, 0x02b80000U, 0x02b00000U, 0x02800000U, 0x02c80000U, 0x02d80000U,
	0x01a80000U, 0x01c00000U, 0x01880000U, 0x01e80000U, 0x01d00000U, 0x01980000U, 0x01a00000U, 0x01900000U,
	0x01f00000U, 0x01f80000U, 0x01e00000U, 0x01b80000U, 0x01b00000U, 0x01800000U, 0x01c80000U, 0x01d80000U,
	0x30000002U, 0x60000002U, 0x38000002U, 0x08000002U, 0x28000002U, 0x78000002U, 0x68000002U, 0x40000002U,
	0x20000002U, 0x50000002U, 0x48000002U, 0x70000002U, 0x00000002U, 0x18000002U, 0x58000002U, 0x10000002U,
	0xb0000005U, 0xe0000005U, 0xb8000005U, 0x88000005U, 0xa8000005U, 0xf8000005U, 0xe8000005U, 0xc0000005U,
	0xa0000005U, 0xd0000005U, 0xc8000005U, 0xf0000005U, 0x80000005U, 0x98000005U, 0xd8000005U, 0x90000005U,
	0x30000005U, 0x60000005U, 0x38000005U, 0x08000005U, 0x28000005U, 0x78000005U, 0x68000005U, 0x40000005U,
	0x20000005U, 0x50000005U, 0x48000005U, 0x70000005U, 0x00000005U, 0x18000005U, 0x58000005U, 0x10000005U,
	0x30000000U, 0x60000000U, 0x38000000U, 0x08000000U, 0x28000000U, 0x78000000U, 0x68000000U, 0x40000000U,
	0x20000000U, 0x50000000U, 0x48000000U, 0x70000000U, 0x00000000U, 0x18000000U, 0x58000000U, 0x10000000U,
	0xb0000003U, 0xe0000003U, 0xb8000003U, 0x88000003U, 0xa8000003U, 0xf8000003U, 0xe8000003U, 0xc0000003U,
	0xa0000003U, 0xd0000003U, 0xc8000003U, 0xf0000003U, 0x80000003U, 0x98000003U, 0xd8000003U, 0x90000003U,
	0x30000001U, 0x60000001U, 0x38000001U, 0x08000001U, 0x28000001U, 0x78000001U, 0x68000001U, 0x40000001U,
	0x20000001U, 0x50000001U, 0x48000001U, 0x70000001U, 0x00000001U, 0x18000001U, 0x58000001U, 0x10000001U,
	0xb0000000U, 0xe0000000U, 0xb8000000U, 0x88000000U, 0xa8000000U, 0xf8000000U, 0xe8000000U, 0xc0000000U,
	0xa0000000U, 0xd0000000U, 0xc8000000U, 0xf0000000U, 0x80000000U, 0x98000000U, 0xd8000000U, 0x90000000U,
	0xb0000006U, 0xe0000006U, 0xb8000006U, 0x88000006U, 0xa8000006U, 0xf8000006U, 0xe8000006U, 0xc0000006U,
	0xa0000006U, 0xd0000006U, 0xc8000006U, 0xf0000006U, 0x80000006U, 0x98000006U, 0xd8000006U, 0x90000006U,
	0xb0000001U, 0xe0000001U, 0xb8000001U, 0x88000001U, 0xa8000001U, 0xf8000001U, 0xe8000001U, 0xc0000001U,
	0xa0000001U, 0xd0000001U, 0xc8000001U, 0xf0000001U, 0x80000001U, 0x98000001U, 0xd8000001U, 0x90000001U,
	0x30000003U, 0x60000003U, 0x38000003U, 0x08000003U, 0x28000003U, 0x78000003U, 0x68000003U, 0x40000003U,
	0x20000003U, 0x50000003U, 0x48000003U, 0x70000003U, 0x00000003U, 0x18000003U, 0x58000003U, 0x10000003U,
	0x30000004U, 0x60000004U, 0x38000004U, 0x08000004U, 0x28000004U, 0x78000004U, 0x68000004U, 0x40000004U,
	0x20000004U, 0x50000004U, 0x48000004U, 0x70000004U, 0x00000004U, 0x18000004U, 0x58000004U, 0x10000004U,
	0xb0000002U, 0xe0000002U, 0xb8000002U, 0x88000002U, 0xa8000002U, 0xf8000002U, 0xe8000002U, 0xc0000002U,
	0xa0000002U, 0xd0000002U, 0xc8000002U, 0xf0000002U, 0x80000002U, 0x98000002U, 0xd8000002U, 0x90000002U,
	0xb0000004U, 0xe0000004U, 0xb8000004U, 0x88000004U, 0xa8000004U, 0xf8000004U, 0xe8000004U, 0xc0000004U,
	0xa0000004U, 0xd0000004U, 0xc8000004U, 0xf0000004U, 0x80000004U, 0x98000004U, 0xd8000004U, 0x90000004U,
	0x30000006U, 0x60000006U, 0x38000006U, 0x08000006U, 0x28000006U, 0x78000006U, 0x68000006U, 0x40000006U,
	0x20000006U, 0x50000006U, 0x48000006U, 0x70000006U, 0x00000006U, 0x18000006U, 0x58000006U, 0x10000006U,
	0xb0000007U, 0xe0000007U, 0xb8000007U, 0x88000007U, 0xa8000007U, 0xf8000007U, 0xe8000007U, 0xc0000007U,
	0xa0000007U, 0xd0000007U, 0xc8000007U, 0xf0000007U, 0x80000007U, 0x98000007U, 0xd8000007U, 0x90000007U,
	0x30000007U, 0x60000007U, 0x38000007U, 0x08000007U, 0x28000007U, 0x78000007U, 0x68000007U, 0x40000007U,
	0x20000007U, 0x50000007U, 0x48000007U, 0x70000007U, 0x00000007U, 0x18000007U, 0x58000007U, 0x10000007U,
	0x000000e8U, 0x000000d8U, 0x000000a0U, 0x00000088U, 0x00000098U, 0x000000f8U, 0x000000a8U, 0x000000c8U,
	0x00000080U, 0x000000d0U, 0x000000f0U, 0x000000b8U, 0x000000b0U, 0x000000c0U, 0x00000090U, 0x000000e0U,
	0x000007e8U, 0x000007d8U, 0x000007a0U, 0x00000788U, 0x00000798U, 0x000007f8U, 0x000007a8U, 0x000007c8U,
	0x00000780U, 0x000007d0U, 0x000007f0U, 0x000007b8U, 0x000007b0U, 0x000007c0U, 0x00000790U, 0x000007e0U,
	0x000006e8U, 0x000006d8U, 0x000006a0U, 0x00000688U, 0x00000698U, 0x000006f8U, 0x000006a8U, 0x000006c8U,
	0x00000680U, 0x000006d0U, 0x000006f0U, 0x000006b8U, 0x000006b0U, 0x000006c0U, 0x00000690U, 0x000006e0U,
	0x00000068U, 0x00000058U, 0x00000020U, 0x00000008U, 0x00000018U, 0x00000078U, 0x00000028U, 0x00000048U,
	0x00000000U, 0x00000050U, 0x00000070U, 0x00000038U, 0x00000030U, 0x00000040U, 0x00000010U, 0x00000060U,
	0x000002e8U, 0x000002d8U, 0x000002a0U, 0x00000288U, 0x00000298U, 0x000002f8U, 0x000002a8U, 0x000002c8U,
	0x00000280U, 0x000002d0U, 0x000002f0U, 0x000002b8U, 0x000002b0U, 0x000002c0U, 0x00000290U, 0x000002e0U,
	0x000003e8U, 0x000003d8U, 0x000003a0U, 0x00000388U, 0x00000398U, 0x000003f8U, 0x000003a8U, 0x000003c8U,
	0x00000380U, 0x000003d0U, 0x000003f0U, 0x000003b8U, 0x000003b0U, 0x000003c0U, 0x00000390U, 0x000003e0U,
	0x00000568U, 0x00000558U, 0x00000520U, 0x00000508U, 0x00000518U, 0x00000578U, 0x00000528U, 0x00000548U,
	0x00000500U, 0x00000550U, 0x00000570U, 0x00000538U, 0x00000530U, 0x00000540U, 0x00000510U, 0x00000560U,
	0x00000268U, 0x00000258U, 0x00000220U, 0x00000208U, 0x00000218U, 0x00000278U, 0x00000228U, 0x00000248U,
	0x00000200U, 0x00000250U, 0x00000270U, 0x00000238U, 0x00000230U, 0x00000240U, 0x00000210U, 0x00000260U,
	0x000004e8U, 0x000004d8U, 0x000004a0U, 0x00000488U, 0x00000498U, 0x000004f8U, 0x000004a8U, 0x000004c8U,
	0x00000480U, 0x000004d0U, 0x000004f0U, 0x000004b8U, 0x000004b0U, 0x000004c0U, 0x00000490U, 0x000004e0U,
	0x00000168U, 0x00000158U, 0x00000120U, 0x00000108U, 0x00000118U, 0x00000178U, 0x00000128U, 0x00000148U,
	0x00000100U, 0x00000150U, 0x00000170U, 0x00000138U, 0x00000130U, 0x00000140U, 0x00000110U, 0x00000160U,
	0x000001e8U, 0x000001d8U, 0x000001a0U, 0x00000188U, 0x00000198U, 0x000001f8U, 0x000001a8U, 0x000001c8U,
	0x00000180U, 0x000001d0U, 0x000001f0U, 0x000001b8U, 0x000001b0U, 0x000001c0U, 0x00000190U, 0x000001e0U,
	0x00000768U, 0x00000758U, 0x00000720U, 0x00000708U, 0x00000718U, 0x00000778U, 0x00000728U, 0x00000748U,
	0x00000700U, 0x00000750U, 0x00000770U, 0x00000738U, 0x00000730U, 0x00000740U, 0x00000710U, 0x00000760U,
	0x00000368U, 0x00000358U, 0x00000320U, 0x00000308U, 0x00000318U, 0x00000378U, 0x00000328U, 0x00000348U,
	0x00000300U, 0x00000350U, 0x00000370U, 0x00000338U, 0x00000330U, 0x00000340U, 0x00000310U, 0x00000360U,
	0x000005e8U, 0x000005d8U, 0x000005a0U, 0x00000588U, 0x00000598U, 0x000005f8U, 0x000005a8U, 0x000005c8U,
	0x00000580U, 0x000005d0U, 0x000005f0U, 0x000005b8U, 0x000005b0U, 0x000005c0U, 0x00000590U, 0x000005e0U,
	0x00000468U, 0x00000458U, 0x00000420U, 0x00000408U, 0x00000418U, 0x00000478U, 0x00000428U, 0x00000448U,
	0x00000400U, 0x00000450U, 0x00000470U, 0x00000438U, 0x00000430U, 0x00000440U, 0x00000410U, 0x00000460U,
	0x00000668U, 0x00000658U, 0x00000620U, 0x00000608U, 0x00000618U, 0x00000678U, 0x00000628U, 0x00000648U,
	0x00000600U, 0x00000650U, 0x00000670U, 0x00000638U, 0x00000630U, 0x00000640U, 0x00000610U, 0x00000660U,
};
#elif GOST94_CRYPTPRO
/* Parameter set recommended by RFC 4357.
 * Eight 4-bit S-Boxes as defined by RFC 4357 section 11.2 */
__constant uchar sbox[8][16] = {
	{ 10,  4,  5,  6,  8,  1,  3,  7, 13, 12, 14,  0,  9,  2, 11, 15 },
	{  5, 15,  4,  0,  2, 13, 11,  9,  1,  7,  6,  3, 12, 14, 10,  8 },
	{  7, 15, 12, 14,  9,  4,  1,  0,  3, 11,  5,  2,  6, 10,  8, 13 },
	{  4, 10,  7, 12,  0, 15,  2,  8, 14,  1,  6,  5, 13, 11,  9,  3 },
	{  7,  6,  4, 11,  9, 12,  2, 10,  1,  8,  0, 14, 15, 13,  3,  5 },
	{  7,  6,  2,  4, 13,  9, 15,  0, 10,  1,  5, 11,  8, 14, 12,  3 },
	{ 13, 14,  4,  1,  7,  0,  5, 10,  3, 12,  8, 15,  6,  2,  9, 11 },
	{  1,  3, 10,  9,  5, 11,  4, 15,  8,  6,  7, 14, 13,  0,  2, 12 }
};
#else
/* Test parameters set. Eight 4-bit S-Boxes defined by GOST R 34.10-94
 * standard for testing the hash function.
 * Also given by RFC 4357 section 11.2 */
__constant uchar sbox[8][16] = {
	{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
	{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
	{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
	{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
	{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
	{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
	{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
	{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
};
#endif

/**
 * Initialize the GOST lookup tables for both parameters sets.
 * The lookup table contain 4 KiB in total, so calculating
 * it at run-time can save a little space in the executable file
 * in trade of consuming some time at program start.
 */
INLINE void gost94_init_table(MAYBE_LOCAL rhash_gost94_sbox *cur_sbox)
{
	uint i;
#if GOST94_FLAT_INIT
#if GOST94_USE_LOCAL
	for (i = THREAD; i < 1024; i += LWS)
		cur_sbox->flat[i] = precomp_table[i];
#else
	for (i = 0; i < 1024; i++)
		cur_sbox->flat[i] = precomp_table[i];
#endif	/* GOST94_USE_LOCAL */
#else
	uint a, b;
	uint ax, bx, cx, dx;

#if GOST94_USE_LOCAL
	if (THREAD == 0) // Suboptimal
#endif
	for (i = 0, a = 0; a < 16; a++) {
		ax = (uint)sbox[1][a] << 15;
		bx = (uint)sbox[3][a] << 23;
		cx = ROTL32((uint)sbox[5][a], 31);
		dx = (uint)sbox[7][a] << 7;

		for (b = 0; b < 16; b++, i++) {
			cur_sbox->array[0][i] = ax | ((uint)sbox[0][b] << 11);
			cur_sbox->array[1][i] = bx | ((uint)sbox[2][b] << 19);
			cur_sbox->array[2][i] = cx | ((uint)sbox[4][b] << 27);
			cur_sbox->array[3][i] = dx | ((uint)sbox[6][b] << 3);
		}
	}
#endif	/* GOST94_FLAT_INIT */
#if GOST94_USE_LOCAL
	barrier(CLK_LOCAL_MEM_FENCE);
#endif
}

#endif /* GOST94_H */

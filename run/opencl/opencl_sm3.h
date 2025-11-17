/*
 * This software is Copyright (c) 2025 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef OPENCL_SM3_H
#define OPENCL_SM3_H

#include "opencl_misc.h"

#define SM3_BLOCK_SIZE  64
#define SM3_HASH_LENGTH 32

/* algorithm context */
typedef struct sm3_ctx {
	uint32_t hash[8];       /* 256-bit hash */
	uchar block[SM3_BLOCK_SIZE];    /* 512-bit message block */
	uint64_t num_blocks;    /* processed number of blocks */
	uint64_t num;           /* index in the buffer of the last byte stored */
} sm3_ctx;

__constant uint32_t K[64] = {
	0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
	0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
	0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
	0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
	0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
	0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
	0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
	0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};

#define GETU32(x)             \
    ((uint32_t)(x)[0] << 24 | \
     (uint32_t)(x)[1] << 16 | \
     (uint32_t)(x)[2] <<  8 | \
     (uint32_t)(x)[3])

#define PUTU32(x,y)                 \
    ((x)[0] = (uchar)((y) >> 24), \
     (x)[1] = (uchar)((y) >> 16), \
     (x)[2] = (uchar)((y) >>  8), \
     (x)[3] = (uchar)(y))

#define P0(x) ((x) ^ rol32((x), 9) ^ rol32((x),17))
#define P1(x) ((x) ^ rol32((x),15) ^ rol32((x),23))

#define SM3_LUT3	HAVE_LUT3

#if SM3_LUT3
#define FF00(x, y, z)  lut3(x, y, z, 0x96)
#define FF16(x, y, z)  lut3(x, y, z, 0xE8)
#define GG00(x, y, z)  lut3(x, y, z, 0x96)
#define GG16(x, y, z)  lut3(x, y, z, 0xCA)
#else
#define FF00(x,y,z)  ((x) ^ (y) ^ (z))
#define FF16(x,y,z)  (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG00(x,y,z)  ((x) ^ (y) ^ (z))
#define GG16(x,y,z)  ((((y) ^ (z)) & (x)) ^ (z))
#endif

#define rol32(a, b)	rotate((a), (uint)(b))

#define SM3_ROUND_0(j,A,B,C,D,E,F,G,H)              \
    SS0 = rol32(A, 12);                             \
    SS1 = rol32(SS0 + E + K[j], 7);                 \
    SS2 = SS1 ^ SS0;                                \
    D += FF00(A, B, C) + SS2 + (W[j] ^ W[j + 4]);   \
    SS1 += GG00(E, F, G) + H + W[j];                \
    B = rol32(B, 9);                                \
    H = P0(SS1);                                    \
    F = rol32(F, 19);                               \
    W[j+16] = P1(W[j] ^ W[j+7] ^ rol32(W[j+13], 15)) ^ rol32(W[j+3], 7) ^ W[j+10];

#define SM3_ROUND_1(j,A,B,C,D,E,F,G,H)              \
    SS0 = rol32(A, 12);                             \
    SS1 = rol32(SS0 + E + K[j], 7);                 \
    SS2 = SS1 ^ SS0;                                \
    D += FF16(A, B, C) + SS2 + (W[j] ^ W[j + 4]);   \
    SS1 += GG16(E, F, G) + H + W[j];                \
    B = rol32(B, 9);                                \
    H = P0(SS1);                                    \
    F = rol32(F, 19);                               \
    W[j+16] = P1(W[j] ^ W[j+7] ^ rol32(W[j+13], 15)) ^ rol32(W[j+3], 7) ^ W[j+10];

#define SM3_ROUND_2(j,A,B,C,D,E,F,G,H)              \
    SS0 = rol32(A, 12);                             \
    SS1 = rol32(SS0 + E + K[j], 7);                 \
    SS2 = SS1 ^ SS0;                                \
    D += FF16(A, B, C) + SS2 + (W[j] ^ W[j + 4]);   \
    SS1 += GG16(E, F, G) + H + W[j];                \
    B = rol32(B, 9);                                \
    H = P0(SS1);                                    \
    F = rol32(F, 19);


INLINE void sm3_compress_blocks(uint32_t *hash, const uchar *data, size_t blocks)
{
	uint32_t A, B, C, D, E, F, G, H;
	uint32_t W[68];
	uint32_t SS0, SS1, SS2;
	int j;

	while (blocks--) {

		A = hash[0];
		B = hash[1];
		C = hash[2];
		D = hash[3];
		E = hash[4];
		F = hash[5];
		G = hash[6];
		H = hash[7];

		for (j = 0; j < 16; j++) {
			W[j] = GETU32(data + j * 4);
		}

		SM3_ROUND_0(0, A, B, C, D, E, F, G, H);
		SM3_ROUND_0(1, D, A, B, C, H, E, F, G);
		SM3_ROUND_0(2, C, D, A, B, G, H, E, F);
		SM3_ROUND_0(3, B, C, D, A, F, G, H, E);
		SM3_ROUND_0(4, A, B, C, D, E, F, G, H);
		SM3_ROUND_0(5, D, A, B, C, H, E, F, G);
		SM3_ROUND_0(6, C, D, A, B, G, H, E, F);
		SM3_ROUND_0(7, B, C, D, A, F, G, H, E);
		SM3_ROUND_0(8, A, B, C, D, E, F, G, H);
		SM3_ROUND_0(9, D, A, B, C, H, E, F, G);
		SM3_ROUND_0(10, C, D, A, B, G, H, E, F);
		SM3_ROUND_0(11, B, C, D, A, F, G, H, E);
		SM3_ROUND_0(12, A, B, C, D, E, F, G, H);
		SM3_ROUND_0(13, D, A, B, C, H, E, F, G);
		SM3_ROUND_0(14, C, D, A, B, G, H, E, F);
		SM3_ROUND_0(15, B, C, D, A, F, G, H, E);
		SM3_ROUND_1(16, A, B, C, D, E, F, G, H);
		SM3_ROUND_1(17, D, A, B, C, H, E, F, G);
		SM3_ROUND_1(18, C, D, A, B, G, H, E, F);
		SM3_ROUND_1(19, B, C, D, A, F, G, H, E);
		SM3_ROUND_1(20, A, B, C, D, E, F, G, H);
		SM3_ROUND_1(21, D, A, B, C, H, E, F, G);
		SM3_ROUND_1(22, C, D, A, B, G, H, E, F);
		SM3_ROUND_1(23, B, C, D, A, F, G, H, E);
		SM3_ROUND_1(24, A, B, C, D, E, F, G, H);
		SM3_ROUND_1(25, D, A, B, C, H, E, F, G);
		SM3_ROUND_1(26, C, D, A, B, G, H, E, F);
		SM3_ROUND_1(27, B, C, D, A, F, G, H, E);
		SM3_ROUND_1(28, A, B, C, D, E, F, G, H);
		SM3_ROUND_1(29, D, A, B, C, H, E, F, G);
		SM3_ROUND_1(30, C, D, A, B, G, H, E, F);
		SM3_ROUND_1(31, B, C, D, A, F, G, H, E);
		SM3_ROUND_1(32, A, B, C, D, E, F, G, H);
		SM3_ROUND_1(33, D, A, B, C, H, E, F, G);
		SM3_ROUND_1(34, C, D, A, B, G, H, E, F);
		SM3_ROUND_1(35, B, C, D, A, F, G, H, E);
		SM3_ROUND_1(36, A, B, C, D, E, F, G, H);
		SM3_ROUND_1(37, D, A, B, C, H, E, F, G);
		SM3_ROUND_1(38, C, D, A, B, G, H, E, F);
		SM3_ROUND_1(39, B, C, D, A, F, G, H, E);
		SM3_ROUND_1(40, A, B, C, D, E, F, G, H);
		SM3_ROUND_1(41, D, A, B, C, H, E, F, G);
		SM3_ROUND_1(42, C, D, A, B, G, H, E, F);
		SM3_ROUND_1(43, B, C, D, A, F, G, H, E);
		SM3_ROUND_1(44, A, B, C, D, E, F, G, H);
		SM3_ROUND_1(45, D, A, B, C, H, E, F, G);
		SM3_ROUND_1(46, C, D, A, B, G, H, E, F);
		SM3_ROUND_1(47, B, C, D, A, F, G, H, E);
		SM3_ROUND_1(48, A, B, C, D, E, F, G, H);
		SM3_ROUND_1(49, D, A, B, C, H, E, F, G);
		SM3_ROUND_1(50, C, D, A, B, G, H, E, F);
		SM3_ROUND_1(51, B, C, D, A, F, G, H, E);
		SM3_ROUND_2(52, A, B, C, D, E, F, G, H);
		SM3_ROUND_2(53, D, A, B, C, H, E, F, G);
		SM3_ROUND_2(54, C, D, A, B, G, H, E, F);
		SM3_ROUND_2(55, B, C, D, A, F, G, H, E);
		SM3_ROUND_2(56, A, B, C, D, E, F, G, H);
		SM3_ROUND_2(57, D, A, B, C, H, E, F, G);
		SM3_ROUND_2(58, C, D, A, B, G, H, E, F);
		SM3_ROUND_2(59, B, C, D, A, F, G, H, E);
		SM3_ROUND_2(60, A, B, C, D, E, F, G, H);
		SM3_ROUND_2(61, D, A, B, C, H, E, F, G);
		SM3_ROUND_2(62, C, D, A, B, G, H, E, F);
		SM3_ROUND_2(63, B, C, D, A, F, G, H, E);

		hash[0] ^= A;
		hash[1] ^= B;
		hash[2] ^= C;
		hash[3] ^= D;
		hash[4] ^= E;
		hash[5] ^= F;
		hash[6] ^= G;
		hash[7] ^= H;

		data += SM3_BLOCK_SIZE;
	}
}

INLINE void sm3_init(sm3_ctx *ctx)
{
	memset_p(ctx, 0, sizeof(sm3_ctx));
	/* Set IV */
	ctx->hash[0] = 0x7380166fU;
	ctx->hash[1] = 0x4914b2b9U;
	ctx->hash[2] = 0x172442d7U;
	ctx->hash[3] = 0xda8a0600U;
	ctx->hash[4] = 0xa96f30bcU;
	ctx->hash[5] = 0x163138aaU;
	ctx->hash[6] = 0xe38dee4dU;
	ctx->hash[7] = 0xb0fb0e4eU;
}

INLINE void sm3_update(sm3_ctx *ctx, const void *_data, size_t size)
{
	const uchar *data = _data;
	size_t blocks;

	ctx->num &= 0x3f;
	if (ctx->num) {
		size_t left = SM3_BLOCK_SIZE - ctx->num;

		if (size < left) {
			memcpy_pp(ctx->block + ctx->num, data, size);
			ctx->num += size;
			return;
		} else {
			memcpy_pp(ctx->block + ctx->num, data, left);
			sm3_compress_blocks(ctx->hash, ctx->block, 1);
			ctx->num_blocks++;
			data += left;
			size -= left;
		}
	}

	blocks = size / SM3_BLOCK_SIZE;
	if (blocks) {
		sm3_compress_blocks(ctx->hash, data, blocks);
		ctx->num_blocks += blocks;
		data += SM3_BLOCK_SIZE * blocks;
		size -= SM3_BLOCK_SIZE * blocks;
	}

	ctx->num = size;
	if (size) {
		memcpy_pp(ctx->block, data, size);
	}
}

INLINE void sm3_final(sm3_ctx *ctx, void *_result)
{
	uchar *result = _result;
	int i;

	ctx->num &= 0x3f;
	ctx->block[ctx->num] = 0x80;

	if (ctx->num <= SM3_BLOCK_SIZE - 9) {
		memset_p(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	} else {
		memset_p(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress_blocks(ctx->hash, ctx->block, 1);
		memset_p(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	PUTU32(ctx->block + 56, ctx->num_blocks >> 23);
	PUTU32(ctx->block + 60, (ctx->num_blocks << 9) + (ctx->num << 3));
	sm3_compress_blocks(ctx->hash, ctx->block, 1);

	for (i = 0; i < 8; i++) {
		PUTU32(result + i * 4, ctx->hash[i]);
	}
}

#endif	/* OPENCL_SM3_H */

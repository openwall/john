/*
 * This software is Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _OPENCL_SHA2_CTX_H
#define _OPENCL_SHA2_CTX_H

#include "opencl_misc.h"
#include "opencl_sha2.h"

#ifndef MAYBE_VOLATILE
#define MAYBE_VOLATILE
#endif

/*
 * SHA-256 context setup
 */

typedef struct {
	uint total;        /* number of bytes processed  */
	uint state[8];     /* intermediate digest state  */
	uchar buffer[64];  /* data block being processed */
} SHA256_CTX;

inline
void SHA256_Init(SHA256_CTX *ctx) {
	uint i;

	ctx->total = 0;

	for (i = 0; i < 8; i++)
		ctx->state[i] = h[i];
}

inline
void _sha256_process(SHA256_CTX *ctx, const uchar data[64]) {
	MAYBE_VOLATILE uint t, W[16], A, B, C, D, E, F, G, H;

#if gpu_nvidia(DEVICE_INFO)
	if (!((size_t)data & 0x03)) {
		GET_UINT32BE_ALIGNED(W[ 0], data,  0);
		GET_UINT32BE_ALIGNED(W[ 1], data,  4);
		GET_UINT32BE_ALIGNED(W[ 2], data,  8);
		GET_UINT32BE_ALIGNED(W[ 3], data, 12);
		GET_UINT32BE_ALIGNED(W[ 4], data, 16);
		GET_UINT32BE_ALIGNED(W[ 5], data, 20);
		GET_UINT32BE_ALIGNED(W[ 6], data, 24);
		GET_UINT32BE_ALIGNED(W[ 7], data, 28);
		GET_UINT32BE_ALIGNED(W[ 8], data, 32);
		GET_UINT32BE_ALIGNED(W[ 9], data, 36);
		GET_UINT32BE_ALIGNED(W[10], data, 40);
		GET_UINT32BE_ALIGNED(W[11], data, 44);
		GET_UINT32BE_ALIGNED(W[12], data, 48);
		GET_UINT32BE_ALIGNED(W[13], data, 52);
		GET_UINT32BE_ALIGNED(W[14], data, 56);
		GET_UINT32BE_ALIGNED(W[15], data, 60);
	} else
#endif
	{
		GET_UINT32BE(W[ 0], data,  0);
		GET_UINT32BE(W[ 1], data,  4);
		GET_UINT32BE(W[ 2], data,  8);
		GET_UINT32BE(W[ 3], data, 12);
		GET_UINT32BE(W[ 4], data, 16);
		GET_UINT32BE(W[ 5], data, 20);
		GET_UINT32BE(W[ 6], data, 24);
		GET_UINT32BE(W[ 7], data, 28);
		GET_UINT32BE(W[ 8], data, 32);
		GET_UINT32BE(W[ 9], data, 36);
		GET_UINT32BE(W[10], data, 40);
		GET_UINT32BE(W[11], data, 44);
		GET_UINT32BE(W[12], data, 48);
		GET_UINT32BE(W[13], data, 52);
		GET_UINT32BE(W[14], data, 56);
		GET_UINT32BE(W[15], data, 60);
	}

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	F = ctx->state[5];
	G = ctx->state[6];
	H = ctx->state[7];

	SHA256(A, B, C, D, E, F, G, H, W);

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
	ctx->state[5] += F;
	ctx->state[6] += G;
	ctx->state[7] += H;
}

/*
 * SHA-256 process buffer
 */
inline
void SHA256_Update(SHA256_CTX *ctx, const uchar *input, uint ilen) {
	uint fill;
	uint left;

	if (ilen <= 0)
		return;

	left = ctx->total & 0x3F;
	fill = 64 - left;

	ctx->total += ilen;

	if (left && ilen >= fill)
	{
		memcpy_pp(ctx->buffer + left, input, fill);
		_sha256_process(ctx, ctx->buffer);
		input += fill;
		ilen  -= fill;
		left = 0;
	}

	while(ilen >= 64)
	{
		_sha256_process(ctx, input);
		input += 64;
		ilen  -= 64;
	}

	if (ilen > 0)
	{
		memcpy_pp(ctx->buffer + left, input, ilen);
	}
}

/*
 * SHA-256 final digest
 */
inline
void SHA256_Final(uchar output[32], SHA256_CTX *ctx) {
	uint last, padn;
	ulong bits;
	uchar msglen[8];
	uchar sha256_padding[64] = { 0x80 /* , 0, 0 ... */ };

	bits = ctx->total << 3;

	PUT_UINT64BE(bits, msglen, 0);

	last = ctx->total & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	SHA256_Update(ctx, sha256_padding, padn);
	SHA256_Update(ctx, msglen, 8);

#if gpu_nvidia(DEVICE_INFO)
	if (!((size_t)output & 0x03)) {
		PUT_UINT32BE_ALIGNED(ctx->state[0], output,  0);
		PUT_UINT32BE_ALIGNED(ctx->state[1], output,  4);
		PUT_UINT32BE_ALIGNED(ctx->state[2], output,  8);
		PUT_UINT32BE_ALIGNED(ctx->state[3], output, 12);
		PUT_UINT32BE_ALIGNED(ctx->state[4], output, 16);
		PUT_UINT32BE_ALIGNED(ctx->state[5], output, 20);
		PUT_UINT32BE_ALIGNED(ctx->state[6], output, 24);
		PUT_UINT32BE_ALIGNED(ctx->state[7], output, 28);
	} else
#endif
	{
		PUT_UINT32BE(ctx->state[0], output,  0);
		PUT_UINT32BE(ctx->state[1], output,  4);
		PUT_UINT32BE(ctx->state[2], output,  8);
		PUT_UINT32BE(ctx->state[3], output, 12);
		PUT_UINT32BE(ctx->state[4], output, 16);
		PUT_UINT32BE(ctx->state[5], output, 20);
		PUT_UINT32BE(ctx->state[6], output, 24);
		PUT_UINT32BE(ctx->state[7], output, 28);
	}
}

/*
 * SHA-512 context setup
 */

typedef struct {
	uint total;        /* number of bytes processed  */
	ulong state[8];    /* intermediate digest state  */
	uchar buffer[128]; /* data block being processed */
} SHA512_CTX;

inline
void SHA512_Init(SHA512_CTX *ctx) {
	ctx->total = 0;
	ctx->state[0] = SHA2_INIT_A;
	ctx->state[1] = SHA2_INIT_B;
	ctx->state[2] = SHA2_INIT_C;
	ctx->state[3] = SHA2_INIT_D;
	ctx->state[4] = SHA2_INIT_E;
	ctx->state[5] = SHA2_INIT_F;
	ctx->state[6] = SHA2_INIT_G;
	ctx->state[7] = SHA2_INIT_H;
}

inline
void _sha512_process(SHA512_CTX *ctx, const uchar data[128]) {
	ulong t, W[16], A, B, C, D, E, F, G, H;

#if gpu_nvidia(DEVICE_INFO)
	if (!((size_t)data & 0x07)) {
		GET_UINT64BE_ALIGNED(W[ 0], data,   0);
		GET_UINT64BE_ALIGNED(W[ 1], data,   8);
		GET_UINT64BE_ALIGNED(W[ 2], data,  16);
		GET_UINT64BE_ALIGNED(W[ 3], data,  24);
		GET_UINT64BE_ALIGNED(W[ 4], data,  32);
		GET_UINT64BE_ALIGNED(W[ 5], data,  40);
		GET_UINT64BE_ALIGNED(W[ 6], data,  48);
		GET_UINT64BE_ALIGNED(W[ 7], data,  56);
		GET_UINT64BE_ALIGNED(W[ 8], data,  64);
		GET_UINT64BE_ALIGNED(W[ 9], data,  72);
		GET_UINT64BE_ALIGNED(W[10], data,  80);
		GET_UINT64BE_ALIGNED(W[11], data,  88);
		GET_UINT64BE_ALIGNED(W[12], data,  96);
		GET_UINT64BE_ALIGNED(W[13], data, 104);
		GET_UINT64BE_ALIGNED(W[14], data, 112);
		GET_UINT64BE_ALIGNED(W[15], data, 120);
	} else
#endif
	{
		GET_UINT64BE(W[ 0], data,   0);
		GET_UINT64BE(W[ 1], data,   8);
		GET_UINT64BE(W[ 2], data,  16);
		GET_UINT64BE(W[ 3], data,  24);
		GET_UINT64BE(W[ 4], data,  32);
		GET_UINT64BE(W[ 5], data,  40);
		GET_UINT64BE(W[ 6], data,  48);
		GET_UINT64BE(W[ 7], data,  56);
		GET_UINT64BE(W[ 8], data,  64);
		GET_UINT64BE(W[ 9], data,  72);
		GET_UINT64BE(W[10], data,  80);
		GET_UINT64BE(W[11], data,  88);
		GET_UINT64BE(W[12], data,  96);
		GET_UINT64BE(W[13], data, 104);
		GET_UINT64BE(W[14], data, 112);
		GET_UINT64BE(W[15], data, 120);
	}

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	F = ctx->state[5];
	G = ctx->state[6];
	H = ctx->state[7];

	SHA512(A, B, C, D, E, F, G, H, W);

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
	ctx->state[5] += F;
	ctx->state[6] += G;
	ctx->state[7] += H;
}

/*
 * SHA-512 process buffer
 */
inline
void SHA512_Update(SHA512_CTX *ctx, const uchar *input, uint ilen) {
	uint fill;
	uint left;

	if (ilen <= 0)
		return;

	left = ctx->total & 0x7F;
	fill = 128 - left;

	ctx->total += ilen;

	if (left && ilen >= fill)
	{
		memcpy_pp(ctx->buffer + left, input, fill);
		_sha512_process(ctx, ctx->buffer);
		input += fill;
		ilen  -= fill;
		left = 0;
	}

	while(ilen >= 128)
	{
		_sha512_process(ctx, input);
		input += 128;
		ilen  -= 128;
	}

	if (ilen > 0)
	{
		memcpy_pp(ctx->buffer + left, input, ilen);
	}
}

/*
 * SHA-512 final digest
 */
inline
void SHA512_Final(uchar output[64], SHA512_CTX *ctx) {
	uint last, padn;
	ulong bits;
	uchar msglen[16];
	uchar sha512_padding[128] = { 0x80 /* , 0, 0 ... */ };

	bits = ctx->total << 3;

	PUT_UINT64BE(0UL, msglen, 0);
	PUT_UINT64BE(bits, msglen, 8);

	last = ctx->total & 0x7F;
	padn = (last < 112) ? (112 - last) : (240 - last);

	SHA512_Update(ctx, sha512_padding, padn);
	SHA512_Update(ctx, msglen, 16);

#if gpu_nvidia(DEVICE_INFO)
	if (!((size_t)output & 0x07)) {
		PUT_UINT64BE_ALIGNED(ctx->state[0], output,  0);
		PUT_UINT64BE_ALIGNED(ctx->state[1], output,  8);
		PUT_UINT64BE_ALIGNED(ctx->state[2], output, 16);
		PUT_UINT64BE_ALIGNED(ctx->state[3], output, 24);
		PUT_UINT64BE_ALIGNED(ctx->state[4], output, 32);
		PUT_UINT64BE_ALIGNED(ctx->state[5], output, 40);
		PUT_UINT64BE_ALIGNED(ctx->state[6], output, 48);
		PUT_UINT64BE_ALIGNED(ctx->state[7], output, 56);
	} else
#endif
	{
		PUT_UINT64BE(ctx->state[0], output,  0);
		PUT_UINT64BE(ctx->state[1], output,  8);
		PUT_UINT64BE(ctx->state[2], output, 16);
		PUT_UINT64BE(ctx->state[3], output, 24);
		PUT_UINT64BE(ctx->state[4], output, 32);
		PUT_UINT64BE(ctx->state[5], output, 40);
		PUT_UINT64BE(ctx->state[6], output, 48);
		PUT_UINT64BE(ctx->state[7], output, 56);
	}
}

#endif /* _OPENCL_SHA2_CTX_H */

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

#define _memcpy	memcpy_macro

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
	uint t, W[16], A, B, C, D, E, F, G, H;

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
		_memcpy(ctx->buffer + left, input, fill);
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
		_memcpy(ctx->buffer + left, input, ilen);
	}
}

/*
 * SHA-256 final digest
 */
inline
void SHA256_Final(uchar output[32], SHA256_CTX *ctx) {
	uint last, padn;
	uint bits;
	uchar msglen[8];
	uchar sha256_padding[64] = { 0x80 /* , 0, 0 ... */ };

	bits = ctx->total << 3;

	PUT_UINT32BE(0, msglen, 0);
	PUT_UINT32BE(bits, msglen, 4);

	last = ctx->total & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	SHA256_Update(ctx, sha256_padding, padn);
	SHA256_Update(ctx, msglen, 8);

	PUT_UINT32BE(ctx->state[0], output,  0);
	PUT_UINT32BE(ctx->state[1], output,  4);
	PUT_UINT32BE(ctx->state[2], output,  8);
	PUT_UINT32BE(ctx->state[3], output, 12);
	PUT_UINT32BE(ctx->state[4], output, 16);
	PUT_UINT32BE(ctx->state[5], output, 20);
	PUT_UINT32BE(ctx->state[6], output, 24);
	PUT_UINT32BE(ctx->state[7], output, 28);
}

#endif // #ifndef _OPENCL_SHA2_CTX_H

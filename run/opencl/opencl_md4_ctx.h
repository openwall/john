/*
 * This software is
 * Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _OPENCL_MD4_CTX_H
#define _OPENCL_MD4_CTX_H

#include "opencl_misc.h"
#include "opencl_md4.h"

typedef struct {
	uint total;        /* number of bytes processed  */
	uint state[4];     /* intermediate digest state  */
	uchar buffer[64];  /* data block being processed */
} MD4_CTX;

#ifndef __MESA__
inline
#endif
void _md4_process(MD4_CTX *ctx, const uchar data[64]) {
	uint W[16], A, B, C, D;

#if gpu_nvidia(DEVICE_INFO)
	if (!((size_t)data & 0x03)) {
		GET_UINT32_ALIGNED(W[ 0], data,  0);
		GET_UINT32_ALIGNED(W[ 1], data,  4);
		GET_UINT32_ALIGNED(W[ 2], data,  8);
		GET_UINT32_ALIGNED(W[ 3], data, 12);
		GET_UINT32_ALIGNED(W[ 4], data, 16);
		GET_UINT32_ALIGNED(W[ 5], data, 20);
		GET_UINT32_ALIGNED(W[ 6], data, 24);
		GET_UINT32_ALIGNED(W[ 7], data, 28);
		GET_UINT32_ALIGNED(W[ 8], data, 32);
		GET_UINT32_ALIGNED(W[ 9], data, 36);
		GET_UINT32_ALIGNED(W[10], data, 40);
		GET_UINT32_ALIGNED(W[11], data, 44);
		GET_UINT32_ALIGNED(W[12], data, 48);
		GET_UINT32_ALIGNED(W[13], data, 52);
		GET_UINT32_ALIGNED(W[14], data, 56);
		GET_UINT32_ALIGNED(W[15], data, 60);
	} else
#endif
	{
		GET_UINT32(W[ 0], data,  0);
		GET_UINT32(W[ 1], data,  4);
		GET_UINT32(W[ 2], data,  8);
		GET_UINT32(W[ 3], data, 12);
		GET_UINT32(W[ 4], data, 16);
		GET_UINT32(W[ 5], data, 20);
		GET_UINT32(W[ 6], data, 24);
		GET_UINT32(W[ 7], data, 28);
		GET_UINT32(W[ 8], data, 32);
		GET_UINT32(W[ 9], data, 36);
		GET_UINT32(W[10], data, 40);
		GET_UINT32(W[11], data, 44);
		GET_UINT32(W[12], data, 48);
		GET_UINT32(W[13], data, 52);
		GET_UINT32(W[14], data, 56);
		GET_UINT32(W[15], data, 60);
	}

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];

	MD4(A, B, C, D, W);

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
}

/*
 * MD4 context setup
 */
#ifndef __MESA__
inline
#endif
void MD4_Init(MD4_CTX *ctx) {
	ctx->total = 0;

	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

/*
 * MD4 process buffer
 */
#ifndef __MESA__
inline
#endif
void MD4_Update(MD4_CTX *ctx, const uchar *input, uint ilen) {
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
		_md4_process(ctx, ctx->buffer);
		input += fill;
		ilen  -= fill;
		left = 0;
	}

	while(ilen >= 64)
	{
		_md4_process(ctx, input);
		input += 64;
		ilen  -= 64;
	}

	if (ilen > 0)
	{
		memcpy_pp(ctx->buffer + left, input, ilen);
	}
}

/*
 * MD4 final digest
 */
#ifndef __MESA__
inline
#endif
void MD4_Final(uchar output[20], MD4_CTX *ctx) {
	uint last, padn;
	ulong bits;
	uchar msglen[8];
	uchar md4_padding[64] = { 0x80 /* , 0, 0 ... */ };

	bits = ctx->total <<  3;

	PUT_UINT64(bits, msglen, 0);

	last = ctx->total & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	MD4_Update(ctx, md4_padding, padn);
	MD4_Update(ctx, msglen, 8);

#if gpu_nvidia(DEVICE_INFO)
	if (!((size_t)output & 0x03)) {
		PUT_UINT32_ALIGNED(ctx->state[0], output,  0);
		PUT_UINT32_ALIGNED(ctx->state[1], output,  4);
		PUT_UINT32_ALIGNED(ctx->state[2], output,  8);
		PUT_UINT32_ALIGNED(ctx->state[3], output, 12);
	} else
#endif
	{
		PUT_UINT32(ctx->state[0], output,  0);
		PUT_UINT32(ctx->state[1], output,  4);
		PUT_UINT32(ctx->state[2], output,  8);
		PUT_UINT32(ctx->state[3], output, 12);
	}
}

#endif /* _OPENCL_MD4_CTX_H */

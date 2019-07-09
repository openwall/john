/*
 * This software is
 * Copyright (c) 2016 JimF
 * Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

/*
 * At some point based on "FIPS-180-1 compliant SHA-1 implementation"
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _OPENCL_SHA1_CTX_H
#define _OPENCL_SHA1_CTX_H

/* this file is ONLY made to be built by the GPU code in JtR */

#include "opencl_misc.h"
#include "opencl_sha1.h"

/*
 * SHA-1 context setup
 */

typedef struct {
	uint total;        /* number of bytes processed  */
	uint state[5];     /* intermediate digest state  */
	uchar buffer[64];  /* data block being processed */
} SHA_CTX;

#ifndef __MESA__
inline
#endif
void SHA1_Init(SHA_CTX *ctx) {
	ctx->total = 0;

	ctx->state[0] = INIT_A;
	ctx->state[1] = INIT_B;
	ctx->state[2] = INIT_C;
	ctx->state[3] = INIT_D;
	ctx->state[4] = INIT_E;
}

#ifndef __MESA__
inline
#endif
void _sha1_process(SHA_CTX *ctx, const uchar data[64]) {
#if __OS_X__ && gpu_amd(DEVICE_INFO)
	volatile
#endif
	uint temp, W[16], A, B, C, D, E, r[16];

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

	SHA1(A, B, C, D, E, W);

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
}

/*
 * SHA-1 process buffer
 */
#ifndef __MESA__
inline
#endif
void SHA1_Update(SHA_CTX *ctx, const uchar *input, uint ilen) {
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
		_sha1_process(ctx, ctx->buffer);
		input += fill;
		ilen  -= fill;
		left = 0;
	}

	while(ilen >= 64)
	{
		_sha1_process(ctx, input);
		input += 64;
		ilen  -= 64;
	}

	if (ilen > 0)
	{
		memcpy_pp(ctx->buffer + left, input, ilen);
	}
}

/*
 * SHA-1 final digest
 */
#ifndef __MESA__
inline
#endif
void SHA1_Final(uchar output[20], SHA_CTX *ctx) {
	uint last, padn;
	ulong bits;
	uchar msglen[8];
	uchar sha1_padding[64] = { 0x80 /* , 0, 0 ... */ };

	bits = ctx->total <<  3;

	PUT_UINT64BE(bits, msglen, 0);

	last = ctx->total & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	SHA1_Update(ctx, sha1_padding, padn);
	SHA1_Update(ctx, msglen, 8);

#if gpu_nvidia(DEVICE_INFO)
	if (!((size_t)output & 0x03)) {
		PUT_UINT32BE_ALIGNED(ctx->state[0], output,  0);
		PUT_UINT32BE_ALIGNED(ctx->state[1], output,  4);
		PUT_UINT32BE_ALIGNED(ctx->state[2], output,  8);
		PUT_UINT32BE_ALIGNED(ctx->state[3], output, 12);
		PUT_UINT32BE_ALIGNED(ctx->state[4], output, 16);
	} else
#endif
	{
		PUT_UINT32BE(ctx->state[0], output,  0);
		PUT_UINT32BE(ctx->state[1], output,  4);
		PUT_UINT32BE(ctx->state[2], output,  8);
		PUT_UINT32BE(ctx->state[3], output, 12);
		PUT_UINT32BE(ctx->state[4], output, 16);
	}
}

#endif /* _OPENCL_SHA1_CTX_H */

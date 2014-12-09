/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * and Copyright (c) 2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _OPENCL_SHA2_H
#define _OPENCL_SHA2_H

#include "opencl_device_info.h"
#include "opencl_misc.h"

__constant uint h[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

__constant uint k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#ifdef USE_BITSELECT
#define Ch(x, y, z)	bitselect(z, y, x)
#define Maj(x, y, z)	bitselect(x, y, z ^ x)
#else
#define Ch(x, y, z)	(z ^ (x & (y ^ z)))
#define Maj(x, y, z)	((x & y) | (z & (x | y)))
#endif

#define ror(x, n)	rotate(x, 32U-(n))

#define Sigma0(x) ((ror(x, 2)) ^ (ror(x, 13)) ^ (ror(x, 22)))
#define Sigma1(x) ((ror(x, 6)) ^ (ror(x, 11)) ^ (ror(x, 25)))
#define sigma0(x) ((ror(x, 7)) ^ (ror(x, 18)) ^ (x >> 3))
#define sigma1(x) ((ror(x, 17)) ^ (ror(x, 19)) ^ (x >> 10))

#define ROUND_A(a,b,c,d,e,f,g,h,ki,wi)	  \
	{ \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

#define ROUND_Z(a,b,c,d,e,f,g,h,ki)	  \
	{ \
		t = (ki) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

#define ROUND_B(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj) + sigma0(wk) + wl + wm; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//0110
#define ROUND_I(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma0(wk) + wl; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//1110
#define ROUND_J(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj) + sigma0(wk) + wl; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//1011
#define ROUND_K(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj) + wl + wm; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//1001
#define ROUND_L(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj)+ wm; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//1101
#define ROUND_M(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj) + sigma0(wk) + wm; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

#define sha256_init(o)	  \
	{ \
		uint i; \
		for (i = 0; i < 8; i++) \
			o[i] = h[i]; \
	}

#define sha256_block(W, o)\
 {	  \
	uint A, B, C, D, E, F, G, H, t; \
	A = o[0]; \
	B = o[1]; \
	C = o[2]; \
	D = o[3]; \
	E = o[4]; \
	F = o[5]; \
	G = o[6]; \
	H = o[7]; \
	ROUND_A(A,B,C,D,E,F,G,H,k[0],W[0]); \
	ROUND_A(H,A,B,C,D,E,F,G,k[1],W[1]); \
	ROUND_A(G,H,A,B,C,D,E,F,k[2],W[2]); \
	ROUND_A(F,G,H,A,B,C,D,E,k[3],W[3]); \
	ROUND_A(E,F,G,H,A,B,C,D,k[4],W[4]); \
	ROUND_A(D,E,F,G,H,A,B,C,k[5],W[5]); \
	ROUND_A(C,D,E,F,G,H,A,B,k[6],W[6]); \
	ROUND_A(B,C,D,E,F,G,H,A,k[7],W[7]); \
	ROUND_A(A,B,C,D,E,F,G,H,k[8],W[8]); \
	ROUND_A(H,A,B,C,D,E,F,G,k[9],W[9]); \
	ROUND_A(G,H,A,B,C,D,E,F,k[10],W[10]); \
	ROUND_A(F,G,H,A,B,C,D,E,k[11],W[11]); \
	ROUND_A(E,F,G,H,A,B,C,D,k[12],W[12]); \
	ROUND_A(D,E,F,G,H,A,B,C,k[13],W[13]); \
	ROUND_A(C,D,E,F,G,H,A,B,k[14],W[14]); \
	ROUND_A(B,C,D,E,F,G,H,A,k[15],W[15]); \
	ROUND_B(A,B,C,D,E,F,G,H,k[16],W[0], W[14],W[1],W[0],W[9]); \
	ROUND_B(H,A,B,C,D,E,F,G,k[17],W[1], W[15],W[2],W[1],W[10]); \
	ROUND_B(G,H,A,B,C,D,E,F,k[18],W[2], W[0],W[3],W[2],W[11]); \
	ROUND_B(F,G,H,A,B,C,D,E,k[19],W[3], W[1],W[4],W[3],W[12]); \
	ROUND_B(E,F,G,H,A,B,C,D,k[20],W[4], W[2],W[5],W[4],W[13]); \
	ROUND_B(D,E,F,G,H,A,B,C,k[21],W[5], W[3],W[6],W[5],W[14]); \
	ROUND_B(C,D,E,F,G,H,A,B,k[22],W[6], W[4],W[7],W[6],W[15]); \
	ROUND_B(B,C,D,E,F,G,H,A,k[23],W[7], W[5],W[8],W[7],W[0]); \
	ROUND_B(A,B,C,D,E,F,G,H,k[24],W[8], W[6],W[9],W[8],W[1]); \
	ROUND_B(H,A,B,C,D,E,F,G,k[25],W[9], W[7],W[10],W[9],W[2]); \
	ROUND_B(G,H,A,B,C,D,E,F,k[26],W[10], W[8],W[11],W[10],W[3]); \
	ROUND_B(F,G,H,A,B,C,D,E,k[27],W[11], W[9],W[12],W[11],W[4]); \
	ROUND_B(E,F,G,H,A,B,C,D,k[28],W[12], W[10],W[13],W[12],W[5]); \
	ROUND_B(D,E,F,G,H,A,B,C,k[29],W[13], W[11],W[14],W[13],W[6]); \
	ROUND_B(C,D,E,F,G,H,A,B,k[30],W[14], W[12],W[15],W[14],W[7]); \
	ROUND_B(B,C,D,E,F,G,H,A,k[31],W[15], W[13],W[0],W[15],W[8]); \
	ROUND_B(A,B,C,D,E,F,G,H,k[32],W[0], W[14],W[1],W[0],W[9]); \
	ROUND_B(H,A,B,C,D,E,F,G,k[33],W[1], W[15],W[2],W[1],W[10]); \
	ROUND_B(G,H,A,B,C,D,E,F,k[34],W[2], W[0],W[3],W[2],W[11]); \
	ROUND_B(F,G,H,A,B,C,D,E,k[35],W[3], W[1],W[4],W[3],W[12]); \
	ROUND_B(E,F,G,H,A,B,C,D,k[36],W[4], W[2],W[5],W[4],W[13]); \
	ROUND_B(D,E,F,G,H,A,B,C,k[37],W[5], W[3],W[6],W[5],W[14]); \
	ROUND_B(C,D,E,F,G,H,A,B,k[38],W[6], W[4],W[7],W[6],W[15]); \
	ROUND_B(B,C,D,E,F,G,H,A,k[39],W[7], W[5],W[8],W[7],W[0]); \
	ROUND_B(A,B,C,D,E,F,G,H,k[40],W[8], W[6],W[9],W[8],W[1]); \
	ROUND_B(H,A,B,C,D,E,F,G,k[41],W[9], W[7],W[10],W[9],W[2]); \
	ROUND_B(G,H,A,B,C,D,E,F,k[42],W[10], W[8],W[11],W[10],W[3]); \
	ROUND_B(F,G,H,A,B,C,D,E,k[43],W[11], W[9],W[12],W[11],W[4]); \
	ROUND_B(E,F,G,H,A,B,C,D,k[44],W[12], W[10],W[13],W[12],W[5]); \
	ROUND_B(D,E,F,G,H,A,B,C,k[45],W[13], W[11],W[14],W[13],W[6]); \
	ROUND_B(C,D,E,F,G,H,A,B,k[46],W[14], W[12],W[15],W[14],W[7]); \
	ROUND_B(B,C,D,E,F,G,H,A,k[47],W[15], W[13],W[0],W[15],W[8]); \
	ROUND_B(A,B,C,D,E,F,G,H,k[48],W[0], W[14],W[1],W[0],W[9]); \
	ROUND_B(H,A,B,C,D,E,F,G,k[49],W[1], W[15],W[2],W[1],W[10]); \
	ROUND_B(G,H,A,B,C,D,E,F,k[50],W[2], W[0],W[3],W[2],W[11]); \
	ROUND_B(F,G,H,A,B,C,D,E,k[51],W[3], W[1],W[4],W[3],W[12]); \
	ROUND_B(E,F,G,H,A,B,C,D,k[52],W[4], W[2],W[5],W[4],W[13]); \
	ROUND_B(D,E,F,G,H,A,B,C,k[53],W[5], W[3],W[6],W[5],W[14]); \
	ROUND_B(C,D,E,F,G,H,A,B,k[54],W[6], W[4],W[7],W[6],W[15]); \
	ROUND_B(B,C,D,E,F,G,H,A,k[55],W[7], W[5],W[8],W[7],W[0]); \
	ROUND_B(A,B,C,D,E,F,G,H,k[56],W[8], W[6],W[9],W[8],W[1]); \
	ROUND_B(H,A,B,C,D,E,F,G,k[57],W[9], W[7],W[10],W[9],W[2]); \
	ROUND_B(G,H,A,B,C,D,E,F,k[58],W[10], W[8],W[11],W[10],W[3]); \
	ROUND_B(F,G,H,A,B,C,D,E,k[59],W[11], W[9],W[12],W[11],W[4]); \
	ROUND_B(E,F,G,H,A,B,C,D,k[60],W[12], W[10],W[13],W[12],W[5]); \
	ROUND_B(D,E,F,G,H,A,B,C,k[61],W[13], W[11],W[14],W[13],W[6]); \
	ROUND_B(C,D,E,F,G,H,A,B,k[62],W[14], W[12],W[15],W[14],W[7]); \
	ROUND_B(B,C,D,E,F,G,H,A,k[63],W[15], W[13],W[0],W[15],W[8]); \
	o[0] += A; \
	o[1] += B; \
	o[2] += C; \
	o[3] += D; \
	o[4] += E; \
	o[5] += F; \
	o[6] += G; \
	o[7] += H; \
}

/*
 * FIPS-180-2 compliant SHA-256 implementation
 *
 * Copyright (C) 2001-2003 Christophe Devine
 *
 * sha256.c - Implementation of the Secure Hash Algorithm-256 (SHA-256).
 *
 * Copyright (C) 2002 Southern Storm Software, Pty Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

typedef struct {
	uint total[2];
	uint state[8];
	uchar buffer[64];
} SHA256_CTX;

inline void _memcpy(uchar *dest, __global const uchar *src, uint count)
{
	while (count--)
		*dest++ = *src++;
}

inline void _memcpy_(uchar *dest, const uchar *src, uint count)
{
	while (count--)
		*dest++ = *src++;
}

#if 0
#define GET_UINT32(n, b, i)	(n) = ((uint*)(b))[(i) / 4]
#define PUT_UINT32(n, b, i)	((uint*)(b))[(i) / 4] = (n)
#else
#define GET_UINT32(n, b, i)	  \
	{ \
		(n) = ((uint) (b)[(i)] << 24) \
			| ((uint) (b)[(i) + 1] << 16) \
			| ((uint) (b)[(i) + 2] <<  8) \
			| ((uint) (b)[(i) + 3]      ); \
	}

#define PUT_UINT32(n, b, i)	  \
	{ \
		(b)[(i)    ] = (uchar) ((n) >> 24); \
		(b)[(i) + 1] = (uchar) ((n) >> 16); \
		(b)[(i) + 2] = (uchar) ((n) >>  8); \
		(b)[(i) + 3] = (uchar) ((n)      ); \
	}
#endif

inline void SHA256_Init(SHA256_CTX *ctx)
{
	ctx->total[0] = 0;
	ctx->total[1] = 0;

	ctx->state[0] = 0x6A09E667;
	ctx->state[1] = 0xBB67AE85;
	ctx->state[2] = 0x3C6EF372;
	ctx->state[3] = 0xA54FF53A;
	ctx->state[4] = 0x510E527F;
	ctx->state[5] = 0x9B05688C;
	ctx->state[6] = 0x1F83D9AB;
	ctx->state[7] = 0x5BE0CD19;
}

inline void sha256_process(SHA256_CTX *ctx, uchar data[64])
{
	uint temp1, temp2, W[64];
	uint A, B, C, D, E, F, G, H;

	GET_UINT32(W[0], data, 0);
	GET_UINT32(W[1], data, 4);
	GET_UINT32(W[2], data, 8);
	GET_UINT32(W[3], data, 12);
	GET_UINT32(W[4], data, 16);
	GET_UINT32(W[5], data, 20);
	GET_UINT32(W[6], data, 24);
	GET_UINT32(W[7], data, 28);
	GET_UINT32(W[8], data, 32);
	GET_UINT32(W[9], data, 36);
	GET_UINT32(W[10], data, 40);
	GET_UINT32(W[11], data, 44);
	GET_UINT32(W[12], data, 48);
	GET_UINT32(W[13], data, 52);
	GET_UINT32(W[14], data, 56);
	GET_UINT32(W[15], data, 60);

#if 1

#define S0(x)		((ror(x, 7)) ^ (ror(x, 18)) ^ (x >> 3))
#define S1(x)		((ror(x, 17)) ^ (ror(x, 19)) ^ (x >> 10))

#define S2(x)		((ror(x, 2)) ^ (ror(x, 13)) ^ (ror(x, 22)))
#define S3(x)		((ror(x, 6)) ^ (ror(x, 11)) ^ (ror(x, 25)))

#ifdef USE_BITSELECT
#define F0(x, y, z)	bitselect(x, y, z ^ x)
#define F1(x, y, z)	bitselect(z, y, x)
#else
#define F0(x, y, z)	((x & y) | (z & (x | y)))
#define F1(x, y, z)	(z ^ (x & (y ^ z)))
#endif

#else

#define SHR(x, n)	((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n)	(SHR(x, n) | (x << (32 - n)))

#define S0(x)		(ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define S1(x)		(ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

#define S2(x)		(ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S3(x)		(ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

#define F0(x,y,z)	((x & y) | (z & (x | y)))
#define F1(x,y,z)	(z ^ (x & (y ^ z)))

#endif

#define R(t)	  \
	( \
		W[t] = S1(W[t - 2]) + W[t - 7] + \
		S0(W[t - 15]) + W[t - 16] \
		)

#define P(a,b,c,d,e,f,g,h,x,K)	  \
	{ \
		temp1 = h + S3(e) + F1(e,f,g) + K + x; \
		temp2 = S2(a) + F0(a,b,c); \
		d += temp1; h = temp1 + temp2; \
	}

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	F = ctx->state[5];
	G = ctx->state[6];
	H = ctx->state[7];

	P(A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98);
	P(H, A, B, C, D, E, F, G, W[ 1], 0x71374491);
	P(G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCF);
	P(F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA5);
	P(E, F, G, H, A, B, C, D, W[ 4], 0x3956C25B);
	P(D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1);
	P(C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4);
	P(B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5);
	P(A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98);
	P(H, A, B, C, D, E, F, G, W[ 9], 0x12835B01);
	P(G, H, A, B, C, D, E, F, W[10], 0x243185BE);
	P(F, G, H, A, B, C, D, E, W[11], 0x550C7DC3);
	P(E, F, G, H, A, B, C, D, W[12], 0x72BE5D74);
	P(D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE);
	P(C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7);
	P(B, C, D, E, F, G, H, A, W[15], 0xC19BF174);
	P(A, B, C, D, E, F, G, H, R(16), 0xE49B69C1);
	P(H, A, B, C, D, E, F, G, R(17), 0xEFBE4786);
	P(G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6);
	P(F, G, H, A, B, C, D, E, R(19), 0x240CA1CC);
	P(E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F);
	P(D, E, F, G, H, A, B, C, R(21), 0x4A7484AA);
	P(C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC);
	P(B, C, D, E, F, G, H, A, R(23), 0x76F988DA);
	P(A, B, C, D, E, F, G, H, R(24), 0x983E5152);
	P(H, A, B, C, D, E, F, G, R(25), 0xA831C66D);
	P(G, H, A, B, C, D, E, F, R(26), 0xB00327C8);
	P(F, G, H, A, B, C, D, E, R(27), 0xBF597FC7);
	P(E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3);
	P(D, E, F, G, H, A, B, C, R(29), 0xD5A79147);
	P(C, D, E, F, G, H, A, B, R(30), 0x06CA6351);
	P(B, C, D, E, F, G, H, A, R(31), 0x14292967);
	P(A, B, C, D, E, F, G, H, R(32), 0x27B70A85);
	P(H, A, B, C, D, E, F, G, R(33), 0x2E1B2138);
	P(G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC);
	P(F, G, H, A, B, C, D, E, R(35), 0x53380D13);
	P(E, F, G, H, A, B, C, D, R(36), 0x650A7354);
	P(D, E, F, G, H, A, B, C, R(37), 0x766A0ABB);
	P(C, D, E, F, G, H, A, B, R(38), 0x81C2C92E);
	P(B, C, D, E, F, G, H, A, R(39), 0x92722C85);
	P(A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1);
	P(H, A, B, C, D, E, F, G, R(41), 0xA81A664B);
	P(G, H, A, B, C, D, E, F, R(42), 0xC24B8B70);
	P(F, G, H, A, B, C, D, E, R(43), 0xC76C51A3);
	P(E, F, G, H, A, B, C, D, R(44), 0xD192E819);
	P(D, E, F, G, H, A, B, C, R(45), 0xD6990624);
	P(C, D, E, F, G, H, A, B, R(46), 0xF40E3585);
	P(B, C, D, E, F, G, H, A, R(47), 0x106AA070);
	P(A, B, C, D, E, F, G, H, R(48), 0x19A4C116);
	P(H, A, B, C, D, E, F, G, R(49), 0x1E376C08);
	P(G, H, A, B, C, D, E, F, R(50), 0x2748774C);
	P(F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5);
	P(E, F, G, H, A, B, C, D, R(52), 0x391C0CB3);
	P(D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A);
	P(C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F);
	P(B, C, D, E, F, G, H, A, R(55), 0x682E6FF3);
	P(A, B, C, D, E, F, G, H, R(56), 0x748F82EE);
	P(H, A, B, C, D, E, F, G, R(57), 0x78A5636F);
	P(G, H, A, B, C, D, E, F, R(58), 0x84C87814);
	P(F, G, H, A, B, C, D, E, R(59), 0x8CC70208);
	P(E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA);
	P(D, E, F, G, H, A, B, C, R(61), 0xA4506CEB);
	P(C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7);
	P(B, C, D, E, F, G, H, A, R(63), 0xC67178F2);

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
	ctx->state[5] += F;
	ctx->state[6] += G;
	ctx->state[7] += H;
}

inline void SHA256_Update(SHA256_CTX *ctx, uchar *input, uint length)
{
	uint left, fill;

	if (!length) return;

	left = ctx->total[0] & 0x3F;
	fill = 64 - left;

	ctx->total[0] += length;
	ctx->total[0] &= 0xFFFFFFFF;

	if (ctx->total[0] < length)
		ctx->total[1]++;

	if (left && length >= fill) {
		_memcpy_((uchar *) (ctx->buffer + left),
		         (uchar *) input, fill);
		sha256_process(ctx, ctx->buffer);
		length -= fill;
		input += fill;
		left = 0;
	}

	while(length >= 64) {
		sha256_process(ctx, input);
		length -= 64;
		input += 64;
	}

	if (length) {
		_memcpy_((uchar *) (ctx->buffer + left),
		         (uchar *) input, length);
	}
}

inline void SHA256_Final(SHA256_CTX *ctx, uchar digest[32])
{
	uchar sha256_padding[64] =
		{ 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	uint last, padn;
	uint high, low;
	uchar msglen[8];

	high = (ctx->total[0] >> 29)
		| (ctx->total[1] << 3);
	low = (ctx->total[0] << 3);

	PUT_UINT32(high, msglen, 0);
	PUT_UINT32(low, msglen, 4);

	last = ctx->total[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	SHA256_Update(ctx, sha256_padding, padn);
	SHA256_Update(ctx, msglen, 8);

	PUT_UINT32(ctx->state[0], digest, 0);
	PUT_UINT32(ctx->state[1], digest, 4);
	PUT_UINT32(ctx->state[2], digest, 8);
	PUT_UINT32(ctx->state[3], digest, 12);
	PUT_UINT32(ctx->state[4], digest, 16);
	PUT_UINT32(ctx->state[5], digest, 20);
	PUT_UINT32(ctx->state[6], digest, 24);
	PUT_UINT32(ctx->state[7], digest, 28);
}

#endif /* _OPENCL_SHA2_H */

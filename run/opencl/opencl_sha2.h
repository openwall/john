/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * and Copyright (c) 2014-2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _OPENCL_SHA2_H
#define _OPENCL_SHA2_H

#include "opencl_device_info.h"
#include "opencl_misc.h"

#define SHA256_LUT3 HAVE_LUT3
#define SHA512_LUT3 HAVE_LUT3_64

#if SHA256_LUT3
#define Ch(x, y, z) lut3(x, y, z, 0xca)
#elif USE_BITSELECT
#define Ch(x, y, z) bitselect(z, y, x)
#elif HAVE_ANDNOT
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#endif

#if SHA256_LUT3
#define Maj(x, y, z) lut3(x, y, z, 0xe8)
#elif USE_BITSELECT
#define Maj(x, y, z) bitselect(x, y, z ^ x)
#else
#define Maj(x, y, z) ((x & y) | (z & (x | y)))
#endif

#define ror(x, n)	rotate(x, 32U-(n))

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

#if 0 && SHA256_LUT3
/* LOP3.LUT alternative - does no good */
#define Sigma0(x) lut3(ror(x, 2), ror(x, 13), ror(x, 22), 0x96)
#define Sigma1(x) lut3(ror(x, 6), ror(x, 11), ror(x, 25), 0x96)
#elif gpu_nvidia(DEVICE_INFO)
/*
 * These Sigma alternatives are from "Fast SHA-256 Implementations on Intel
 * Architecture Processors" whitepaper by Intel. They were intended for use
 * with destructive rotate (minimizing register copies) but might be better
 * or worse on different hardware for other reasons.
 */
#define Sigma0(x) (ror(ror(ror(x, 9) ^ x, 11) ^ x, 2))
#define Sigma1(x) (ror(ror(ror(x, 14) ^ x, 5) ^ x, 6))
#else
/* Original SHA-2 function */
#define Sigma0(x) (ror(x, 2) ^ ror(x, 13) ^ ror(x, 22))
#define Sigma1(x) (ror(x, 6) ^ ror(x, 11) ^ ror(x, 25))
#endif

#if 0 && SHA256_LUT3
/* LOP3.LUT alternative - does no good */
#define sigma0(x) lut3(ror(x, 7), ror(x, 18), (x >> 3), 0x96)
#define sigma1(x) lut3(ror(x, 17), ror(x, 19), (x >> 10), 0x96)
#elif 0
/*
 * These sigma alternatives are derived from "Fast SHA-512 Implementations
 * on Intel Architecture Processors" whitepaper by Intel (rewritten here
 * for SHA-256 by magnum). They were intended for use with destructive shifts
 * (minimizing register copies) but might be better or worse on different
 * hardware for other reasons. They will likely always be a regression when
 * we have hardware rotate instructions.
 */
#define sigma0(x) ((((((x >> 11) ^ x) >> 4) ^ x) >> 3) ^ (((x << 11) ^ x) << 14))
#define sigma1(x) ((((((x >> 2) ^ x) >> 7) ^ x) >> 10) ^ (((x << 2) ^ x) << 13))
#else
/* Original SHA-2 function */
#define sigma0(x) (ror(x, 7) ^ ror(x, 18) ^ (x >> 3))
#define sigma1(x) (ror(x, 17) ^ ror(x, 19) ^ (x >> 10))
#endif

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

#define SHA256(A,B,C,D,E,F,G,H,W)	  \
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
	ROUND_B(A,B,C,D,E,F,G,H,k[16],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[17],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[18],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[19],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[20],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[21],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[22],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[23],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[24],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[25],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[26],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[27],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[28],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[29],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[30],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[31],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[32],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[33],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[34],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[35],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[36],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[37],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[38],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[39],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[40],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[41],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[42],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[43],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[44],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[45],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[46],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[47],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[48],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[49],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[50],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[51],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[52],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[53],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[54],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[55],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[56],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[57],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[58],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[59],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[60],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[61],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[62],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[63],W[15],  W[13],W[0],W[15],W[8])

#define Z (0)
//W[9]-W[14] are zeros
#define SHA256_ZEROS(A,B,C,D,E,F,G,H,W)	  \
	ROUND_A(A,B,C,D,E,F,G,H,k[0],W[0]); \
	ROUND_A(H,A,B,C,D,E,F,G,k[1],W[1]); \
	ROUND_A(G,H,A,B,C,D,E,F,k[2],W[2]); \
	ROUND_A(F,G,H,A,B,C,D,E,k[3],W[3]); \
	ROUND_A(E,F,G,H,A,B,C,D,k[4],W[4]); \
	ROUND_A(D,E,F,G,H,A,B,C,k[5],W[5]); \
	ROUND_A(C,D,E,F,G,H,A,B,k[6],W[6]); \
	ROUND_A(B,C,D,E,F,G,H,A,k[7],W[7]); \
	ROUND_A(A,B,C,D,E,F,G,H,k[8],W[8]); \
	ROUND_Z(H,A,B,C,D,E,F,G,k[9]); \
	ROUND_Z(G,H,A,B,C,D,E,F,k[10]); \
	ROUND_Z(F,G,H,A,B,C,D,E,k[11]); \
	ROUND_Z(E,F,G,H,A,B,C,D,k[12]); \
	ROUND_Z(D,E,F,G,H,A,B,C,k[13]); \
	ROUND_Z(C,D,E,F,G,H,A,B,k[14]); \
	ROUND_A(B,C,D,E,F,G,H,A,k[15],W[15]); \
	ROUND_I(A,B,C,D,E,F,G,H,k[16],W[0],  Z,W[1],W[0],Z) \
	ROUND_J(H,A,B,C,D,E,F,G,k[17],W[1],  W[15],W[2],W[1],Z) \
	ROUND_J(G,H,A,B,C,D,E,F,k[18],W[2],  W[0],W[3],W[2],Z) \
	ROUND_J(F,G,H,A,B,C,D,E,k[19],W[3],  W[1],W[4],W[3],Z) \
	ROUND_J(E,F,G,H,A,B,C,D,k[20],W[4],  W[2],W[5],W[4],Z) \
	ROUND_J(D,E,F,G,H,A,B,C,k[21],W[5],  W[3],W[6],W[5],Z) \
	ROUND_B(C,D,E,F,G,H,A,B,k[22],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[23],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_K(A,B,C,D,E,F,G,H,k[24],W[8],  W[6],Z,W[8],W[1]) \
	ROUND_L(H,A,B,C,D,E,F,G,k[25],W[9],  W[7],Z,Z,W[2]) \
	ROUND_L(G,H,A,B,C,D,E,F,k[26],W[10],  W[8],Z,Z,W[3]) \
	ROUND_L(F,G,H,A,B,C,D,E,k[27],W[11],  W[9],Z,Z,W[4]) \
	ROUND_L(E,F,G,H,A,B,C,D,k[28],W[12],  W[10],Z,Z,W[5]) \
	ROUND_L(D,E,F,G,H,A,B,C,k[29],W[13],  W[11],Z,Z,W[6]) \
	ROUND_M(C,D,E,F,G,H,A,B,k[30],W[14],  W[12],W[15],Z,W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[31],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[32],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[33],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[34],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[35],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[36],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[37],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[38],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[39],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[40],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[41],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[42],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[43],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[44],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[45],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[46],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[47],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[48],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[49],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[50],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[51],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[52],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[53],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[54],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[55],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[56],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[57],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[58],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[59],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[60],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[61],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[62],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[63],W[15],  W[13],W[0],W[15],W[8])

#define sha256_init(ctx)	  \
	{ \
		uint i; \
		for (i = 0; i < 8; i++) \
			(ctx)[i] = h[i]; \
	}

#define sha256_block(pad, ctx)\
 {	  \
	uint A, B, C, D, E, F, G, H, t; \
	A = (ctx)[0]; \
	B = (ctx)[1]; \
	C = (ctx)[2]; \
	D = (ctx)[3]; \
	E = (ctx)[4]; \
	F = (ctx)[5]; \
	G = (ctx)[6]; \
	H = (ctx)[7]; \
	SHA256(A,B,C,D,E,F,G,H,pad); \
	(ctx)[0] += A; \
	(ctx)[1] += B; \
	(ctx)[2] += C; \
	(ctx)[3] += D; \
	(ctx)[4] += E; \
	(ctx)[5] += F; \
	(ctx)[6] += G; \
	(ctx)[7] += H; \
}

#define sha256_block_zeros(pad, ctx)\
 {	  \
	uint A, B, C, D, E, F, G, H, t; \
	A = (ctx)[0]; \
	B = (ctx)[1]; \
	C = (ctx)[2]; \
	D = (ctx)[3]; \
	E = (ctx)[4]; \
	F = (ctx)[5]; \
	G = (ctx)[6]; \
	H = (ctx)[7]; \
	SHA256_ZEROS(A,B,C,D,E,F,G,H,pad); \
	(ctx)[0] += A; \
	(ctx)[1] += B; \
	(ctx)[2] += C; \
	(ctx)[3] += D; \
	(ctx)[4] += E; \
	(ctx)[5] += F; \
	(ctx)[6] += G; \
	(ctx)[7] += H; \
}

/*
 ***************************************************************************
 * SHA512 below this line
 ***************************************************************************
 */

#undef Maj
#undef Ch

#if SHA512_LUT3
#define Ch(x, y, z) lut3_64(x, y, z, 0xca)
#elif USE_BITSELECT
#define Ch(x, y, z) bitselect(z, y, x)
#elif HAVE_ANDNOT
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#endif

#if SHA512_LUT3
#define Maj(x, y, z) lut3_64(x, y, z, 0xe8)
#elif USE_BITSELECT
#define Maj(x, y, z) bitselect(x, y, z ^ x)
#else
#define Maj(x, y, z) ((x & y) | (z & (x | y)))
#endif

__constant ulong K[] = {
	0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL,
	0xe9b5dba58189dbbcUL, 0x3956c25bf348b538UL, 0x59f111f1b605d019UL,
	0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL, 0xd807aa98a3030242UL,
	0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
	0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL,
	0xc19bf174cf692694UL, 0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL,
	0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL, 0x2de92c6f592b0275UL,
	0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
	0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL,
	0xbf597fc7beef0ee4UL, 0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL,
	0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL,
	0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
	0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL,
	0x92722c851482353bUL, 0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL,
	0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL, 0xd192e819d6ef5218UL,
	0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
	0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL,
	0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL,
	0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL,
	0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
	0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL,
	0xc67178f2e372532bUL, 0xca273eceea26619cUL, 0xd186b8c721c0c207UL,
	0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL, 0x06f067aa72176fbaUL,
	0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
	0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL,
	0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL,
	0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

#if gpu_amd(DEVICE_INFO) && SCALAR && defined(cl_amd_media_ops) && !__MESA__
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#define ror64(x, n)	((n) < 32 ? \
	 (amd_bitalign((uint)((x) >> 32), (uint)(x), (uint)(n)) | \
	  ((ulong)amd_bitalign((uint)(x), (uint)((x) >> 32), (uint)(n)) << 32)) \
	 : \
	 (amd_bitalign((uint)(x), (uint)((x) >> 32), (uint)(n) - 32) | \
	  ((ulong)amd_bitalign((uint)((x) >> 32), (uint)(x), (uint)(n) - 32) << 32)))
#elif __OS_X__ && gpu_nvidia(DEVICE_INFO)
/* Bug workaround for OSX nvidia 10.2.7 310.41.25f01 */
#define ror64(x, n)       ((x >> n) | (x << (64 - n)))
#else
#define ror64(x, n)       rotate(x, (ulong)(64 - n))
#endif

#if 0 && SHA512_LUT3
/* LOP3.LUT alternative - does no good */
#define Sigma0_64(x) lut3_64(ror64(x, 28), ror64(x, 34), ror64(x, 39), 0x96)
#define Sigma1_64(x) lut3_64(ror64(x, 14), ror64(x, 18), ror64(x, 41), 0x96)
#elif 0
/*
 * These Sigma alternatives are derived from "Fast SHA-256 Implementations
 * on Intel Architecture Processors" whitepaper by Intel (rewritten here
 * for SHA-512 by magnum). They were intended for use with destructive rotate
 * (minimizing register copies) but might be better or worse on different
 * hardware for other reasons.
 */
#define Sigma0_64(x) (ror64(ror64(ror64(x, 5) ^ x, 6) ^ x, 28))
#define Sigma1_64(x) (ror64(ror64(ror64(x, 23) ^ x, 4) ^ x, 14))
#else
/* Original SHA-2 function */
#define Sigma0_64(x) (ror64(x, 28) ^ ror64(x, 34) ^ ror64(x, 39))
#define Sigma1_64(x) (ror64(x, 14) ^ ror64(x, 18) ^ ror64(x, 41))
#endif

#if 0 && SHA512_LUT3
/* LOP3.LUT alternative - does no good */
#define sigma0_64(x) lut3_64(ror64(x, 1), ror64(x, 8), (x >> 7), 0x96)
#define sigma1_64(x) lut3_64(ror64(x, 19), ror64(x, 61), (x >> 6), 0x96)
#elif 0
/*
 * These sigma alternatives are from "Fast SHA-512 Implementations on Intel
 * Architecture Processors" whitepaper by Intel. They were intended for use
 * with destructive shifts (minimizing register copies) but might be better
 * or worse on different hardware for other reasons. They will likely always
 * be a regression when we have 64-bit hardware rotate instructions - but
 * that probably doesn't exist for current GPU's as of now since they're all
 * 32-bit (and may not even have 32-bit rotate for that matter).
 */
#define sigma0_64(x) ((((((x >> 1) ^ x) >> 6) ^ x) >> 1) ^ (((x << 7) ^ x) << 56))
#define sigma1_64(x) ((((((x >> 42) ^ x) >> 13) ^ x) >> 6) ^ (((x << 42) ^ x) << 3))
#else
/* Original SHA-2 function */
#define sigma0_64(x) (ror64(x, 1)  ^ ror64(x, 8) ^ (x >> 7))
#define sigma1_64(x) (ror64(x, 19) ^ ror64(x, 61) ^ (x >> 6))
#endif

#define SHA2_INIT_A	0x6a09e667f3bcc908UL
#define SHA2_INIT_B	0xbb67ae8584caa73bUL
#define SHA2_INIT_C	0x3c6ef372fe94f82bUL
#define SHA2_INIT_D	0xa54ff53a5f1d36f1UL
#define SHA2_INIT_E	0x510e527fade682d1UL
#define SHA2_INIT_F	0x9b05688c2b3e6c1fUL
#define SHA2_INIT_G	0x1f83d9abfb41bd6bUL
#define SHA2_INIT_H	0x5be0cd19137e2179UL

#define ROUND512_A(a, b, c, d, e, f, g, h, ki, wi)	\
	t = (ki) + (wi) + (h) + Sigma1_64(e) + Ch((e), (f), (g)); \
	d += (t); h = (t) + Sigma0_64(a) + Maj((a), (b), (c));

#define ROUND512_Z(a, b, c, d, e, f, g, h, ki)	\
	t = (ki) + (h) + Sigma1_64(e) + Ch((e), (f), (g)); \
	d += (t); h = (t) + Sigma0_64(a) + Maj((a), (b), (c));

#define ROUND512_B(a, b, c, d, e, f, g, h, ki, wi, wj, wk, wl, wm)	  \
	wi = sigma1_64(wj) + sigma0_64(wk) + wl + wm; \
	t = (ki) + (wi) + (h) + Sigma1_64(e) + Ch((e), (f), (g)); \
	d += (t); h = (t) + Sigma0_64(a) + Maj((a), (b), (c));

#define SHA512(A, B, C, D, E, F, G, H, W)	  \
	ROUND512_A(A,B,C,D,E,F,G,H,K[0],W[0]) \
	ROUND512_A(H,A,B,C,D,E,F,G,K[1],W[1]) \
	ROUND512_A(G,H,A,B,C,D,E,F,K[2],W[2]) \
	ROUND512_A(F,G,H,A,B,C,D,E,K[3],W[3]) \
	ROUND512_A(E,F,G,H,A,B,C,D,K[4],W[4]) \
	ROUND512_A(D,E,F,G,H,A,B,C,K[5],W[5]) \
	ROUND512_A(C,D,E,F,G,H,A,B,K[6],W[6]) \
	ROUND512_A(B,C,D,E,F,G,H,A,K[7],W[7]) \
	ROUND512_A(A,B,C,D,E,F,G,H,K[8],W[8]) \
	ROUND512_A(H,A,B,C,D,E,F,G,K[9],W[9]) \
	ROUND512_A(G,H,A,B,C,D,E,F,K[10],W[10]) \
	ROUND512_A(F,G,H,A,B,C,D,E,K[11],W[11]) \
	ROUND512_A(E,F,G,H,A,B,C,D,K[12],W[12]) \
	ROUND512_A(D,E,F,G,H,A,B,C,K[13],W[13]) \
	ROUND512_A(C,D,E,F,G,H,A,B,K[14],W[14]) \
	ROUND512_A(B,C,D,E,F,G,H,A,K[15],W[15]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[16],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[17],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[18],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[19],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[20],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[21],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[22],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[23],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[24],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[25],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[26],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[27],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[28],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[29],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[30],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[31],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[32],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[33],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[34],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[35],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[36],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[37],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[38],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[39],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[40],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[41],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[42],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[43],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[44],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[45],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[46],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[47],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[48],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[49],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[50],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[51],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[52],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[53],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[54],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[55],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[56],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[57],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[58],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[59],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[60],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[61],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[62],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[63],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[64],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[65],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[66],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[67],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[68],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[69],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[70],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[71],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[72],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[73],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[74],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[75],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[76],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[77],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[78],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[79],W[15],  W[13],W[0],W[15],W[8])

#define z 0UL
//W[9]-W[14] are zeros
#define SHA512_ZEROS(A, B, C, D, E, F, G, H, W)	  \
	ROUND512_A(A,B,C,D,E,F,G,H,K[0],W[0]) \
	ROUND512_A(H,A,B,C,D,E,F,G,K[1],W[1]) \
	ROUND512_A(G,H,A,B,C,D,E,F,K[2],W[2]) \
	ROUND512_A(F,G,H,A,B,C,D,E,K[3],W[3]) \
	ROUND512_A(E,F,G,H,A,B,C,D,K[4],W[4]) \
	ROUND512_A(D,E,F,G,H,A,B,C,K[5],W[5]) \
	ROUND512_A(C,D,E,F,G,H,A,B,K[6],W[6]) \
	ROUND512_A(B,C,D,E,F,G,H,A,K[7],W[7]) \
	ROUND512_A(A,B,C,D,E,F,G,H,K[8],W[8]) \
	ROUND512_Z(H,A,B,C,D,E,F,G,K[9]) \
	ROUND512_Z(G,H,A,B,C,D,E,F,K[10]) \
	ROUND512_Z(F,G,H,A,B,C,D,E,K[11]) \
	ROUND512_Z(E,F,G,H,A,B,C,D,K[12]) \
	ROUND512_Z(D,E,F,G,H,A,B,C,K[13]) \
	ROUND512_Z(C,D,E,F,G,H,A,B,K[14]) \
	ROUND512_A(B,C,D,E,F,G,H,A,K[15],W[15]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[16],W[0],  z,W[1],W[0],z) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[17],W[1],  W[15],W[2],W[1],z) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[18],W[2],  W[0],W[3],W[2],z) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[19],W[3],  W[1],W[4],W[3],z) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[20],W[4],  W[2],W[5],W[4],z) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[21],W[5],  W[3],W[6],W[5],z) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[22],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[23],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[24],W[8],  W[6],z,W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[25],W[9],  W[7],z,z,W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[26],W[10],  W[8],z,z,W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[27],W[11],  W[9],z,z,W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[28],W[12],  W[10],z,z,W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[29],W[13],  W[11],z,z,W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[30],W[14],  W[12],W[15],z,W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[31],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[32],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[33],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[34],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[35],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[36],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[37],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[38],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[39],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[40],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[41],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[42],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[43],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[44],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[45],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[46],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[47],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[48],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[49],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[50],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[51],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[52],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[53],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[54],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[55],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[56],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[57],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[58],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[59],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[60],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[61],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[62],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[63],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[64],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[65],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[66],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[67],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[68],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[69],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[70],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[71],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[72],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[73],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[74],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[75],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[76],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[77],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[78],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[79],W[15],  W[13],W[0],W[15],W[8])

#ifdef SCALAR
#define sha512_single_s		sha512_single
#else

/* Raw'n'lean single-block SHA-512, no context[tm] */
inline void sha512_single_s(ulong *W, ulong *output)
{
	ulong A, B, C, D, E, F, G, H, t;

	A = SHA2_INIT_A;
	B = SHA2_INIT_B;
	C = SHA2_INIT_C;
	D = SHA2_INIT_D;
	E = SHA2_INIT_E;
	F = SHA2_INIT_F;
	G = SHA2_INIT_G;
	H = SHA2_INIT_H;

	SHA512(A, B, C, D, E, F, G, H, W)

	output[0] = A + SHA2_INIT_A;
	output[1] = B + SHA2_INIT_B;
	output[2] = C + SHA2_INIT_C;
	output[3] = D + SHA2_INIT_D;
	output[4] = E + SHA2_INIT_E;
	output[5] = F + SHA2_INIT_F;
	output[6] = G + SHA2_INIT_G;
	output[7] = H + SHA2_INIT_H;
}
#endif

/* Raw'n'lean single-block SHA-512, no context[tm] */
inline void sha512_single(MAYBE_VECTOR_ULONG *W, MAYBE_VECTOR_ULONG *output)
{
	MAYBE_VECTOR_ULONG A, B, C, D, E, F, G, H, t;

	A = SHA2_INIT_A;
	B = SHA2_INIT_B;
	C = SHA2_INIT_C;
	D = SHA2_INIT_D;
	E = SHA2_INIT_E;
	F = SHA2_INIT_F;
	G = SHA2_INIT_G;
	H = SHA2_INIT_H;

	SHA512(A, B, C, D, E, F, G, H, W)

	output[0] = A + SHA2_INIT_A;
	output[1] = B + SHA2_INIT_B;
	output[2] = C + SHA2_INIT_C;
	output[3] = D + SHA2_INIT_D;
	output[4] = E + SHA2_INIT_E;
	output[5] = F + SHA2_INIT_F;
	output[6] = G + SHA2_INIT_G;
	output[7] = H + SHA2_INIT_H;
}

inline void sha512_single_zeros(MAYBE_VECTOR_ULONG *W,
                                MAYBE_VECTOR_ULONG *output)
{
	MAYBE_VECTOR_ULONG A, B, C, D, E, F, G, H, t;

	A = SHA2_INIT_A;
	B = SHA2_INIT_B;
	C = SHA2_INIT_C;
	D = SHA2_INIT_D;
	E = SHA2_INIT_E;
	F = SHA2_INIT_F;
	G = SHA2_INIT_G;
	H = SHA2_INIT_H;

	SHA512_ZEROS(A, B, C, D, E, F, G, H, W)

	output[0] = A + SHA2_INIT_A;
	output[1] = B + SHA2_INIT_B;
	output[2] = C + SHA2_INIT_C;
	output[3] = D + SHA2_INIT_D;
	output[4] = E + SHA2_INIT_E;
	output[5] = F + SHA2_INIT_F;
	output[6] = G + SHA2_INIT_G;
	output[7] = H + SHA2_INIT_H;
}

#endif /* _OPENCL_SHA2_H */

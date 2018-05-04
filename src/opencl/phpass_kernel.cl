/*
 * This software is
 * Copyright (c) 2018 magnum
 * Copyright (c) 2011,2012 Lukas Odzioba <ukasz at openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifndef V_WIDTH
#error V_WIDTH must be defined
#endif
#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

#include "opencl_misc.h"

typedef struct {
	uint v[(PLAINTEXT_LENGTH + 3) / 4];
	uint length;
} phpass_password;

typedef struct {
	uint v[4];
} phpass_hash;


#define H(x, y, z)              (((x) ^ (y)) ^ (z))
#define H2(x, y, z)             ((x) ^ ((y) ^ (z)))
#define I(x, y, z)              ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, s)       rotate(x,(uint)s)
#define F(x, y, z) bitselect((z), (y), (x))
#define G(x, y, z) bitselect((y), (x), (z))

#define FF(v, w, x, y, z, s, ac)	  \
	v = ROTATE_LEFT(v + z + ac + F(w, x, y), (uint)s) + w

#define FF2(v, w, x, y, s, ac)	  \
	v = ROTATE_LEFT(v + ac + F(w, x, y), s) + w

#define GG(v, w, x, y, z, s, ac)	  \
	v = ROTATE_LEFT(v + z + ac + G(w, x, y), (uint)s) + w;

#define GG2(v, w, x, y, s, ac)	  \
	v = ROTATE_LEFT(v + ac + G(w, x, y), s) + w

#define HH(v, w, x, y, z, s, ac)	  \
	v = ROTATE_LEFT(v + z + ac + H(w, x, y), (uint)s) + w;

#define HH2(v, w, x, y, s, ac) 	  \
	v = ROTATE_LEFT(v + ac + H(w, x, y), s) + w

#define HHH(v, w, x, y, z, s, ac)	  \
	v = ROTATE_LEFT(v + z + ac + H2(w, x, y), (uint)s) + w;

#define II(v, w, x, y, z, s, ac)	  \
	v = ROTATE_LEFT(v + z + ac + I(w, x, y), (uint)s) + w;

#define II2(v, w, x, y, s, ac)	  \
	v = ROTATE_LEFT(v + ac + I(w, x, y), s) + w

#define S11                             7
#define S12                             12
#define S13                             17
#define S14                             22
#define S21                             5
#define S22                             9
#define S23                             14
#define S24                             20
#define S31                             4
#define S32                             11
#define S33                             16
#define S34                             23
#define S41                             6
#define S42                             10
#define S43                             15
#define S44                             21

#define AC1                             0xd76aa477
#define AC2pCd                          0xf8fa0bcc
#define AC3pCc                          0xbcdb4dd9
#define AC4pCb                          0xb18b7a77
#define MASK1                           0x77777777

inline void md5(MAYBE_VECTOR_UINT len,
                __private MAYBE_VECTOR_UINT *internal_ret,
                __private MAYBE_VECTOR_UINT *x)
{
	MAYBE_VECTOR_UINT x14 = len << 3;

	MAYBE_VECTOR_UINT a;
	MAYBE_VECTOR_UINT b = 0xefcdab89;
	MAYBE_VECTOR_UINT c = 0x98badcfe;
	MAYBE_VECTOR_UINT d;        // = 0x10325476;

	a = AC1 + x[0];
	a = ROTATE_LEFT(a, S11);
	a += b;                     /* 1 */
	d = (c ^ (a & MASK1)) + x[1] + AC2pCd;
	d = ROTATE_LEFT(d, S12);
	d += a;                     /* 2 */
	c = F(d, a, b) + x[2] + AC3pCc;
	c = ROTATE_LEFT(c, S13);
	c += d;                     /* 3 */
	b = F(c, d, a) + x[3] + AC4pCb;
	b = ROTATE_LEFT(b, S14);
	b += c;
	FF(a, b, c, d, x[4], S11, 0xf57c0faf);
	FF(d, a, b, c, x[5], S12, 0x4787c62a);
	FF(c, d, a, b, x[6], S13, 0xa8304613);
	FF(b, c, d, a, x[7], S14, 0xfd469501);
	FF(a, b, c, d, x[8], S11, 0x698098d8);
	FF(d, a, b, c, x[9], S12, 0x8b44f7af);
	FF(c, d, a, b, x[10], S13, 0xffff5bb1);
	FF(b, c, d, a, x[11], S14, 0x895cd7be);
	FF(a, b, c, d, x[12], S11, 0x6b901122);
	FF(d, a, b, c, x[13], S12, 0xfd987193);
	FF(c, d, a, b, x14, S13, 0xa679438e);
	FF2(b, c, d, a, S14, 0x49b40821);

	GG(a, b, c, d, x[1], S21, 0xf61e2562);
	GG(d, a, b, c, x[6], S22, 0xc040b340);
	GG(c, d, a, b, x[11], S23, 0x265e5a51);
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
	GG(a, b, c, d, x[5], S21, 0xd62f105d);
	GG(d, a, b, c, x[10], S22, 0x2441453);
	GG2(c, d, a, b, S23, 0xd8a1e681);
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
	GG(a, b, c, d, x[9], S21, 0x21e1cde6);
	GG(d, a, b, c, x14, S22, 0xc33707d6);
	GG(c, d, a, b, x[3], S23, 0xf4d50d87);
	GG(b, c, d, a, x[8], S24, 0x455a14ed);
	GG(a, b, c, d, x[13], S21, 0xa9e3e905);
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
	GG(c, d, a, b, x[7], S23, 0x676f02d9);
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

	HH(a, b, c, d, x[5], S31, 0xfffa3942);
	HHH(d, a, b, c, x[8], S32, 0x8771f681);
	HH(c, d, a, b, x[11], S33, 0x6d9d6122);
	HHH(b, c, d, a, x14, S34, 0xfde5380c);
	HH(a, b, c, d, x[1], S31, 0xa4beea44);
	HHH(d, a, b, c, x[4], S32, 0x4bdecfa9);
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60);
	HHH(b, c, d, a, x[10], S34, 0xbebfbc70);
	HH(a, b, c, d, x[13], S31, 0x289b7ec6);
	HHH(d, a, b, c, x[0], S32, 0xeaa127fa);
	HH(c, d, a, b, x[3], S33, 0xd4ef3085);
	HHH(b, c, d, a, x[6], S34, 0x4881d05);
	HH(a, b, c, d, x[9], S31, 0xd9d4d039);
	HHH(d, a, b, c, x[12], S32, 0xe6db99e5);
	HH2(c, d, a, b, S33, 0x1fa27cf8);
	HHH(b, c, d, a, x[2], S34, 0xc4ac5665);

	II(a, b, c, d, x[0], S41, 0xf4292244);
	II(d, a, b, c, x[7], S42, 0x432aff97);
	II(c, d, a, b, x14, S43, 0xab9423a7);
	II(b, c, d, a, x[5], S44, 0xfc93a039);
	II(a, b, c, d, x[12], S41, 0x655b59c3);
	II(d, a, b, c, x[3], S42, 0x8f0ccc92);
	II(c, d, a, b, x[10], S43, 0xffeff47d);
	II(b, c, d, a, x[1], S44, 0x85845dd1);
	II(a, b, c, d, x[8], S41, 0x6fa87e4f);
	II2(d, a, b, c, S42, 0xfe2ce6e0);
	II(c, d, a, b, x[6], S43, 0xa3014314);
	II(b, c, d, a, x[13], S44, 0x4e0811a1);
	II(a, b, c, d, x[4], S41, 0xf7537e82);
	II(d, a, b, c, x[11], S42, 0xbd3af235);
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb);
	II(b, c, d, a, x[9], S44, 0xeb86d391);

	internal_ret[0] = a + 0x67452301;
	internal_ret[1] = b + 0xefcdab89;
	internal_ret[2] = c + 0x98badcfe;
	internal_ret[3] = d + 0x10325476;
}

__kernel void phpass (__global const phpass_password *data,
                      __global phpass_hash *data_out,
                      __global const uint *salt)
{
	MAYBE_VECTOR_UINT x[14], length;
	uint i, idx = get_global_id(0);
	uint count = salt[2];

	__global const uint *password0 = data[idx * V_WIDTH +  0].v;
#if V_WIDTH > 1
	__global const uint *password1 = data[idx * V_WIDTH +  1].v;
#if V_WIDTH > 2
	__global const uint *password2 = data[idx * V_WIDTH +  2].v;
#if V_WIDTH > 3
	__global const uint *password3 = data[idx * V_WIDTH +  3].v;
#if V_WIDTH > 4
	__global const uint *password4 = data[idx * V_WIDTH +  4].v;
	__global const uint *password5 = data[idx * V_WIDTH +  5].v;
	__global const uint *password6 = data[idx * V_WIDTH +  6].v;
	__global const uint *password7 = data[idx * V_WIDTH +  7].v;
#if V_WIDTH > 8
	__global const uint *password8 = data[idx * V_WIDTH +  8].v;
	__global const uint *password9 = data[idx * V_WIDTH +  9].v;
	__global const uint *passworda = data[idx * V_WIDTH + 10].v;
	__global const uint *passwordb = data[idx * V_WIDTH + 11].v;
	__global const uint *passwordc = data[idx * V_WIDTH + 12].v;
	__global const uint *passwordd = data[idx * V_WIDTH + 13].v;
	__global const uint *passworde = data[idx * V_WIDTH + 14].v;
	__global const uint *passwordf = data[idx * V_WIDTH + 15].v;
#endif
#endif
#endif
#endif
#endif

#ifdef SCALAR
	length = (uint)data[idx].length;
#else
	length.s0 = (uint)data[idx * V_WIDTH +  0].length;
	length.s1 = (uint)data[idx * V_WIDTH +  1].length;
#if V_WIDTH > 2
	length.s2 = (uint)data[idx * V_WIDTH +  2].length;
#if V_WIDTH > 3
	length.s3 = (uint)data[idx * V_WIDTH +  3].length;
#if V_WIDTH > 4
	length.s4 = (uint)data[idx * V_WIDTH +  4].length;
	length.s5 = (uint)data[idx * V_WIDTH +  5].length;
	length.s6 = (uint)data[idx * V_WIDTH +  6].length;
	length.s7 = (uint)data[idx * V_WIDTH +  7].length;
#if V_WIDTH > 8
	length.s8 = (uint)data[idx * V_WIDTH +  8].length;
	length.s9 = (uint)data[idx * V_WIDTH +  9].length;
	length.sa = (uint)data[idx * V_WIDTH + 10].length;
	length.sb = (uint)data[idx * V_WIDTH + 11].length;
	length.sc = (uint)data[idx * V_WIDTH + 12].length;
	length.sd = (uint)data[idx * V_WIDTH + 13].length;
	length.se = (uint)data[idx * V_WIDTH + 14].length;
	length.sf = (uint)data[idx * V_WIDTH + 15].length;
#endif
#endif
#endif
#endif
#endif

#ifdef SCALAR
	for (i = 0; i < 2; i++)
		x[i] = salt[i];
	for (i = 0; i < 10; i++)
		x[2 + i] = password0[i];
	x[12] = x[13] = 0;
#else
#define K1(q)	  \
	for (i = 0; i < 2; i++) \
		x[i] = salt[i]; \
	for (i = 0; i < 10; i++) \
		x[2 + i].s##q = password##q[i];

	K1(0);
	K1(1);
#if V_WIDTH > 2
	K1(2);
#if V_WIDTH > 3
	K1(3);
#if V_WIDTH > 4
	K1(4);
	K1(5);
	K1(6);
	K1(7);
#if V_WIDTH > 8
	K1(8);
	K1(9);
	K1(a);
	K1(b);
	K1(c);
	K1(d);
	K1(e);
	K1(f);
#endif
#endif
#endif
#endif
	x[12] = x[13] = 0;
#endif
#undef K1

	MAYBE_VECTOR_UINT len = 8 + length;

#ifdef SCALAR
	x[len / 4] |= (((uint)0x80) << ((len & 0x3) << 3));
#else
	x[len.s0 / 4].s0 |= (((uint)0x80) << ((len.s0 & 0x3) << 3));
	x[len.s1 / 4].s1 |= (((uint)0x80) << ((len.s1 & 0x3) << 3));
#if V_WIDTH > 2
	x[len.s2 / 4].s2 |= (((uint)0x80) << ((len.s2 & 0x3) << 3));
#if V_WIDTH > 3
	x[len.s3 / 4].s3 |= (((uint)0x80) << ((len.s3 & 0x3) << 3));
#if V_WIDTH > 4
	x[len.s4 / 4].s4 |= (((uint)0x80) << ((len.s4 & 0x3) << 3));
	x[len.s5 / 4].s5 |= (((uint)0x80) << ((len.s5 & 0x3) << 3));
	x[len.s6 / 4].s6 |= (((uint)0x80) << ((len.s6 & 0x3) << 3));
	x[len.s7 / 4].s7 |= (((uint)0x80) << ((len.s7 & 0x3) << 3));
#if V_WIDTH > 8
	x[len.s8 / 4].s8 |= (((uint)0x80) << ((len.s8 & 0x3) << 3));
	x[len.s9 / 4].s9 |= (((uint)0x80) << ((len.s9 & 0x3) << 3));
	x[len.sa / 4].sa |= (((uint)0x80) << ((len.sa & 0x3) << 3));
	x[len.sb / 4].sb |= (((uint)0x80) << ((len.sb & 0x3) << 3));
	x[len.sc / 4].sc |= (((uint)0x80) << ((len.sc & 0x3) << 3));
	x[len.sd / 4].sd |= (((uint)0x80) << ((len.sd & 0x3) << 3));
	x[len.se / 4].se |= (((uint)0x80) << ((len.se & 0x3) << 3));
	x[len.sf / 4].sf |= (((uint)0x80) << ((len.sf & 0x3) << 3));
#endif
#endif
#endif
#endif
#endif

	md5(len, x, x);

#ifdef SCALAR
	for (i = 0; i < 10; i++)
		x[4 + i] = password0[i];
#else
#define K2(q)	  \
	for (i = 0; i < 10; i++) \
		x[4 + i].s##q = password##q[i];

	K2(0);
	K2(1);
#if V_WIDTH > 2
	K2(2);
#if V_WIDTH > 3
	K2(3);
#if V_WIDTH > 4
	K2(4);
	K2(5);
	K2(6);
	K2(7);
#if V_WIDTH > 8
	K2(8);
	K2(9);
	K2(a);
	K2(b);
	K2(c);
	K2(d);
	K2(e);
	K2(f);
#endif
#endif
#endif
#endif
#endif
#undef K2

	len = 16 + length;
#ifdef SCALAR
	x[len / 4] |= (((uint)0x80) << ((len & 0x3) << 3));
#else
	x[len.s0 / 4].s0 |= (((uint)0x80) << ((len.s0 & 0x3) << 3));
	x[len.s1 / 4].s1 |= (((uint)0x80) << ((len.s1 & 0x3) << 3));
#if V_WIDTH > 2
	x[len.s2 / 4].s2 |= (((uint)0x80) << ((len.s2 & 0x3) << 3));
#if V_WIDTH > 3
	x[len.s3 / 4].s3 |= (((uint)0x80) << ((len.s3 & 0x3) << 3));
#if V_WIDTH > 4
	x[len.s4 / 4].s4 |= (((uint)0x80) << ((len.s4 & 0x3) << 3));
	x[len.s5 / 4].s5 |= (((uint)0x80) << ((len.s5 & 0x3) << 3));
	x[len.s6 / 4].s6 |= (((uint)0x80) << ((len.s6 & 0x3) << 3));
	x[len.s7 / 4].s7 |= (((uint)0x80) << ((len.s7 & 0x3) << 3));
#if V_WIDTH > 8
	x[len.s8 / 4].s8 |= (((uint)0x80) << ((len.s8 & 0x3) << 3));
	x[len.s9 / 4].s9 |= (((uint)0x80) << ((len.s9 & 0x3) << 3));
	x[len.sa / 4].sa |= (((uint)0x80) << ((len.sa & 0x3) << 3));
	x[len.sb / 4].sb |= (((uint)0x80) << ((len.sb & 0x3) << 3));
	x[len.sc / 4].sc |= (((uint)0x80) << ((len.sc & 0x3) << 3));
	x[len.sd / 4].sd |= (((uint)0x80) << ((len.sd & 0x3) << 3));
	x[len.se / 4].se |= (((uint)0x80) << ((len.se & 0x3) << 3));
	x[len.sf / 4].sf |= (((uint)0x80) << ((len.sf & 0x3) << 3));
#endif
#endif
#endif
#endif
#endif

	MAYBE_VECTOR_UINT a, b, c, d;
	MAYBE_VECTOR_UINT x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13;
	MAYBE_VECTOR_UINT x14 = len << 3;

	x0 = x[0];
	x1 = x[1];
	x2 = x[2];
	x3 = x[3];
	x4 = x[4];
	x5 = x[5];
	x6 = x[6];
	x7 = x[7];
	x8 = x[8];
	x9 = x[9];
	x10 = x[10];
	x11 = x[11];
	x12 = x[12];
	x13 = x[13];

	do {
		b = 0xefcdab89;
		c = 0x98badcfe;
		//d = 0x10325476;

		a = AC1 + x0;
		a = ROTATE_LEFT(a, S11);
		a += b;                 /* 1 */
		d = (c ^ (a & MASK1)) + x1 + AC2pCd;
		d = ROTATE_LEFT(d, S12);
		d += a;                 /* 2 */
		c = F(d, a, b) + x2 + AC3pCc;
		c = ROTATE_LEFT(c, S13);
		c += d;                 /* 3 */
		b = F(c, d, a) + x3 + AC4pCb;
		b = ROTATE_LEFT(b, S14);
		b += c;
		FF(a, b, c, d, x4, S11, 0xf57c0faf);
		FF(d, a, b, c, x5, S12, 0x4787c62a);
		FF(c, d, a, b, x6, S13, 0xa8304613);
		FF(b, c, d, a, x7, S14, 0xfd469501);
		FF(a, b, c, d, x8, S11, 0x698098d8);
		FF(d, a, b, c, x9, S12, 0x8b44f7af);
		FF(c, d, a, b, x10, S13, 0xffff5bb1);
		FF(b, c, d, a, x11, S14, 0x895cd7be);
		FF(a, b, c, d, x12, S11, 0x6b901122);
		FF(d, a, b, c, x13, S12, 0xfd987193);
		FF(c, d, a, b, x14, S13, 0xa679438e);
		FF2(b, c, d, a, S14, 0x49b40821);

		GG(a, b, c, d, x1, S21, 0xf61e2562);
		GG(d, a, b, c, x6, S22, 0xc040b340);
		GG(c, d, a, b, x11, S23, 0x265e5a51);
		GG(b, c, d, a, x0, S24, 0xe9b6c7aa);
		GG(a, b, c, d, x5, S21, 0xd62f105d);
		GG(d, a, b, c, x10, S22, 0x2441453);
		GG2(c, d, a, b, S23, 0xd8a1e681);
		GG(b, c, d, a, x4, S24, 0xe7d3fbc8);
		GG(a, b, c, d, x9, S21, 0x21e1cde6);
		GG(d, a, b, c, x14, S22, 0xc33707d6);
		GG(c, d, a, b, x3, S23, 0xf4d50d87);
		GG(b, c, d, a, x8, S24, 0x455a14ed);
		GG(a, b, c, d, x13, S21, 0xa9e3e905);
		GG(d, a, b, c, x2, S22, 0xfcefa3f8);
		GG(c, d, a, b, x7, S23, 0x676f02d9);
		GG(b, c, d, a, x12, S24, 0x8d2a4c8a);

		HH(a, b, c, d, x5, S31, 0xfffa3942);
		HH(d, a, b, c, x8, S32, 0x8771f681);
		HH(c, d, a, b, x11, S33, 0x6d9d6122);
		HH(b, c, d, a, x14, S34, 0xfde5380c);
		HH(a, b, c, d, x1, S31, 0xa4beea44);
		HH(d, a, b, c, x4, S32, 0x4bdecfa9);
		HH(c, d, a, b, x7, S33, 0xf6bb4b60);
		HH(b, c, d, a, x10, S34, 0xbebfbc70);
		HH(a, b, c, d, x13, S31, 0x289b7ec6);
		HH(d, a, b, c, x0, S32, 0xeaa127fa);
		HH(c, d, a, b, x3, S33, 0xd4ef3085);
		HH(b, c, d, a, x6, S34, 0x4881d05);
		HH(a, b, c, d, x9, S31, 0xd9d4d039);
		HH(d, a, b, c, x12, S32, 0xe6db99e5);
		HH2(c, d, a, b, S33, 0x1fa27cf8);
		HH(b, c, d, a, x2, S34, 0xc4ac5665);

		II(a, b, c, d, x0, S41, 0xf4292244);
		II(d, a, b, c, x7, S42, 0x432aff97);
		II(c, d, a, b, x14, S43, 0xab9423a7);
		II(b, c, d, a, x5, S44, 0xfc93a039);
		II(a, b, c, d, x12, S41, 0x655b59c3);
		II(d, a, b, c, x3, S42, 0x8f0ccc92);
		II(c, d, a, b, x10, S43, 0xffeff47d);
		II(b, c, d, a, x1, S44, 0x85845dd1);
		II(a, b, c, d, x8, S41, 0x6fa87e4f);
		II2(d, a, b, c, S42, 0xfe2ce6e0);
		II(c, d, a, b, x6, S43, 0xa3014314);
		II(b, c, d, a, x13, S44, 0x4e0811a1);
		II(a, b, c, d, x4, S41, 0xf7537e82);
		II(d, a, b, c, x11, S42, 0xbd3af235);
		II(c, d, a, b, x2, S43, 0x2ad7d2bb);
		II(b, c, d, a, x9, S44, 0xeb86d391);

		x0 = a + 0x67452301;
		x1 = b + 0xefcdab89;
		x2 = c + 0x98badcfe;
		x3 = d + 0x10325476;
	} while (--count);

#ifdef SCALAR
	data_out[idx].v[0] = x0;
	data_out[idx].v[1] = x1;
	data_out[idx].v[2] = x2;
	data_out[idx].v[3] = x3;
#else
#define K3(q)	\
	data_out[idx * V_WIDTH + 0x##q].v[0] = x0.s##q; \
	data_out[idx * V_WIDTH + 0x##q].v[1] = x1.s##q; \
	data_out[idx * V_WIDTH + 0x##q].v[2] = x2.s##q; \
	data_out[idx * V_WIDTH + 0x##q].v[3] = x3.s##q;

	K3(0)
	K3(1)
#if V_WIDTH > 2
	K3(2)
#if V_WIDTH > 3
	K3(3)
#if V_WIDTH > 4
	K3(4)
	K3(5)
	K3(6)
	K3(7)
#if V_WIDTH > 8
	K3(8)
	K3(9)
	K3(a)
	K3(b)
	K3(c)
	K3(d)
	K3(e)
	K3(f)
#endif
#endif
#endif
#endif
#endif
#undef K3
}

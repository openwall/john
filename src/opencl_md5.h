/*
 * OpenCL MD5
 *
 * Copyright (c) 2014, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * NOTICE: After changes in headers, you probably need to drop cached
 * kernels to ensure the changes take effect.
 *
 */

#ifndef _OPENCL_MD5_H
#define _OPENCL_MD5_H

#include "opencl_misc.h"

#define MD5_LUT3 HAVE_LUT3

/* The basic MD5 functions */
#if MD5_LUT3
#define MD5_F(x, y, z)  lut3(x, y, z, 0xca)
#define MD5_G(x, y, z)  lut3(x, y, z, 0xe4)
#elif USE_BITSELECT
#define MD5_F(x, y, z)  bitselect(z, y, x)
#define MD5_G(x, y, z)  bitselect(y, x, z)
#else
#if HAVE_ANDNOT
#define MD5_F(x, y, z)  ((x & y) ^ ((~x) & z))
#else
#define MD5_F(x, y, z)  (z ^ (x & (y ^ z)))
#endif
#define MD5_G(x, y, z)  (y ^ (z & (x ^ y)))
#endif

#if MD5_LUT3
#define MD5_H(x, y, z)  lut3(x, y, z, 0x96)
#define MD5_H2 MD5_H
#else
#define MD5_H(x, y, z)  ((x ^ y) ^ z)
#define MD5_H2(x, y, z) (x ^ (y ^ z))
#endif

#if MD5_LUT3
#define MD5_I(x, y, z)  lut3(x, y, z, 0x39)
#elif USE_BITSELECT
#define MD5_I(x, y, z)  (y ^ bitselect(0xffffffffU, x, z))
#else
#define MD5_I(x, y, z)  (y ^ (x | ~z))
#endif

/* The MD5 transformation for all four rounds. */
#define MD5_STEP(f, a, b, c, d, x, t, s)	  \
	(a) += f((b), (c), (d)) + (x) + (t); \
	    (a) = rotate((a), (uint)(s)); \
	    (a) += (b)

#define MD5(a, b, c, d, W)	  \
	MD5_STEP(MD5_F, a, b, c, d, W[0], 0xd76aa478, 7); \
	MD5_STEP(MD5_F, d, a, b, c, W[1], 0xe8c7b756, 12); \
	MD5_STEP(MD5_F, c, d, a, b, W[2], 0x242070db, 17); \
	MD5_STEP(MD5_F, b, c, d, a, W[3], 0xc1bdceee, 22); \
	MD5_STEP(MD5_F, a, b, c, d, W[4], 0xf57c0faf, 7); \
	MD5_STEP(MD5_F, d, a, b, c, W[5], 0x4787c62a, 12); \
	MD5_STEP(MD5_F, c, d, a, b, W[6], 0xa8304613, 17); \
	MD5_STEP(MD5_F, b, c, d, a, W[7], 0xfd469501, 22); \
	MD5_STEP(MD5_F, a, b, c, d, W[8], 0x698098d8, 7); \
	MD5_STEP(MD5_F, d, a, b, c, W[9], 0x8b44f7af, 12); \
	MD5_STEP(MD5_F, c, d, a, b, W[10], 0xffff5bb1, 17); \
	MD5_STEP(MD5_F, b, c, d, a, W[11], 0x895cd7be, 22); \
	MD5_STEP(MD5_F, a, b, c, d, W[12], 0x6b901122, 7); \
	MD5_STEP(MD5_F, d, a, b, c, W[13], 0xfd987193, 12); \
	MD5_STEP(MD5_F, c, d, a, b, W[14], 0xa679438e, 17); \
	MD5_STEP(MD5_F, b, c, d, a, W[15], 0x49b40821, 22); \
	MD5_STEP(MD5_G, a, b, c, d, W[1], 0xf61e2562, 5); \
	MD5_STEP(MD5_G, d, a, b, c, W[6], 0xc040b340, 9); \
	MD5_STEP(MD5_G, c, d, a, b, W[11], 0x265e5a51, 14); \
	MD5_STEP(MD5_G, b, c, d, a, W[0], 0xe9b6c7aa, 20); \
	MD5_STEP(MD5_G, a, b, c, d, W[5], 0xd62f105d, 5); \
	MD5_STEP(MD5_G, d, a, b, c, W[10], 0x02441453, 9); \
	MD5_STEP(MD5_G, c, d, a, b, W[15], 0xd8a1e681, 14); \
	MD5_STEP(MD5_G, b, c, d, a, W[4], 0xe7d3fbc8, 20); \
	MD5_STEP(MD5_G, a, b, c, d, W[9], 0x21e1cde6, 5); \
	MD5_STEP(MD5_G, d, a, b, c, W[14], 0xc33707d6, 9); \
	MD5_STEP(MD5_G, c, d, a, b, W[3], 0xf4d50d87, 14); \
	MD5_STEP(MD5_G, b, c, d, a, W[8], 0x455a14ed, 20); \
	MD5_STEP(MD5_G, a, b, c, d, W[13], 0xa9e3e905, 5); \
	MD5_STEP(MD5_G, d, a, b, c, W[2], 0xfcefa3f8, 9); \
	MD5_STEP(MD5_G, c, d, a, b, W[7], 0x676f02d9, 14); \
	MD5_STEP(MD5_G, b, c, d, a, W[12], 0x8d2a4c8a, 20); \
	MD5_STEP(MD5_H, a, b, c, d, W[5], 0xfffa3942, 4); \
	MD5_STEP(MD5_H2, d, a, b, c, W[8], 0x8771f681, 11); \
	MD5_STEP(MD5_H, c, d, a, b, W[11], 0x6d9d6122, 16); \
	MD5_STEP(MD5_H2, b, c, d, a, W[14], 0xfde5380c, 23); \
	MD5_STEP(MD5_H, a, b, c, d, W[1], 0xa4beea44, 4); \
	MD5_STEP(MD5_H2, d, a, b, c, W[4], 0x4bdecfa9, 11); \
	MD5_STEP(MD5_H, c, d, a, b, W[7], 0xf6bb4b60, 16); \
	MD5_STEP(MD5_H2, b, c, d, a, W[10], 0xbebfbc70, 23); \
	MD5_STEP(MD5_H, a, b, c, d, W[13], 0x289b7ec6, 4); \
	MD5_STEP(MD5_H2, d, a, b, c, W[0], 0xeaa127fa, 11); \
	MD5_STEP(MD5_H, c, d, a, b, W[3], 0xd4ef3085, 16); \
	MD5_STEP(MD5_H2, b, c, d, a, W[6], 0x04881d05, 23); \
	MD5_STEP(MD5_H, a, b, c, d, W[9], 0xd9d4d039, 4); \
	MD5_STEP(MD5_H2, d, a, b, c, W[12], 0xe6db99e5, 11); \
	MD5_STEP(MD5_H, c, d, a, b, W[15], 0x1fa27cf8, 16); \
	MD5_STEP(MD5_H2, b, c, d, a, W[2], 0xc4ac5665, 23); \
	MD5_STEP(MD5_I, a, b, c, d, W[0], 0xf4292244, 6); \
	MD5_STEP(MD5_I, d, a, b, c, W[7], 0x432aff97, 10); \
	MD5_STEP(MD5_I, c, d, a, b, W[14], 0xab9423a7, 15); \
	MD5_STEP(MD5_I, b, c, d, a, W[5], 0xfc93a039, 21); \
	MD5_STEP(MD5_I, a, b, c, d, W[12], 0x655b59c3, 6); \
	MD5_STEP(MD5_I, d, a, b, c, W[3], 0x8f0ccc92, 10); \
	MD5_STEP(MD5_I, c, d, a, b, W[10], 0xffeff47d, 15); \
	MD5_STEP(MD5_I, b, c, d, a, W[1], 0x85845dd1, 21); \
	MD5_STEP(MD5_I, a, b, c, d, W[8], 0x6fa87e4f, 6); \
	MD5_STEP(MD5_I, d, a, b, c, W[15], 0xfe2ce6e0, 10); \
	MD5_STEP(MD5_I, c, d, a, b, W[6], 0xa3014314, 15); \
	MD5_STEP(MD5_I, b, c, d, a, W[13], 0x4e0811a1, 21); \
	MD5_STEP(MD5_I, a, b, c, d, W[4], 0xf7537e82, 6); \
	MD5_STEP(MD5_I, d, a, b, c, W[11], 0xbd3af235, 10); \
	MD5_STEP(MD5_I, c, d, a, b, W[2], 0x2ad7d2bb, 15); \
	MD5_STEP(MD5_I, b, c, d, a, W[9], 0xeb86d391, 21)

#define md5_block(itype, W, ctx)	  \
	{ \
		itype a, b, c, d; \
		a = ctx[0]; \
		b = ctx[1]; \
		c = ctx[2]; \
		d = ctx[3]; \
		MD5(a, b, c, d, W); \
		ctx[0] += a; \
		ctx[1] += b; \
		ctx[2] += c; \
		ctx[3] += d; \
	}

#define md5_init(ctx) {	  \
		ctx[0] = 0x67452301; \
		ctx[1] = 0xefcdab89; \
		ctx[2] = 0x98badcfe; \
		ctx[3] = 0x10325476; \
	}

#define	md5_single(itype, W, out) { \
		itype a, b, c, d; \
		a = 0x67452301; \
		b = 0xefcdab89; \
		c = 0x98badcfe; \
		d = 0x10325476; \
		MD5(a, b, c, d, W); \
		out[0] = 0x67452301 + a; \
		out[1] = 0xefcdab89 + b; \
		out[2] = 0x98badcfe + c; \
		out[3] = 0x10325476 + d; \
	}

#endif

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

/* The basic MD5 functions */
#ifdef USE_BITSELECT
#define MD5_F(x, y, z)	bitselect((z), (y), (x))
#define MD5_G(x, y, z)	bitselect((y), (x), (z))
#else
#define MD5_F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#define MD5_G(x, y, z)	((y) ^ ((z) & ((x) ^ (y))))
#endif

#define MD5_H(x, y, z)	((x) ^ (y) ^ (z))
#define MD5_I(x, y, z)	((y) ^ ((x) | ~(z)))


/* The MD5 transformation for all four rounds. */
#define MD5_STEP(f, a, b, c, d, x, t, s)	  \
	(a) += f((b), (c), (d)) + (x) + (t); \
	    (a) = rotate((a), (uint)(s)); \
	    (a) += (b)


/*
 * Raw'n'lean MD5 with context in output buffer
 * NOTE: This version thrashes the input block!
 *
 * Needs caller to have these defined:
 *	uint a, b, c, d;
 *
 * or perhaps:
 *	MAYBE_VECTOR_UINT a, b, c, d;
 *
 */
#define md5_block(block, output)  \
	{ \
		a = output[0]; \
		b = output[1]; \
		c = output[2]; \
		d = output[3]; \
		MD5_STEP(MD5_F, a, b, c, d, block[0], 0xd76aa478, 7); \
		MD5_STEP(MD5_F, d, a, b, c, block[1], 0xe8c7b756, 12); \
		MD5_STEP(MD5_F, c, d, a, b, block[2], 0x242070db, 17); \
		MD5_STEP(MD5_F, b, c, d, a, block[3], 0xc1bdceee, 22); \
		MD5_STEP(MD5_F, a, b, c, d, block[4], 0xf57c0faf, 7); \
		MD5_STEP(MD5_F, d, a, b, c, block[5], 0x4787c62a, 12); \
		MD5_STEP(MD5_F, c, d, a, b, block[6], 0xa8304613, 17); \
		MD5_STEP(MD5_F, b, c, d, a, block[7], 0xfd469501, 22); \
		MD5_STEP(MD5_F, a, b, c, d, block[8], 0x698098d8, 7); \
		MD5_STEP(MD5_F, d, a, b, c, block[9], 0x8b44f7af, 12); \
		MD5_STEP(MD5_F, c, d, a, b, block[10], 0xffff5bb1, 17); \
		MD5_STEP(MD5_F, b, c, d, a, block[11], 0x895cd7be, 22); \
		MD5_STEP(MD5_F, a, b, c, d, block[12], 0x6b901122, 7); \
		MD5_STEP(MD5_F, d, a, b, c, block[13], 0xfd987193, 12); \
		MD5_STEP(MD5_F, c, d, a, b, block[14], 0xa679438e, 17); \
		MD5_STEP(MD5_F, b, c, d, a, block[15], 0x49b40821, 22); \
		MD5_STEP(MD5_G, a, b, c, d, block[1], 0xf61e2562, 5); \
		MD5_STEP(MD5_G, d, a, b, c, block[6], 0xc040b340, 9); \
		MD5_STEP(MD5_G, c, d, a, b, block[11], 0x265e5a51, 14); \
		MD5_STEP(MD5_G, b, c, d, a, block[0], 0xe9b6c7aa, 20); \
		MD5_STEP(MD5_G, a, b, c, d, block[5], 0xd62f105d, 5); \
		MD5_STEP(MD5_G, d, a, b, c, block[10], 0x02441453, 9); \
		MD5_STEP(MD5_G, c, d, a, b, block[15], 0xd8a1e681, 14); \
		MD5_STEP(MD5_G, b, c, d, a, block[4], 0xe7d3fbc8, 20); \
		MD5_STEP(MD5_G, a, b, c, d, block[9], 0x21e1cde6, 5); \
		MD5_STEP(MD5_G, d, a, b, c, block[14], 0xc33707d6, 9); \
		MD5_STEP(MD5_G, c, d, a, b, block[3], 0xf4d50d87, 14); \
		MD5_STEP(MD5_G, b, c, d, a, block[8], 0x455a14ed, 20); \
		MD5_STEP(MD5_G, a, b, c, d, block[13], 0xa9e3e905, 5); \
		MD5_STEP(MD5_G, d, a, b, c, block[2], 0xfcefa3f8, 9); \
		MD5_STEP(MD5_G, c, d, a, b, block[7], 0x676f02d9, 14); \
		MD5_STEP(MD5_G, b, c, d, a, block[12], 0x8d2a4c8a, 20); \
		MD5_STEP(MD5_H, a, b, c, d, block[5], 0xfffa3942, 4); \
		MD5_STEP(MD5_H, d, a, b, c, block[8], 0x8771f681, 11); \
		MD5_STEP(MD5_H, c, d, a, b, block[11], 0x6d9d6122, 16); \
		MD5_STEP(MD5_H, b, c, d, a, block[14], 0xfde5380c, 23); \
		MD5_STEP(MD5_H, a, b, c, d, block[1], 0xa4beea44, 4); \
		MD5_STEP(MD5_H, d, a, b, c, block[4], 0x4bdecfa9, 11); \
		MD5_STEP(MD5_H, c, d, a, b, block[7], 0xf6bb4b60, 16); \
		MD5_STEP(MD5_H, b, c, d, a, block[10], 0xbebfbc70, 23); \
		MD5_STEP(MD5_H, a, b, c, d, block[13], 0x289b7ec6, 4); \
		MD5_STEP(MD5_H, d, a, b, c, block[0], 0xeaa127fa, 11); \
		MD5_STEP(MD5_H, c, d, a, b, block[3], 0xd4ef3085, 16); \
		MD5_STEP(MD5_H, b, c, d, a, block[6], 0x04881d05, 23); \
		MD5_STEP(MD5_H, a, b, c, d, block[9], 0xd9d4d039, 4); \
		MD5_STEP(MD5_H, d, a, b, c, block[12], 0xe6db99e5, 11); \
		MD5_STEP(MD5_H, c, d, a, b, block[15], 0x1fa27cf8, 16); \
		MD5_STEP(MD5_H, b, c, d, a, block[2], 0xc4ac5665, 23); \
		MD5_STEP(MD5_I, a, b, c, d, block[0], 0xf4292244, 6); \
		MD5_STEP(MD5_I, d, a, b, c, block[7], 0x432aff97, 10); \
		MD5_STEP(MD5_I, c, d, a, b, block[14], 0xab9423a7, 15); \
		MD5_STEP(MD5_I, b, c, d, a, block[5], 0xfc93a039, 21); \
		MD5_STEP(MD5_I, a, b, c, d, block[12], 0x655b59c3, 6); \
		MD5_STEP(MD5_I, d, a, b, c, block[3], 0x8f0ccc92, 10); \
		MD5_STEP(MD5_I, c, d, a, b, block[10], 0xffeff47d, 15); \
		MD5_STEP(MD5_I, b, c, d, a, block[1], 0x85845dd1, 21); \
		MD5_STEP(MD5_I, a, b, c, d, block[8], 0x6fa87e4f, 6); \
		MD5_STEP(MD5_I, d, a, b, c, block[15], 0xfe2ce6e0, 10); \
		MD5_STEP(MD5_I, c, d, a, b, block[6], 0xa3014314, 15); \
		MD5_STEP(MD5_I, b, c, d, a, block[13], 0x4e0811a1, 21); \
		MD5_STEP(MD5_I, a, b, c, d, block[4], 0xf7537e82, 6); \
		MD5_STEP(MD5_I, d, a, b, c, block[11], 0xbd3af235, 10); \
		MD5_STEP(MD5_I, c, d, a, b, block[2], 0x2ad7d2bb, 15); \
		MD5_STEP(MD5_I, b, c, d, a, block[9], 0xeb86d391, 21); \
		output[0] += a; \
		output[1] += b; \
		output[2] += c; \
		output[3] += d; \
	}


#define md5_init(output) {	  \
		output[0] = 0x67452301; \
		output[1] = 0xefcdab89; \
		output[2] = 0x98badcfe; \
		output[3] = 0x10325476; \
	}

#endif

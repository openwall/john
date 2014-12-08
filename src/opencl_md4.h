/*
 * OpenCL MD4
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

#ifndef _OPENCL_MD4_H
#define _OPENCL_MD4_H

#include "opencl_misc.h"

#ifdef USE_BITSELECT
#define MD4_F(x, y, z)	bitselect((z), (y), (x))
#else
#define MD4_F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#endif

#define MD4_H(x, y, z)	((x) ^ (y) ^ (z))


/* The basic MD4 functions */
#define MD4_G(x, y, z)	(((x) & ((y) | (z))) | ((y) & (z)))


/* The MD4 transformation for all three rounds. */
#define MD4STEP(f, a, b, c, d, x, s)  \
	(a) += f((b), (c), (d)) + (x); \
	    (a) = rotate((a), (uint)(s))


/*
 * Raw'n'lean MD4 with context in output buffer
 * NOTE: This version thrashes the input block!
 *
 * Needs caller to have these defined:
 *	uint a, b, c, d;
 *
 * or perhaps:
 *	MAYBE_VECTOR_UINT a, b, c, d;
 *
 */
#define	md4_block(block, output) { \
		a = output[0]; \
		b = output[1]; \
		c = output[2]; \
		d = output[3]; \
		MD4STEP(MD4_F, a, b, c, d, block[0], 3); \
		MD4STEP(MD4_F, d, a, b, c, block[1], 7); \
		MD4STEP(MD4_F, c, d, a, b, block[2], 11); \
		MD4STEP(MD4_F, b, c, d, a, block[3], 19); \
		MD4STEP(MD4_F, a, b, c, d, block[4], 3); \
		MD4STEP(MD4_F, d, a, b, c, block[5], 7); \
		MD4STEP(MD4_F, c, d, a, b, block[6], 11); \
		MD4STEP(MD4_F, b, c, d, a, block[7], 19); \
		MD4STEP(MD4_F, a, b, c, d, block[8], 3); \
		MD4STEP(MD4_F, d, a, b, c, block[9], 7); \
		MD4STEP(MD4_F, c, d, a, b, block[10], 11); \
		MD4STEP(MD4_F, b, c, d, a, block[11], 19); \
		MD4STEP(MD4_F, a, b, c, d, block[12], 3); \
		MD4STEP(MD4_F, d, a, b, c, block[13], 7); \
		MD4STEP(MD4_F, c, d, a, b, block[14], 11); \
		MD4STEP(MD4_F, b, c, d, a, block[15], 19); \
		MD4STEP(MD4_G, a, b, c, d, block[0] + 0x5a827999, 3); \
		MD4STEP(MD4_G, d, a, b, c, block[4] + 0x5a827999, 5); \
		MD4STEP(MD4_G, c, d, a, b, block[8] + 0x5a827999, 9); \
		MD4STEP(MD4_G, b, c, d, a, block[12] + 0x5a827999, 13); \
		MD4STEP(MD4_G, a, b, c, d, block[1] + 0x5a827999, 3); \
		MD4STEP(MD4_G, d, a, b, c, block[5] + 0x5a827999, 5); \
		MD4STEP(MD4_G, c, d, a, b, block[9] + 0x5a827999, 9); \
		MD4STEP(MD4_G, b, c, d, a, block[13] + 0x5a827999, 13); \
		MD4STEP(MD4_G, a, b, c, d, block[2] + 0x5a827999, 3); \
		MD4STEP(MD4_G, d, a, b, c, block[6] + 0x5a827999, 5); \
		MD4STEP(MD4_G, c, d, a, b, block[10] + 0x5a827999, 9); \
		MD4STEP(MD4_G, b, c, d, a, block[14] + 0x5a827999, 13); \
		MD4STEP(MD4_G, a, b, c, d, block[3] + 0x5a827999, 3); \
		MD4STEP(MD4_G, d, a, b, c, block[7] + 0x5a827999, 5); \
		MD4STEP(MD4_G, c, d, a, b, block[11] + 0x5a827999, 9); \
		MD4STEP(MD4_G, b, c, d, a, block[15] + 0x5a827999, 13); \
		MD4STEP(MD4_H, a, b, c, d, block[0] + 0x6ed9eba1, 3); \
		MD4STEP(MD4_H, d, a, b, c, block[8] + 0x6ed9eba1, 9); \
		MD4STEP(MD4_H, c, d, a, b, block[4] + 0x6ed9eba1, 11); \
		MD4STEP(MD4_H, b, c, d, a, block[12] + 0x6ed9eba1, 15); \
		MD4STEP(MD4_H, a, b, c, d, block[2] + 0x6ed9eba1, 3); \
		MD4STEP(MD4_H, d, a, b, c, block[10] + 0x6ed9eba1, 9); \
		MD4STEP(MD4_H, c, d, a, b, block[6] + 0x6ed9eba1, 11); \
		MD4STEP(MD4_H, b, c, d, a, block[14] + 0x6ed9eba1, 15); \
		MD4STEP(MD4_H, a, b, c, d, block[1] + 0x6ed9eba1, 3); \
		MD4STEP(MD4_H, d, a, b, c, block[9] + 0x6ed9eba1, 9); \
		MD4STEP(MD4_H, c, d, a, b, block[5] + 0x6ed9eba1, 11); \
		MD4STEP(MD4_H, b, c, d, a, block[13] + 0x6ed9eba1, 15); \
		MD4STEP(MD4_H, a, b, c, d, block[3] + 0x6ed9eba1, 3); \
		MD4STEP(MD4_H, d, a, b, c, block[11] + 0x6ed9eba1, 9); \
		MD4STEP(MD4_H, c, d, a, b, block[7] + 0x6ed9eba1, 11); \
		MD4STEP(MD4_H, b, c, d, a, block[15] + 0x6ed9eba1, 15); \
		output[0] += a; \
		output[1] += b; \
		output[2] += c; \
		output[3] += d; \
	}

#define md4_init(output) {	  \
	output[0] = 0x67452301; \
	output[1] = 0xefcdab89; \
	output[2] = 0x98badcfe; \
	output[3] = 0x10325476; \
	}

#endif

/*
 * NTLMv2
 * MD4 + 2 x HMAC-MD5
 *
 * Copyright (c) 2012, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#include "opencl_device_info.h"

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

#if gpu(DEVICE_INFO)
#define SCALAR
#endif

/* Workaround for driver bug seen in version 295.49 */
#if gpu_nvidia(DEVICE_INFO)
#define MAYBE_CONSTANT const __global
#else
#define MAYBE_CONSTANT	__constant
#endif

#ifdef SCALAR
#define MAYBE_VECTOR_UINT	uint
#else
#define MAYBE_VECTOR_UINT	uint4
#endif


/* Functions common to MD4 and MD5 */
#ifdef USE_BITSELECT
#define F(x, y, z)	bitselect((z), (y), (x))
#else
#define F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#endif

#define H(x, y, z)	((x) ^ (y) ^ (z))


/* The basic MD4 functions */
#define G(x, y, z)	(((x) & ((y) | (z))) | ((y) & (z)))


/* The MD4 transformation for all three rounds. */
#define STEP(f, a, b, c, d, x, s)  \
	(a) += f((b), (c), (d)) + (x); \
	    (a) = rotate((a), (uint)(s))


/* Raw'n'lean MD4 with context in output buffer */
/* NOTE: This version thrashes the input block! */
inline void md4_block(MAYBE_VECTOR_UINT *block, MAYBE_VECTOR_UINT *output)
{
	MAYBE_VECTOR_UINT a, b, c, d;

	a = output[0];
	b = output[1];
	c = output[2];
	d = output[3];

	/* Round 1 */
	STEP(F, a, b, c, d, block[0], 3);
	STEP(F, d, a, b, c, block[1], 7);
	STEP(F, c, d, a, b, block[2], 11);
	STEP(F, b, c, d, a, block[3], 19);
	STEP(F, a, b, c, d, block[4], 3);
	STEP(F, d, a, b, c, block[5], 7);
	STEP(F, c, d, a, b, block[6], 11);
	STEP(F, b, c, d, a, block[7], 19);
	STEP(F, a, b, c, d, block[8], 3);
	STEP(F, d, a, b, c, block[9], 7);
	STEP(F, c, d, a, b, block[10], 11);
	STEP(F, b, c, d, a, block[11], 19);
	STEP(F, a, b, c, d, block[12], 3);
	STEP(F, d, a, b, c, block[13], 7);
	STEP(F, c, d, a, b, block[14], 11);
	STEP(F, b, c, d, a, block[15], 19);

	/* Round 2 */
	STEP(G, a, b, c, d, block[0] + 0x5a827999, 3);
	STEP(G, d, a, b, c, block[4] + 0x5a827999, 5);
	STEP(G, c, d, a, b, block[8] + 0x5a827999, 9);
	STEP(G, b, c, d, a, block[12] + 0x5a827999, 13);
	STEP(G, a, b, c, d, block[1] + 0x5a827999, 3);
	STEP(G, d, a, b, c, block[5] + 0x5a827999, 5);
	STEP(G, c, d, a, b, block[9] + 0x5a827999, 9);
	STEP(G, b, c, d, a, block[13] + 0x5a827999, 13);
	STEP(G, a, b, c, d, block[2] + 0x5a827999, 3);
	STEP(G, d, a, b, c, block[6] + 0x5a827999, 5);
	STEP(G, c, d, a, b, block[10] + 0x5a827999, 9);
	STEP(G, b, c, d, a, block[14] + 0x5a827999, 13);
	STEP(G, a, b, c, d, block[3] + 0x5a827999, 3);
	STEP(G, d, a, b, c, block[7] + 0x5a827999, 5);
	STEP(G, c, d, a, b, block[11] + 0x5a827999, 9);
	STEP(G, b, c, d, a, block[15] + 0x5a827999, 13);

	/* Round 3 */
	STEP(H, a, b, c, d, block[0] + 0x6ed9eba1, 3);
	STEP(H, d, a, b, c, block[8] + 0x6ed9eba1, 9);
	STEP(H, c, d, a, b, block[4] + 0x6ed9eba1, 11);
	STEP(H, b, c, d, a, block[12] + 0x6ed9eba1, 15);
	STEP(H, a, b, c, d, block[2] + 0x6ed9eba1, 3);
	STEP(H, d, a, b, c, block[10] + 0x6ed9eba1, 9);
	STEP(H, c, d, a, b, block[6] + 0x6ed9eba1, 11);
	STEP(H, b, c, d, a, block[14] + 0x6ed9eba1, 15);
	STEP(H, a, b, c, d, block[1] + 0x6ed9eba1, 3);
	STEP(H, d, a, b, c, block[9] + 0x6ed9eba1, 9);
	STEP(H, c, d, a, b, block[5] + 0x6ed9eba1, 11);
	STEP(H, b, c, d, a, block[13] + 0x6ed9eba1, 15);
	STEP(H, a, b, c, d, block[3] + 0x6ed9eba1, 3);
	STEP(H, d, a, b, c, block[11] + 0x6ed9eba1, 9);
	STEP(H, c, d, a, b, block[7] + 0x6ed9eba1, 11);
	STEP(H, b, c, d, a, block[15] + 0x6ed9eba1, 15);

	output[0] += a;
	output[1] += b;
	output[2] += c;
	output[3] += d;
}


/* The basic MD5 functions */
/* F and H are the same as for MD4, above */
#undef G
#undef STEP
#ifdef USE_BITSELECT
#define G(x, y, z)	bitselect((y), (x), (z))
#else
#define G(x, y, z)	((y) ^ ((z) & ((x) ^ (y))))
#endif

#define I(x, y, z)	((y) ^ ((x) | ~(z)))


/* The MD5 transformation for all four rounds. */
#define STEP(f, a, b, c, d, x, t, s)	  \
	(a) += f((b), (c), (d)) + (x) + (t); \
	    (a) = rotate((a), (uint)(s)); \
	    (a) += (b)


/* Raw'n'lean MD5 with context in output buffer */
/* NOTE: This version thrashes the input block! */
inline void md5_block(MAYBE_VECTOR_UINT *block, MAYBE_VECTOR_UINT *output)
{
	MAYBE_VECTOR_UINT a, b, c, d;

	a = output[0];
	b = output[1];
	c = output[2];
	d = output[3];

	/* Round 1 */
	STEP(F, a, b, c, d, block[0], 0xd76aa478, 7);
	STEP(F, d, a, b, c, block[1], 0xe8c7b756, 12);
	STEP(F, c, d, a, b, block[2], 0x242070db, 17);
	STEP(F, b, c, d, a, block[3], 0xc1bdceee, 22);
	STEP(F, a, b, c, d, block[4], 0xf57c0faf, 7);
	STEP(F, d, a, b, c, block[5], 0x4787c62a, 12);
	STEP(F, c, d, a, b, block[6], 0xa8304613, 17);
	STEP(F, b, c, d, a, block[7], 0xfd469501, 22);
	STEP(F, a, b, c, d, block[8], 0x698098d8, 7);
	STEP(F, d, a, b, c, block[9], 0x8b44f7af, 12);
	STEP(F, c, d, a, b, block[10], 0xffff5bb1, 17);
	STEP(F, b, c, d, a, block[11], 0x895cd7be, 22);
	STEP(F, a, b, c, d, block[12], 0x6b901122, 7);
	STEP(F, d, a, b, c, block[13], 0xfd987193, 12);
	STEP(F, c, d, a, b, block[14], 0xa679438e, 17);
	STEP(F, b, c, d, a, block[15], 0x49b40821, 22);

	/* Round 2 */
	STEP(G, a, b, c, d, block[1], 0xf61e2562, 5);
	STEP(G, d, a, b, c, block[6], 0xc040b340, 9);
	STEP(G, c, d, a, b, block[11], 0x265e5a51, 14);
	STEP(G, b, c, d, a, block[0], 0xe9b6c7aa, 20);
	STEP(G, a, b, c, d, block[5], 0xd62f105d, 5);
	STEP(G, d, a, b, c, block[10], 0x02441453, 9);
	STEP(G, c, d, a, b, block[15], 0xd8a1e681, 14);
	STEP(G, b, c, d, a, block[4], 0xe7d3fbc8, 20);
	STEP(G, a, b, c, d, block[9], 0x21e1cde6, 5);
	STEP(G, d, a, b, c, block[14], 0xc33707d6, 9);
	STEP(G, c, d, a, b, block[3], 0xf4d50d87, 14);
	STEP(G, b, c, d, a, block[8], 0x455a14ed, 20);
	STEP(G, a, b, c, d, block[13], 0xa9e3e905, 5);
	STEP(G, d, a, b, c, block[2], 0xfcefa3f8, 9);
	STEP(G, c, d, a, b, block[7], 0x676f02d9, 14);
	STEP(G, b, c, d, a, block[12], 0x8d2a4c8a, 20);

	/* Round 3 */
	STEP(H, a, b, c, d, block[5], 0xfffa3942, 4);
	STEP(H, d, a, b, c, block[8], 0x8771f681, 11);
	STEP(H, c, d, a, b, block[11], 0x6d9d6122, 16);
	STEP(H, b, c, d, a, block[14], 0xfde5380c, 23);
	STEP(H, a, b, c, d, block[1], 0xa4beea44, 4);
	STEP(H, d, a, b, c, block[4], 0x4bdecfa9, 11);
	STEP(H, c, d, a, b, block[7], 0xf6bb4b60, 16);
	STEP(H, b, c, d, a, block[10], 0xbebfbc70, 23);
	STEP(H, a, b, c, d, block[13], 0x289b7ec6, 4);
	STEP(H, d, a, b, c, block[0], 0xeaa127fa, 11);
	STEP(H, c, d, a, b, block[3], 0xd4ef3085, 16);
	STEP(H, b, c, d, a, block[6], 0x04881d05, 23);
	STEP(H, a, b, c, d, block[9], 0xd9d4d039, 4);
	STEP(H, d, a, b, c, block[12], 0xe6db99e5, 11);
	STEP(H, c, d, a, b, block[15], 0x1fa27cf8, 16);
	STEP(H, b, c, d, a, block[2], 0xc4ac5665, 23);

	/* Round 4 */
	STEP(I, a, b, c, d, block[0], 0xf4292244, 6);
	STEP(I, d, a, b, c, block[7], 0x432aff97, 10);
	STEP(I, c, d, a, b, block[14], 0xab9423a7, 15);
	STEP(I, b, c, d, a, block[5], 0xfc93a039, 21);
	STEP(I, a, b, c, d, block[12], 0x655b59c3, 6);
	STEP(I, d, a, b, c, block[3], 0x8f0ccc92, 10);
	STEP(I, c, d, a, b, block[10], 0xffeff47d, 15);
	STEP(I, b, c, d, a, block[1], 0x85845dd1, 21);
	STEP(I, a, b, c, d, block[8], 0x6fa87e4f, 6);
	STEP(I, d, a, b, c, block[15], 0xfe2ce6e0, 10);
	STEP(I, c, d, a, b, block[6], 0xa3014314, 15);
	STEP(I, b, c, d, a, block[13], 0x4e0811a1, 21);
	STEP(I, a, b, c, d, block[4], 0xf7537e82, 6);
	STEP(I, d, a, b, c, block[11], 0xbd3af235, 10);
	STEP(I, c, d, a, b, block[2], 0x2ad7d2bb, 15);
	STEP(I, b, c, d, a, block[9], 0xeb86d391, 21);

	output[0] += a;
	output[1] += b;
	output[2] += c;
	output[3] += d;
}


#define md5_init(output) {	  \
	output[0] = 0x67452301; \
	output[1] = 0xefcdab89; \
	output[2] = 0x98badcfe; \
	output[3] = 0x10325476; \
	}

#define md4_init(output)	md5_init(output)


__kernel void ntlmv2_nthash(const __global uint *unicode_pw, __global MAYBE_VECTOR_UINT *nthash)
{
	uint i;
	uint gid = get_global_id(0);
	MAYBE_VECTOR_UINT block[16];
	MAYBE_VECTOR_UINT output[4];
#ifdef SCALAR
	const __global uint *pw = &unicode_pw[gid * 16];
#endif

	/* Initial hash of password */
	/* Input buffer is prepared with 0x80, zero-padding and length << 3 */
	md4_init(output);

#pragma unroll
	for (i = 0; i < 16; i++) {
#ifdef SCALAR
		block[i] = *pw++;
#else
		block[i].s0 = unicode_pw[(gid * 4 + 0) * 16 + i];
		block[i].s1 = unicode_pw[(gid * 4 + 1) * 16 + i];
		block[i].s2 = unicode_pw[(gid * 4 + 2) * 16 + i];
		block[i].s3 = unicode_pw[(gid * 4 + 3) * 16 + i];
#endif
	}
	md4_block(block, output);

#pragma unroll
	for (i = 0; i < 4; i++)
		nthash[gid * 4 + i] = output[i];
}

__kernel void ntlmv2_final(const __global MAYBE_VECTOR_UINT *nthash, MAYBE_CONSTANT uint *challenge, __global uint *result)
{
	uint i;
	uint gid = get_global_id(0);
	MAYBE_VECTOR_UINT block[16];
	MAYBE_VECTOR_UINT output[4], hash[4];
	MAYBE_CONSTANT uint *cp = challenge; /* identity[16].len,server_chal.client_chal[len] */
	uint challenge_size;

	/* 1st HMAC */
	md5_init(output);

#pragma unroll
	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ nthash[gid * 4 + i];
#pragma unroll
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(block, output); /* md5_update(ipad, 64) */

	/* Salt buffer is prepared with 0x80, zero-padding and length,
	 * ie. (saltlen + 64) << 3 in get_salt() */
#pragma unroll
	for (i = 0; i < 16; i++)
		block[i] = *cp++;
	md5_block(block, output); /* md5_update(salt, saltlen), md5_final() */

#pragma unroll
	for (i = 0; i < 4; i++) {
		hash[i] = output[i];
		block[i] = 0x5c5c5c5c ^ nthash[gid * 4 + i];
	}
	md5_init(output);
#pragma unroll
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_block(block, output); /* md5_update(opad, 64) */

#pragma unroll
	for (i = 0; i < 4; i++)
		block[i] = hash[i];
	block[4] = 0x80;
#pragma unroll
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(hash, 16), md5_final() */

	/* 2nd HMAC */
#pragma unroll
	for (i = 0; i < 4; i++) {
		hash[i] = output[i];
		block[i] = 0x36363636 ^ output[i];
	}
	md5_init(output);
#pragma unroll
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(block, output); /* md5_update(ipad, 64) */

	/* Challenge:  blocks (of MD5),
	 * Server Challenge + Client Challenge (Blob) +
	 * 0x80, null padded and len set in get_salt() */
	challenge_size = *cp++;

	/* At least this will not diverge */
	while (challenge_size--) {
#pragma unroll
		for (i = 0; i < 16; i++)
			block[i] = *cp++;
		md5_block(block, output); /* md5_update(challenge, len), md5_final() */
	}

#pragma unroll
	for (i = 0; i < 4; i++) {
		block[i] = 0x5c5c5c5c ^ hash[i];
		hash[i] = output[i];
	}
	md5_init(output);
#pragma unroll
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_block(block, output); /* md5_update(opad, 64) */

#pragma unroll
	for (i = 0; i < 4; i++)
		block[i] = hash[i];
	block[4] = 0x80;
#pragma unroll
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(hash, 16), md5_final() */

#pragma unroll
	for (i = 0; i < 4; i++) {
#ifdef SCALAR
		result[gid * 4 + i] = output[i];
#else
		result[(gid * 4 + 0) * 4 + i] = output[i].s0;
		result[(gid * 4 + 1) * 4 + i] = output[i].s1;
		result[(gid * 4 + 2) * 4 + i] = output[i].s2;
		result[(gid * 4 + 3) * 4 + i] = output[i].s3;
#endif
	}
}

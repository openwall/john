/*
 * Office 2013
 *
 * Copyright (c) 2012, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * This is thanks to Dhiru writing the CPU code first!
 * Also, it's using Claudio's SHA-512 (although very slimmed here).
 */

#include "opencl_device_info.h"

#if gpu(DEVICE_INFO)
#define SCALAR
#endif

/* Office 2010/2013 */
__constant ulong InputBlockKey = 0xfea7d2763b4b9e79UL;
__constant ulong ValueBlockKey = 0xd7aa0f6d3061344eUL;

/* SHA-2 constants */
__constant ulong k[] = {
	0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
	0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
	0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
	0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
	0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
	0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
	0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
	0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
	0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
	0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
	0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
	0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
	0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
	0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
	0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
	0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
	0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
	0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
	0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
	0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
};

#if gpu_amd(DEVICE_INFO)

/* AMD alternatives */
#define Ch(x,y,z)       bitselect(z, y, x)
#define Maj(x,y,z)      bitselect(x, y, z ^ x)
#define ror(x, n)       rotate(x, (ulong) 64-n)
#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))
#define SWAP64(n)       (as_ulong(as_uchar8(n).s76543210))

#else

/* non-AMD alternatives */
#define Ch(x,y,z)       ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z)      ((x & y) ^ (x & z) ^ (y & z))
#define ror(x, n)       ((x >> n) | (x << (64-n)))
inline uint SWAP32(uint x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#define SWAP64(n)	  \
	(((n) << 56) \
	 | (((n) & 0xff00) << 40) \
	 | (((n) & 0xff0000) << 24) \
	 | (((n) & 0xff000000) << 8) \
	 | (((n) >> 8) & 0xff000000) \
	 | (((n) >> 24) & 0xff0000) \
	 | (((n) >> 40) & 0xff00) \
	 | ((n) >> 56))

#endif

/* common SHA-2 stuff */
#define Sigma0(x)               ((ror(x,28)) ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x)               ((ror(x,14)) ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x)               ((ror(x,1))  ^ (ror(x,8))  ^ (x>>7))
#define sigma1(x)               ((ror(x,19)) ^ (ror(x,61)) ^ (x>>6))

#ifdef SCALAR
#define MAYBE_VECTOR_ULONG	ulong
#define sha512_single_s		sha512_single
#else
#define VF			4
#define MAYBE_VECTOR_ULONG	ulong4

/* Raw'n'lean single-block SHA-512, no context[tm] */
inline void sha512_single_s(ulong *w, ulong *output) {
	ulong t1, t2, a, b, c, d, e, f, g, h;

	/* always init */
	a = 0x6a09e667f3bcc908UL;
	b = 0xbb67ae8584caa73bUL;
	c = 0x3c6ef372fe94f82bUL;
	d = 0xa54ff53a5f1d36f1UL;
	e = 0x510e527fade682d1UL;
	f = 0x9b05688c2b3e6c1fUL;
	g = 0x1f83d9abfb41bd6bUL;
	h = 0x5be0cd19137e2179UL;

#pragma unroll
	for (int i = 0; i < 16; i++) {
		t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

#pragma unroll
	for (int i = 16; i < 80; i++) {
		w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
		t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	output[0] = 0x6a09e667f3bcc908UL + a;
	output[1] = 0xbb67ae8584caa73bUL + b;
	output[2] = 0x3c6ef372fe94f82bUL + c;
	output[3] = 0xa54ff53a5f1d36f1UL + d;
	output[4] = 0x510e527fade682d1UL + e;
	output[5] = 0x9b05688c2b3e6c1fUL + f;
	output[6] = 0x1f83d9abfb41bd6bUL + g;
	output[7] = 0x5be0cd19137e2179UL + h;
}
#endif

/* Raw'n'lean single-block SHA-512, no context[tm] */
inline void sha512_single(MAYBE_VECTOR_ULONG *w, MAYBE_VECTOR_ULONG *output) {
	MAYBE_VECTOR_ULONG t1, t2, a, b, c, d, e, f, g, h;

	/* always init */
	a = 0x6a09e667f3bcc908UL;
	b = 0xbb67ae8584caa73bUL;
	c = 0x3c6ef372fe94f82bUL;
	d = 0xa54ff53a5f1d36f1UL;
	e = 0x510e527fade682d1UL;
	f = 0x9b05688c2b3e6c1fUL;
	g = 0x1f83d9abfb41bd6bUL;
	h = 0x5be0cd19137e2179UL;

#pragma unroll
	for (int i = 0; i < 16; i++) {
		t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

#pragma unroll
	for (int i = 16; i < 80; i++) {
		w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
		t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	output[0] = 0x6a09e667f3bcc908UL + a;
	output[1] = 0xbb67ae8584caa73bUL + b;
	output[2] = 0x3c6ef372fe94f82bUL + c;
	output[3] = 0xa54ff53a5f1d36f1UL + d;
	output[4] = 0x510e527fade682d1UL + e;
	output[5] = 0x9b05688c2b3e6c1fUL + f;
	output[6] = 0x1f83d9abfb41bd6bUL + g;
	output[7] = 0x5be0cd19137e2179UL + h;
}

__kernel void GenerateSHA512pwhash(
	__global ulong *unicode_pw,
	__global uint *pw_len,
	__constant ulong *salt,
	__global ulong *pwhash)
{
	uint i;
	ulong block[16];
	ulong output[8];
	uint gid = get_global_id(0);

	/* Initial hash of salt + password */
	/* The ending 0x80 is already in the buffer */
#pragma unroll
	for (i = 0; i < 2; i++)
		block[i] = SWAP64(salt[i]);
#pragma unroll
	for (i = 2; i < 14; i++) {
		block[i] = SWAP64(unicode_pw[gid * (UNICODE_LENGTH >> 3) + i - 2]);
	}
	block[14] = 0;
	block[15] = (ulong)(pw_len[gid] + 16) << 3;
	sha512_single_s(block, output);

#pragma unroll
	for (i = 0; i < 8; i++)
#ifdef SCALAR
		pwhash[gid * 9 + i] = output[i];
	pwhash[gid * 9 + 8] = 0;
#else
		pwhash[(gid >> 2) * VF * 9 + (gid & 3) + i * VF] = output[i];
	pwhash[(gid >> 2) * VF * 9 + (gid & 3) + 8 * VF] = 0;
#endif
}

__kernel void HashLoop(__global MAYBE_VECTOR_ULONG *pwhash)
{
	uint i, j;
	MAYBE_VECTOR_ULONG block[16];
	MAYBE_VECTOR_ULONG output[8];
	uint gid = get_global_id(0);
#ifdef SCALAR
	uint base = pwhash[gid * 9 + 8];
#else
	uint base = pwhash[gid * 9 + 8].s0;
#endif

#pragma unroll
	for (i = 0; i < 8; i++)
		output[i] = pwhash[gid * 9 + i];

	/* HASH_LOOPS rounds of sha512(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 0; j < HASH_LOOPS; j++)
	{
		block[0] = ((ulong)SWAP32(base + j) << 32) | (output[0] >> 32);
#pragma unroll
		for (i = 1; i < 8; i++)
			block[i] = (output[i - 1] << 32) | (output[i] >> 32);
		block[8] = (output[7] << 32) | 0x80000000UL;
#pragma unroll
		for (i = 9; i < 15; i++)
			block[i] = 0;
		block[15] = 68 << 3;
		sha512_single(block, output);
	}
#pragma unroll
	for (i = 0; i < 8; i++)
		pwhash[gid * 9 + i] = output[i];
	pwhash[gid * 9 + 8] += HASH_LOOPS;
}

__kernel void Generate2013key(
	__global MAYBE_VECTOR_ULONG *pwhash,
	__global ulong *key,
	__constant uint *spincount)
{
	uint i, j;
	MAYBE_VECTOR_ULONG block[16], temp[8];
	MAYBE_VECTOR_ULONG output[8];
	uint gid = get_global_id(0);
#ifdef SCALAR
	uint base = pwhash[gid * 9 + 8];
#else
	uint base = pwhash[gid * 9 + 8].s0;
#endif
	uint iterations = *spincount % HASH_LOOPS;

#pragma unroll
	for (i = 0; i < 8; i++)
		output[i] = pwhash[gid * 9 + i];

	/* Remainder of iterations */
	for (j = 0; j < iterations; j++)
	{
		block[0] = ((ulong)SWAP32(base + j) << 32) | (output[0] >> 32);
#pragma unroll
		for (i = 1; i < 8; i++)
			block[i] = (output[i - 1] << 32) | (output[i] >> 32);
		block[8] = (output[7] << 32) | 0x80000000UL;
#pragma unroll
		for (i = 9; i < 15; i++)
			block[i] = 0;
		block[15] = 68 << 3;
		sha512_single(block, output);
	}

	/* Our sha512 destroys input so we store a needed portion in temp[] */
#pragma unroll
	for (i = 0; i < 8; i++)
		block[i] = temp[i] = output[i];

	/* Final hash 1 */
	block[8] = InputBlockKey;
	block[9] = 0x8000000000000000UL;
#pragma unroll
	for (i = 10; i < 15; i++)
		block[i] = 0;
	block[15] = 72 << 3;
	sha512_single(block, output);

	/* Prepare for final hash 2 */
#pragma unroll
	for (i = 0; i < 8; i++)
		block[i] = temp[i];

	/* Endian-swap to hash 1 output */
#pragma unroll
	for (i = 0; i < 8; i++) {
#ifdef SCALAR
		key[gid * 128/8 + i] = SWAP64(output[i]);
#else
		key[(gid * VF) * 128/8 + i] = SWAP64(output[i].s0);
		key[(gid * VF + 1) * 128/8 + i] = SWAP64(output[i].s1);
		key[(gid * VF + 2) * 128/8 + i] = SWAP64(output[i].s2);
		key[(gid * VF + 3) * 128/8 + i] = SWAP64(output[i].s3);
#endif
	}

	/* Final hash 2 */
	block[8] = ValueBlockKey;
	block[9] = 0x8000000000000000UL;
#pragma unroll
	for (i = 10; i < 15; i++)
		block[i] = 0;
	block[15] = 72 << 3;
	sha512_single(block, output);

	/* Endian-swap to hash 2 output */
#pragma unroll
	for (i = 0; i < 8; i++) {
#ifdef SCALAR
		key[gid * 128/8 + 64/8 + i] = SWAP64(output[i]);
#else
		key[(gid * VF) * 128/8 + 64/8 + i] = SWAP64(output[i].s0);
		key[(gid * VF + 1) * 128/8 + 64/8 + i] = SWAP64(output[i].s1);
		key[(gid * VF + 2) * 128/8 + 64/8 + i] = SWAP64(output[i].s2);
		key[(gid * VF + 3) * 128/8 + 64/8 + i] = SWAP64(output[i].s3);
#endif
	}
}

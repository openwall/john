/*
 * Office 2007:
 * GeneratePasswordHashUsingSHA1() [50002 x SHA-1]
 * and DeriveKey() [xor 0x36 to a 64-byte block and 2 x SHA-1]
 *
 * Copyright 2012, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * This is thanks to Dhiru writing the CPU code first!
 */

#include "opencl_device_info.h"

//#if (defined(VECTORIZE) || (!defined(SCALAR) && gpu_amd(DEVICE_INFO) && !amd_gcn(DEVICE_INFO)))
#ifdef VECTORIZE
#define MAYBE_VECTOR_UINT	uint4
#ifndef VECTORIZE
#define VECTORIZE
#endif
#else
#define MAYBE_VECTOR_UINT	uint
#ifndef SCALAR
#define SCALAR
#endif
#endif

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

#if gpu_nvidia(DEVICE_INFO) || amd_gcn(DEVICE_INFO)
inline uint SWAP32(uint x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#else
#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))
#endif

#define INIT_A			0x67452301
#define INIT_B			0xefcdab89
#define INIT_C			0x98badcfe
#define INIT_D			0x10325476
#define INIT_E			0xc3d2e1f0

#define SQRT_2			0x5a827999
#define SQRT_3			0x6ed9eba1

#define K1			0x5a827999
#define K2			0x6ed9eba1
#define K3			0x8f1bbcdc
#define K4			0xca62c1d6

#ifdef USE_BITSELECT
#define F1(x, y, z)	bitselect(z, y, x)
#else
#define F1(x, y, z)	(z ^ (x & (y ^ z)))
#endif

#define F2(x, y, z)		(x ^ y ^ z)

#ifdef USE_BITSELECT
#define F3(x, y, z)	(bitselect(x, y, z) ^ bitselect(x, 0U, y))
#else
#define F3(x, y, z)	((x & y) | (z & (x | y)))
#endif

#define F4(x, y, z)		(x ^ y ^ z)

#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))
#define XORCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2]) ^ ((val) << ((((index) & 3) ^ 3) << 3))
#else
#define PUTCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] = (val)
#define XORCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] ^= (val)
#endif

#define R(t)	  \
	( \
		temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( W[t & 0x0F] = rotate(temp, 1U) ) \
		)

#define R2(t)	  \
	( \
		rotate((W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		   W[(t - 14) & 0x0F] ^ W[ t      & 0x0F]), 1U) \
		)

#define P1(a, b, c, d, e, x)	  \
	{ \
		e += rotate(a, 5U) + F1(b, c, d) + K1 + x; b = rotate(b, 30U); \
	}

#define P2(a, b, c, d, e, x)	  \
	{ \
		e += rotate(a, 5U) + F2(b, c, d) + K2 + x; b = rotate(b, 30U); \
	}

#define P3(a, b, c, d, e, x)	  \
	{ \
		e += rotate(a, 5U) + F3(b, c, d) + K3 + x; b = rotate(b, 30U); \
	}

#define P4(a, b, c, d, e, x)	  \
	{ \
		e += rotate(a, 5U) + F4(b, c, d) + K4 + x; b = rotate(b, 30U); \
	}

#define PZ(a, b, c, d, e)	  \
	{ \
		e += rotate(a, 5U) + F1(b, c, d) + K1 ; b = rotate(b, 30U); \
	}

#define SHA1(A, B, C, D, E, W)	  \
	P1(A, B, C, D, E, W[0] ); \
	P1(E, A, B, C, D, W[1] ); \
	P1(D, E, A, B, C, W[2] ); \
	P1(C, D, E, A, B, W[3] ); \
	P1(B, C, D, E, A, W[4] ); \
	P1(A, B, C, D, E, W[5] ); \
	P1(E, A, B, C, D, W[6] ); \
	P1(D, E, A, B, C, W[7] ); \
	P1(C, D, E, A, B, W[8] ); \
	P1(B, C, D, E, A, W[9] ); \
	P1(A, B, C, D, E, W[10]); \
	P1(E, A, B, C, D, W[11]); \
	P1(D, E, A, B, C, W[12]); \
	P1(C, D, E, A, B, W[13]); \
	P1(B, C, D, E, A, W[14]); \
	P1(A, B, C, D, E, W[15]); \
	P1(E, A, B, C, D, R(16)); \
	P1(D, E, A, B, C, R(17)); \
	P1(C, D, E, A, B, R(18)); \
	P1(B, C, D, E, A, R(19)); \
	P2(A, B, C, D, E, R(20)); \
	P2(E, A, B, C, D, R(21)); \
	P2(D, E, A, B, C, R(22)); \
	P2(C, D, E, A, B, R(23)); \
	P2(B, C, D, E, A, R(24)); \
	P2(A, B, C, D, E, R(25)); \
	P2(E, A, B, C, D, R(26)); \
	P2(D, E, A, B, C, R(27)); \
	P2(C, D, E, A, B, R(28)); \
	P2(B, C, D, E, A, R(29)); \
	P2(A, B, C, D, E, R(30)); \
	P2(E, A, B, C, D, R(31)); \
	P2(D, E, A, B, C, R(32)); \
	P2(C, D, E, A, B, R(33)); \
	P2(B, C, D, E, A, R(34)); \
	P2(A, B, C, D, E, R(35)); \
	P2(E, A, B, C, D, R(36)); \
	P2(D, E, A, B, C, R(37)); \
	P2(C, D, E, A, B, R(38)); \
	P2(B, C, D, E, A, R(39)); \
	P3(A, B, C, D, E, R(40)); \
	P3(E, A, B, C, D, R(41)); \
	P3(D, E, A, B, C, R(42)); \
	P3(C, D, E, A, B, R(43)); \
	P3(B, C, D, E, A, R(44)); \
	P3(A, B, C, D, E, R(45)); \
	P3(E, A, B, C, D, R(46)); \
	P3(D, E, A, B, C, R(47)); \
	P3(C, D, E, A, B, R(48)); \
	P3(B, C, D, E, A, R(49)); \
	P3(A, B, C, D, E, R(50)); \
	P3(E, A, B, C, D, R(51)); \
	P3(D, E, A, B, C, R(52)); \
	P3(C, D, E, A, B, R(53)); \
	P3(B, C, D, E, A, R(54)); \
	P3(A, B, C, D, E, R(55)); \
	P3(E, A, B, C, D, R(56)); \
	P3(D, E, A, B, C, R(57)); \
	P3(C, D, E, A, B, R(58)); \
	P3(B, C, D, E, A, R(59)); \
	P4(A, B, C, D, E, R(60)); \
	P4(E, A, B, C, D, R(61)); \
	P4(D, E, A, B, C, R(62)); \
	P4(C, D, E, A, B, R(63)); \
	P4(B, C, D, E, A, R(64)); \
	P4(A, B, C, D, E, R(65)); \
	P4(E, A, B, C, D, R(66)); \
	P4(D, E, A, B, C, R(67)); \
	P4(C, D, E, A, B, R(68)); \
	P4(B, C, D, E, A, R(69)); \
	P4(A, B, C, D, E, R(70)); \
	P4(E, A, B, C, D, R(71)); \
	P4(D, E, A, B, C, R(72)); \
	P4(C, D, E, A, B, R(73)); \
	P4(B, C, D, E, A, R(74)); \
	P4(A, B, C, D, E, R(75)); \
	P4(E, A, B, C, D, R(76)); \
	P4(D, E, A, B, C, R(77)); \
	P4(C, D, E, A, B, R(78)); \
	P4(B, C, D, E, A, R(79));

#define SHA1_SHORT_BEG(A, B, C, D, E, W)	  \
	P1(A, B, C, D, E, W[0]); \
	P1(E, A, B, C, D, W[1]); \
	P1(D, E, A, B, C, W[2]); \
	P1(C, D, E, A, B, W[3]); \
	P1(B, C, D, E, A, W[4]); \
	P1(A, B, C, D, E, W[5]); \
	P1(E, A, B, C, D, W[6]); \
	PZ(D, E, A, B, C); \
	PZ(C, D, E, A, B); \
	PZ(B, C, D, E, A); \
	PZ(A, B, C, D, E); \
	PZ(E, A, B, C, D); \
	PZ(D, E, A, B, C); \
	PZ(C, D, E, A, B); \
	PZ(B, C, D, E, A); \
	P1(A, B, C, D, E, W[15]);

// Q16 temp = W[13] ^ W[8] ^ W[2] ^ W[0], ( W[0] = rotate(temp, 1) )
// Q17 temp = W[14] ^ W[9] ^ W[3] ^ W[1], ( W[1] = rotate(temp, 1) )
// Q18 temp = W[15] ^ W[10] ^ W[4] ^ W[2], ( W[2] = rotate(temp, 1) )
// Q19 temp = W[0] ^ W[11] ^ W[5] ^ W[3], ( W[3] = rotate(temp, 1) )
// Q20 temp = W[1] ^ W[12] ^ W[6] ^ W[4], ( W[4] = rotate(temp, 1) )
// Q21 temp = W[2] ^ W[13] ^ W[7] ^ W[5], ( W[5] = rotate(temp, 1) )
// Q22 temp = W[3] ^ W[14] ^ W[8] ^ W[6], ( W[6] = rotate(temp, 1) )
// Q23 temp = W[4] ^ W[15] ^ W[9] ^ W[7], ( W[7] = rotate(temp, 1) )
// Q24 temp = W[5] ^ W[0] ^ W[10] ^ W[8], ( W[8] = rotate(temp, 1) )
// Q25 temp = W[6] ^ W[1] ^ W[11] ^ W[9], ( W[9] = rotate(temp, 1) )
// Q26 temp = W[7] ^ W[2] ^ W[12] ^ W[10], ( W[10] = rotate(temp, 1) )
// Q27 temp = W[8] ^ W[3] ^ W[13] ^ W[11], ( W[11] = rotate(temp, 1) )
// Q28 temp = W[9] ^ W[4] ^ W[14] ^ W[12], ( W[12] = rotate(temp, 1) )
// Q29 temp = W[10] ^ W[5] ^ W[15] ^ W[13], ( W[13] = rotate(temp, 1) )
// Q30 temp = W[11] ^ W[6] ^ W[0] ^ W[14], ( W[14] = rotate(temp, 1) )

#define Q16 (W[0] = rotate((W[2] ^ W[0]), 1U))
#define Q17 (W[1] = rotate((W[3] ^ W[1]), 1U))
#define Q18 (W[2] = rotate((W[15] ^ W[4] ^ W[2]), 1U))
#define Q19 (W[3] = rotate((W[0]  ^ W[5] ^ W[3]), 1U))
#define Q20 (W[4] = rotate((W[1] ^ W[6] ^ W[4]), 1U))
#define Q21 (W[5] = rotate((W[2] ^ W[5]), 1U))
#define Q22 (W[6] = rotate(W[3] ^ W[6], 1U))
#define Q23 (W[7] = rotate((W[4] ^ W[15]), 1U))
#define Q24 (W[8] = rotate((W[5] ^ W[0]), 1U))
#define Q25 (W[9] = rotate((W[6] ^ W[1]), 1U))
#define Q26 (W[10] = rotate((W[7] ^ W[2]), 1U))
#define Q27 (W[11] = rotate((W[8] ^ W[3]), 1U))
#define Q28 (W[12] = rotate((W[9] ^ W[4]), 1U))
#define Q29 (W[13] = rotate((W[10] ^ W[5] ^ W[15]), 1U))
#define Q30 (W[14] = rotate((W[11] ^ W[6] ^ W[0]), 1U))

#define SHA1_SHORT_END(A, B, C, D, E, W)	  \
	P1(E, A, B, C, D, Q16); \
	P1(D, E, A, B, C, Q17); \
	P1(C, D, E, A, B, Q18); \
	P1(B, C, D, E, A, Q19); \
	P2(A, B, C, D, E, Q20); \
	P2(E, A, B, C, D, Q21); \
	P2(D, E, A, B, C, Q22); \
	P2(C, D, E, A, B, Q23); \
	P2(B, C, D, E, A, Q24); \
	P2(A, B, C, D, E, Q25); \
	P2(E, A, B, C, D, Q26); \
	P2(D, E, A, B, C, Q27); \
	P2(C, D, E, A, B, Q28); \
	P2(B, C, D, E, A, Q29); \
	P2(A, B, C, D, E, Q30); \
	P2(E, A, B, C, D, R(31)); \
	P2(D, E, A, B, C, R(32)); \
	P2(C, D, E, A, B, R(33)); \
	P2(B, C, D, E, A, R(34)); \
	P2(A, B, C, D, E, R(35)); \
	P2(E, A, B, C, D, R(36)); \
	P2(D, E, A, B, C, R(37)); \
	P2(C, D, E, A, B, R(38)); \
	P2(B, C, D, E, A, R(39)); \
	P3(A, B, C, D, E, R(40)); \
	P3(E, A, B, C, D, R(41)); \
	P3(D, E, A, B, C, R(42)); \
	P3(C, D, E, A, B, R(43)); \
	P3(B, C, D, E, A, R(44)); \
	P3(A, B, C, D, E, R(45)); \
	P3(E, A, B, C, D, R(46)); \
	P3(D, E, A, B, C, R(47)); \
	P3(C, D, E, A, B, R(48)); \
	P3(B, C, D, E, A, R(49)); \
	P3(A, B, C, D, E, R(50)); \
	P3(E, A, B, C, D, R(51)); \
	P3(D, E, A, B, C, R(52)); \
	P3(C, D, E, A, B, R(53)); \
	P3(B, C, D, E, A, R(54)); \
	P3(A, B, C, D, E, R(55)); \
	P3(E, A, B, C, D, R(56)); \
	P3(D, E, A, B, C, R(57)); \
	P3(C, D, E, A, B, R(58)); \
	P3(B, C, D, E, A, R(59)); \
	P4(A, B, C, D, E, R(60)); \
	P4(E, A, B, C, D, R(61)); \
	P4(D, E, A, B, C, R(62)); \
	P4(C, D, E, A, B, R(63)); \
	P4(B, C, D, E, A, R(64)); \
	P4(A, B, C, D, E, R(65)); \
	P4(E, A, B, C, D, R(66)); \
	P4(D, E, A, B, C, R(67)); \
	P4(C, D, E, A, B, R(68)); \
	P4(B, C, D, E, A, R(69)); \
	P4(A, B, C, D, E, R(70)); \
	P4(E, A, B, C, D, R(71)); \
	P4(D, E, A, B, C, R(72)); \
	P4(C, D, E, A, B, R(73)); \
	P4(B, C, D, E, A, R(74)); \
	P4(A, B, C, D, E, R(75)); \
	P4(E, A, B, C, D, R(76)); \
	P4(D, E, A, B, C, R2(77)); \
	P4(C, D, E, A, B, R2(78)); \
	P4(B, C, D, E, A, R2(79));

#define SHA1_SHORT(A, B, C, D, E, W) SHA1_SHORT_BEG(A, B, C, D, E, W) SHA1_SHORT_END(A, B, C, D, E, W)

#define sha1_init(o) {	  \
		o[0] = INIT_A; \
		o[1] = INIT_B; \
		o[2] = INIT_C; \
		o[3] = INIT_D; \
		o[4] = INIT_E; \
	}

#define sha1_block(b, o) {	\
		A = o[0]; \
		B = o[1]; \
		C = o[2]; \
		D = o[3]; \
		E = o[4]; \
		SHA1(A, B, C, D, E, b); \
		o[0] += A; \
		o[1] += B; \
		o[2] += C; \
		o[3] += D; \
		o[4] += E; \
	}

#define sha1_block_short(b, o) {	\
		A = o[0]; \
		B = o[1]; \
		C = o[2]; \
		D = o[3]; \
		E = o[4]; \
		SHA1_SHORT(A, B, C, D, E, b); \
		o[0] += A; \
		o[1] += B; \
		o[2] += C; \
		o[3] += D; \
		o[4] += E; \
	}

__kernel void GenerateSHA1pwhash(
	__global const uint *unicode_pw,
	__global const uint *pw_len,
	__constant uint *salt,
	__global uint *pwhash)
{
	uint i;
	uint W[16];
	uint output[5];
	uint gid = get_global_id(0);
	uint A, B, C, D, E, temp;

	/* Initial hash of salt + password */
	/* The ending 0x80 is already in the buffer */
	for (i = 0; i < 4; i++)
		W[i] = SWAP32(salt[i]);
	for (i = 4; i < 16; i++)
		W[i] = SWAP32(unicode_pw[gid * (UNICODE_LENGTH>>2) + i - 4]);
	if (pw_len[gid] < 40) {
		W[14] = 0;
		W[15] = (pw_len[gid] + 16) << 3;
	}
	sha1_init(output);
	sha1_block(W, output);

	if (pw_len[gid] >= 40) {
		for (i = 0; i < 14; i++)
			W[i] = SWAP32(unicode_pw[gid * (UNICODE_LENGTH>>2) + i + 12]);
		W[14] = 0;
		W[15] = (pw_len[gid] + 16) << 3;
		sha1_block(W, output);
	}

	for (i = 0; i < 5; i++)
#ifdef SCALAR
		pwhash[gid * 6 + i] = output[i];
	pwhash[gid * 6 + 5] = 0;
#else
		pwhash[(gid >> 2) * 4 * 6 + (gid & 3) + i * 4] = output[i];
	pwhash[(gid >> 2) * 4 * 6 + (gid & 3) + 5 * 4] = 0;
#endif
}

__kernel void HashLoop(__global MAYBE_VECTOR_UINT *pwhash)
{
	uint i, j;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[5];
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;
	uint gid = get_global_id(0);
#ifdef SCALAR
	uint base = pwhash[gid * 6 + 5];
#else
	uint base = pwhash[gid * 6 + 5].s0;
#endif

	for (i = 0; i < 5; i++)
		output[i] = pwhash[gid * 6 + i];

	/* HASH_LOOPS rounds of sha1(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 0; j < HASH_LOOPS; j++)
	{
		W[0] = SWAP32(base + j);
		for (i = 1; i < 6; i++)
			W[i] = output[i - 1];
		W[6] = 0x80000000;
		//for (i = 7; i < 15; i++)
		//	W[i] = 0;
		W[15] = 24 << 3;
		sha1_init(output);
		sha1_block_short(W, output);
	}
	for (i = 0; i < 5; i++)
		pwhash[gid * 6 + i] = output[i];
	pwhash[gid * 6 + 5] += HASH_LOOPS;
}

__kernel void Generate2007key(
	__global MAYBE_VECTOR_UINT *pwhash,
	__global uint *key)
{
	uint i, j;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[5];
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;
	uint gid = get_global_id(0);

	for (i = 0; i < 5; i++)
		output[i] = pwhash[gid * 6 + i];
	/* Remainder of sha1(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 50000 - (50000 % HASH_LOOPS); j < 50000; j++)
	{
		W[0] = SWAP32(j);
		for (i = 1; i < 6; i++)
			W[i] = output[i - 1];
		W[6] = 0x80000000;
		//for (i = 7; i < 15; i++)
		//	W[i] = 0;
		W[15] = 24 << 3;
		sha1_init(output);
		sha1_block_short(W, output);
	}

	/* Final hash */
	for (i = 0; i < 5; i++)
		W[i] = output[i];
	W[5] = 0;
	W[6] = 0x80000000;
	//for (i = 7; i < 15; i++)
	//	W[i] = 0;
	W[15] = 24 << 3;
	sha1_init(output);
	sha1_block_short(W, output);

	/* DeriveKey */
	for (i = 0; i < 5; i++)
		W[i] = output[i] ^ 0x36363636;
	for (i = 5; i < 16; i++)
		W[i] = 0x36363636;
	sha1_init(output);
	sha1_block(W, output);
	/* sha1_final (last block was 64 bytes) */
	W[0] = 0x80000000;
	for (i = 1; i < 7; i++)
		W[i] = 0;
	W[15] = 64 << 3;
	sha1_block_short(W, output);

	/* Endian-swap to output (we only use 16 bytes) */
	for (i = 0; i < 4; i++) {
#ifdef SCALAR
		key[gid * 4 + i] = SWAP32(output[i]);
#else
		key[gid * 4 * 4 + i] = SWAP32(output[i].s0);
		key[(gid * 4 + 1) * 4 + i] = SWAP32(output[i].s1);
		key[(gid * 4 + 2) * 4 + i] = SWAP32(output[i].s2);
		key[(gid * 4 + 3) * 4 + i] = SWAP32(output[i].s3);
#endif
	}
}

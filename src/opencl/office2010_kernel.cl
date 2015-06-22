/*
 * Office 2010
 *
 * Copyright 2012, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * This is thanks to Dhiru writing the CPU code first!
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"

/* Office 2010/2013 */
__constant uint InputBlockKey[] = { 0xfea7d276, 0x3b4b9e79 };
__constant uint ValueBlockKey[] = { 0xd7aa0f6d, 0x3061344e };

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
	uint A, B, C, D, E, temp, a, b, c, d, e;

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
	sha1_single(W, output);

	if (pw_len[gid] >= 40) {
		for (i = 0; i < 14; i++)
			W[i] = SWAP32(unicode_pw[gid * (UNICODE_LENGTH>>2) + i + 12]);
		W[14] = 0;
		W[15] = (pw_len[gid] + 16) << 3;
		sha1_block(W, output);
	}

#ifdef SCALAR
	for (i = 0; i < 5; i++)
		pwhash[gid * 6 + i] = output[i];
	pwhash[gid * 6 + 5] = 0;
#else
#define VEC_IN(VAL)	  \
	pwhash[(gid / V_WIDTH) * 6 * V_WIDTH + (gid % V_WIDTH) + i * V_WIDTH] = (VAL)

	for (i = 0; i < 5; i++)
		VEC_IN(output[i]);
	VEC_IN(0);
#endif
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void HashLoop(__global MAYBE_VECTOR_UINT *pwhash)
{
	uint i, j;
	MAYBE_VECTOR_UINT output[5];
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
		MAYBE_VECTOR_UINT W[16];
		MAYBE_VECTOR_UINT A, B, C, D, E, temp;

		W[0] = SWAP32(base + j);
		for (i = 1; i < 6; i++)
			W[i] = output[i - 1];
		W[6] = 0x80000000;
#ifdef USE_SHA1_SHORT
		W[15] = 24 << 3;
		sha1_single_192Z(W, output);
#else
		for (i = 7; i < 15; i++)
			W[i] = 0;
		W[15] = 24 << 3;
		sha1_single(W, output);
#endif
	}
	for (i = 0; i < 5; i++)
		pwhash[gid * 6 + i] = output[i];
	pwhash[gid * 6 + 5] += HASH_LOOPS;
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void Generate2010key(
	__global MAYBE_VECTOR_UINT *pwhash,
	__global uint *key,
	__constant uint *spincount)
{
	uint i, j;
	MAYBE_VECTOR_UINT W[16], output[5], hash[5];
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;
	uint gid = get_global_id(0);
#ifdef SCALAR
	uint base = pwhash[gid * 6 + 5];
#else
	uint base = pwhash[gid * 6 + 5].s0;
#endif
	uint iterations = *spincount % HASH_LOOPS;

	for (i = 0; i < 5; i++)
		output[i] = pwhash[gid * 6 + i];
	/* Remainder of sha1(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 0; j < iterations; j++)
	{
		W[0] = SWAP32(base + j);
		for (i = 1; i < 6; i++)
			W[i] = output[i - 1];
		W[6] = 0x80000000;
#ifdef USE_SHA1_SHORT
		W[15] = 24 << 3;
		sha1_single_192Z(W, output);
#else
		for (i = 7; i < 15; i++)
			W[i] = 0;
		W[15] = 24 << 3;
		sha1_single(W, output);
#endif
	}

	/* Our sha1 destroys input so we store it in hash[] */
	for (i = 0; i < 5; i++)
		W[i] = hash[i] = output[i];

	/* Final hash 1 */
	W[5] = InputBlockKey[0];
	W[6] = InputBlockKey[1];
	W[7] = 0x80000000;
	for (i = 8; i < 15; i++)
		W[i] = 0;
	W[15] = 28 << 3;
	sha1_single(W, output);

	/* Endian-swap to output (we only use 16 bytes) */
	for (i = 0; i < 4; i++)
#ifdef SCALAR
		key[gid * 32/4 + i] = SWAP32(output[i]);
#else

#define VEC_OUT(NUM)	  \
	key[(gid * V_WIDTH + 0x##NUM) * 32/4 + i] = \
		SWAP32(output[i].s##NUM)

	{
		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
	/* Final hash 2 */
	for (i = 0; i < 5; i++)
		W[i] = hash[i];
	W[5] = ValueBlockKey[0];
	W[6] = ValueBlockKey[1];
	W[7] = 0x80000000;
	for (i = 8; i < 15; i++)
		W[i] = 0;
	W[15] = 28 << 3;
	sha1_single(W, output);

	/* Endian-swap to output (we only use 16 bytes) */
	for (i = 0; i < 4; i++)
#ifdef SCALAR
		key[gid * 32/4 + 16/4 + i] = SWAP32(output[i]);
#else

#undef VEC_OUT
#define VEC_OUT(NUM)	  \
	key[(gid * V_WIDTH + 0x##NUM) * 32/4 + 16/4 + i] = \
		SWAP32(output[i].s##NUM)

	{
		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
}

/*
 * Office 2013
 *
 * Copyright (c) 2012-2014, magnum
 * Copyright (c) 2012, 2013 Lukas Odzioba <ukasz at openwall dot net>
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * This is thanks to Dhiru writing the CPU code first!
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha2.h"

/* Office 2010/2013 */
__constant ulong InputBlockKey = 0xfea7d2763b4b9e79UL;
__constant ulong ValueBlockKey = 0xd7aa0f6d3061344eUL;

__kernel void GenerateSHA512pwhash(
	__global const ulong *unicode_pw,
	__global const uint *pw_len,
	__constant ulong *salt,
	__global ulong *pwhash)
{
	uint i;
	ulong block[16];
	ulong output[8];
	uint gid = get_global_id(0);

	/* Initial hash of salt + password */
	/* The ending 0x80 is already in the buffer */
	for (i = 0; i < 2; i++)
		block[i] = SWAP64(salt[i]);
	for (i = 2; i < 14; i++)
		block[i] = SWAP64(unicode_pw[gid * (UNICODE_LENGTH >> 3) + i - 2]);
	block[14] = 0;
	block[15] = (ulong)(pw_len[gid] + 16) << 3;
	sha512_single_s(block, output);

#ifdef SCALAR
	for (i = 0; i < 8; i++)
		pwhash[gid * 9 + i] = output[i];
	pwhash[gid * 9 + 8] = 0;
#else

#define VEC_IN(VAL)	  \
	pwhash[(gid / V_WIDTH) * V_WIDTH * 9 + (gid & (V_WIDTH - 1)) + i * V_WIDTH] = (VAL)

	for (i = 0; i < 8; i++)
		VEC_IN(output[i]);
	VEC_IN(0);
#endif
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_ULONG)))
void HashLoop(__global MAYBE_VECTOR_ULONG *pwhash)
{
	uint i, j;
	MAYBE_VECTOR_ULONG output[8];
	uint gid = get_global_id(0);
#ifdef SCALAR
	uint base = pwhash[gid * 9 + 8];
#else
	uint base = pwhash[gid * 9 + 8].s0;
#endif

	for (i = 0; i < 8; i++)
		output[i] = pwhash[gid * 9 + i];

	/* HASH_LOOPS rounds of sha512(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 0; j < HASH_LOOPS; j++)
	{
		MAYBE_VECTOR_ULONG block[16];

		block[0] = ((ulong)SWAP32(base + j) << 32) | (output[0] >> 32);
		for (i = 1; i < 8; i++)
			block[i] = (output[i - 1] << 32) | (output[i] >> 32);
		block[8] = (output[7] << 32) | 0x80000000UL;
		//for (i = 9; i < 15; i++)
		//	block[i] = 0;
		block[15] = 68 << 3;
		sha512_single_zeros(block, output);
	}
	for (i = 0; i < 8; i++)
		pwhash[gid * 9 + i] = output[i];
	pwhash[gid * 9 + 8] += HASH_LOOPS;
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_ULONG)))
void Generate2013key(
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

	for (i = 0; i < 8; i++)
		output[i] = pwhash[gid * 9 + i];

	/* Remainder of iterations */
	for (j = 0; j < iterations; j++)
	{
		block[0] = ((ulong)SWAP32(base + j) << 32) | (output[0] >> 32);
		for (i = 1; i < 8; i++)
			block[i] = (output[i - 1] << 32) | (output[i] >> 32);
		block[8] = (output[7] << 32) | 0x80000000UL;
		//for (i = 9; i < 15; i++)
		//	block[i] = 0;
		block[15] = 68 << 3;
		sha512_single_zeros(block, output);
	}

	/* Our sha512 destroys input so we store a needed portion in temp[] */
	for (i = 0; i < 8; i++)
		block[i] = temp[i] = output[i];

	/* Final hash 1 */
	block[8] = InputBlockKey;
	block[9] = 0x8000000000000000UL;
	for (i = 10; i < 15; i++)
		block[i] = 0;
	block[15] = 72 << 3;
	sha512_single(block, output);

	/* Endian-swap to hash 1 output */
	for (i = 0; i < 8; i++)
#ifdef SCALAR
		key[gid * 128/8 + i] = SWAP64(output[i]);
#else

#define VEC_OUT(NUM)	  \
	key[(gid * V_WIDTH + 0x##NUM) * 128/8 + i] = \
		SWAP64(output[i].s##NUM)

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
	for (i = 0; i < 8; i++)
		block[i] = temp[i];
	block[8] = ValueBlockKey;
	block[9] = 0x8000000000000000UL;
	for (i = 10; i < 15; i++)
		block[i] = 0;
	block[15] = 72 << 3;
#if gpu_amd(DEVICE_INFO)
	/* Workaround for Catalyst 14.4-14.6 driver bug */
	barrier(CLK_GLOBAL_MEM_FENCE);
#endif
	sha512_single(block, output);

	/* Endian-swap to hash 2 output */
	for (i = 0; i < 8; i++)
#ifdef SCALAR
		key[gid * 128/8 + 64/8 + i] = SWAP64(output[i]);
#else

#undef VEC_OUT
#define VEC_OUT(NUM)	  \
	key[(gid * V_WIDTH + 0x##NUM) * 128/8 + 64/8 + i] = \
		SWAP64(output[i].s##NUM)

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

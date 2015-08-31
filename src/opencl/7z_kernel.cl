/*
 * This software is
 * Copyright (c) 2015 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha2.h"

#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)

#define sha256_mblock(block, o, blocklen)	  \
	{ \
		uint *b = block; \
		uint blocks = blocklen; \
		while (blocks--) { \
			uint A, B, C, D, E, F, G, H, t; \
			uint W[16]; \
			uint i; \
			for (i = 0; i < 16; i++) \
				W[i] = b[i]; \
			A = o[0]; \
			B = o[1]; \
			C = o[2]; \
			D = o[3]; \
			E = o[4]; \
			F = o[5]; \
			G = o[6]; \
			H = o[7]; \
			SHA256(A,B,C,D,E,F,G,H); \
			o[0] += A; \
			o[1] += B; \
			o[2] += C; \
			o[3] += D; \
			o[4] += E; \
			o[5] += F; \
			o[6] += G; \
			o[7] += H; \
			b += 16; \
		} \
	}

inline void sha256_zerofinal(uint *W, uint *output, const uint tot_len)
{
	uint len = ((tot_len & 63) >> 2) + 1;

	LASTCHAR_BE(W, tot_len & 63, 0x80);

	while (len < 15)
		W[len++] = 0;
	W[15] = tot_len << 3;
	sha256_block(W, output);
}

typedef struct {
	uint length;
	ushort v[PLAINTEXT_LENGTH];
} sevenzip_password;

typedef struct {
	uint round;
	uint key[32/4];
} sevenzip_hash;

typedef struct {
	uint length;
	uint iterations;
	uchar salt[16];
} sevenzip_salt;

__kernel void sevenzip_init(__global sevenzip_hash *outbuffer)
{
	uint gid = get_global_id(0);
	uint i, output[8];

	outbuffer[gid].round = 0;
	sha256_init(output);

	for (i = 0; i < 8; i++)
		outbuffer[gid].key[i] = output[i];
}

__kernel void sevenzip_loop(__global const sevenzip_password *inbuffer,
                            __global const sevenzip_salt *salt,
                            __global sevenzip_hash *outbuffer)
{
	const uint gid = get_global_id(0);
	const uint pwlen = inbuffer[gid].length;
	const uint blocklen = pwlen + 8;
	uint round = outbuffer[gid].round;
	uint block[(UNICODE_LENGTH + 8) * 32/4];
	uint output[8];
	uint i, j;

	for (i = 0; i < 8; i++)
		output[i] = outbuffer[gid].key[i];

	/* Prepare a 32x buffer (always ends at SHA-256 block boundary) */
	for (i = 0; i < 32; i++) {
		for (j = 0; j < pwlen; j++)
			PUTCHAR_BE(block, i * blocklen + j, GETCHAR_G(inbuffer[gid].v, j));
		PUTCHAR_BE(block, i * blocklen + pwlen + 2, round >> 16);
		for (j = 3; j < 8; j++)
			PUTCHAR_BE(block, i * blocklen + pwlen + j, 0);
	}

	/*
	 * Hysterically optimized inner loop.
	 */
	for (j = 0; j < (HASH_LOOPS / 32); j++) {
#pragma unroll
		for (i = 0; i < 32; i++, round++) {
			PUTCHAR_BE(block, i * blocklen + pwlen + 0, round & 0xff);
			if (!(j & 7))
				PUTCHAR_BE(block, i * blocklen + pwlen + 1, (round >> 8) & 0xff);
		}
		sha256_mblock(block, output, blocklen>>1);
	}

	for (i = 0; i < 8; i++)
		outbuffer[gid].key[i] = output[i];
	outbuffer[gid].round = round;
}

__kernel void sevenzip_final(__global const sevenzip_password *inbuffer,
                             __global const sevenzip_salt *salt,
                             __global sevenzip_hash *outbuffer)
{
	uint gid = get_global_id(0);
	uint block[16], output[8];
	uint i;
	uint pwlen = inbuffer[gid].length;

	for (i = 0; i < 8; i++)
		output[i] = outbuffer[gid].key[i];

	/* This is always an empty block (except length) */
	sha256_zerofinal(block, output, (pwlen + 8) * (1U << salt->iterations));

	for (i = 0; i < 8; i++)
		outbuffer[gid].key[i] = SWAP32(output[i]);
}

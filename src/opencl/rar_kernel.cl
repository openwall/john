/*
 * RAR key & iv generation (256K x SHA-1), Copyright 2012, magnum
 *
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * This code is based on the work of Alexander L. Roshal (C)
 *
 * The unRAR sources may be used in any software to handle RAR
 * archives without limitations free of charge, but cannot be used
 * to re-create the RAR compression algorithm, which is proprietary.
 * Distribution of modified unRAR sources in separate form or as a
 * part of other software is permitted, provided that it is clearly
 * stated in the documentation and source comments that the code may
 * not be used to develop a RAR (WinRAR) compatible archiver.
 *
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"

#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define ROUNDS			0x40000

/*
 * This version does several blocks at a time
 */
inline void sha1_mblock(uint *W, uint *out, uint blocks)
{
	uint i;
	uint output[5];

	for (i = 0; i < 5; i++)
		output[i] = out[i];

	while (blocks--) {
		sha1_block(uint, W, output);
		W += 16;
	}

	for (i = 0; i < 5; i++)
		out[i] = output[i];
}

inline void sha1_empty_final(uint *W, uint *output, const uint tot_len)
{
	uint len = ((tot_len & 63) >> 2) + 1;

	LASTCHAR_BE(W, tot_len & 63, 0x80);

	while (len < 15)
		W[len++] = 0;
	W[15] = tot_len << 3;
	sha1_block(uint, W, output);
}

__kernel void RarInit(__global uint *OutputBuf, __global uint *round)
{
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint i, output[5];

	round[gid] = 0;
	sha1_init(output);

	for (i = 0; i < 5; i++)
		OutputBuf[i * gws + gid] = output[i];
}

/* This kernel is called 16 times in a row (at HASH_LOOPS == 0x4000) */
__kernel void RarHashLoop(
	const __global uint *unicode_pw,
	const __global uint *pw_len,
	__global uint *round_p,
	__global uint *OutputBuf,
	__constant uint *salt,
	__global uint *aes_iv)
{
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint block[(UNICODE_LENGTH + 11) * 16];
	uint output[5];
	const uint pwlen = pw_len[gid];
	const uint blocklen = pwlen + 11;
	uint round = round_p[gid];
	uint i, j;

	for (i = 0; i < 5; i++)
		output[i] = OutputBuf[i * gws + gid];

	/* Copy to 64x buffer (always ends at SHA-1 block boundary) */
	for (i = 0; i < 64; i++) {
		for (j = 0; j < pwlen; j++)
			PUTCHAR_BE(block, i * blocklen + j, GETCHAR_G(unicode_pw, gid * UNICODE_LENGTH + j));
		for (j = 0; j < 8; j++)
			PUTCHAR_BE(block, i * blocklen + pwlen + j, ((__constant uchar*)salt)[j]);
		PUTCHAR_BE(block, i * blocklen + pwlen + 10, round >> 16);
	}

	/* Get IV */
#if ROUNDS / HASH_LOOPS != 16
	if ((round % (ROUNDS / 16)) == 0)
#endif
	{
		uint W[16], tempout[5];

		for (i = 0; i < 5; i++)
			tempout[i] = output[i];
		for (i = 0; i < (UNICODE_LENGTH + 8) / 4; i++)
			W[i] = block[i];

		PUTCHAR_BE(W, pwlen + 8, round & 255);
		PUTCHAR_BE(W, pwlen + 9, (round >> 8) & 255);

		sha1_empty_final(W, tempout, blocklen * (round + 1));

		PUTCHAR_G(aes_iv, gid * 16 + (round >> 14), GETCHAR(tempout, 16));
	}

	/*
	 * The inner loop. Compared to earlier revisions of this kernel
	 * this is really a piece of art
	 */
	for (j = 0; j < (HASH_LOOPS / 64); j++) {
#pragma unroll
		for (i = 0; i < 64; i++, round++) {
			PUTCHAR_BE(block, i * blocklen + pwlen + 8, round & 0xff);
			if (!(j & 3))
				PUTCHAR_BE(block, i * blocklen + pwlen + 9, (round >> 8) & 0xff);
		}
		sha1_mblock(block, output, blocklen);
	}

	for (i = 0; i < 5; i++)
		OutputBuf[i * gws + gid] = output[i];
	round_p[gid] = round;
}

__kernel void RarFinal(
	const __global uint *pw_len,
	__global uint *OutputBuf,
	__global uint *aes_key)
{
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint block[16], output[5];
	uint i;

	for (i = 0; i < 5; i++)
		output[i] = OutputBuf[i * gws + gid];

	/* This is always an empty block (except length) */
	sha1_empty_final(block, output, (pw_len[gid] + 8 + 3) * ROUNDS);

	/* No endian-swap and we only use first 128 bits */
	for (i = 0; i < 4; i++)
		aes_key[gid * 4 + i] = output[i];
}

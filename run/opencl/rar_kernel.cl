/*
 * RAR key & iv generation (256K x SHA-1) plus early-rejection,
 * Copyright 2012-2020, magnum
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
#define AES_SRC_TYPE __global const
#define AES_KEY_TYPE __global const
#include "opencl_aes.h"
#include "opencl_crc32.h"

#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define ROUNDS			0x40000

typedef struct {
	uint round;
	uint sha[5]; /* When finished sha[0..3] is the AES key, sha[4] is early reject flag */
	uint iv[4];
} rar_out;

typedef struct {
	uint64_t pack_size;
	uint64_t unp_size;
	uint64_t gpu_size;
	uchar last_iv[16];
	uchar last_data[16];
	int type;	/* 0 = -hp, 1 = -p */
	/* for rar -p mode only: */
	union {
		uint w;
		uchar c[4];
	} crc;
	int method;
	uchar data[1];
} rar_file;

/*
 * This version does several blocks at a time
 */
inline void sha1_mblock(uint *W, uint *out, uint blocks)
{
	uint i;
	uint ctx[5];

	for (i = 0; i < 5; i++)
		ctx[i] = out[i];

	while (blocks--) {
		sha1_block(uint, W, ctx);
		W += 16;
	}

	for (i = 0; i < 5; i++)
		out[i] = ctx[i];
}

inline void sha1_empty_final(uint *W, uint *ctx, const uint tot_len)
{
	uint len = ((tot_len & 63) >> 2) + 1;

	LASTCHAR_BE(W, tot_len & 63, 0x80);

	while (len < 15)
		W[len++] = 0;
	W[15] = tot_len << 3;
	sha1_block(uint, W, ctx);
}

__kernel void RarInit(__global rar_out *output)
{
	uint gid = get_global_id(0);
	uint i, ctx[5];

	output[gid].round = 0;
	sha1_init(ctx);

	for (i = 0; i < 5; i++)
		output[gid].sha[i] = ctx[i];
}

/* This kernel is called 16 times in a row (at HASH_LOOPS == 0x4000) */
__kernel void RarHashLoop(const __global uint *unicode_pw, const __global uint *pw_len,
                          __global rar_out *output, __constant uint *salt)
{
	uint gid = get_global_id(0);
	uint block[(UNICODE_LENGTH + 11) * 16];
	uint ctx[5];
	const uint pwlen = pw_len[gid];
	const uint blocklen = pwlen + 11;
	uint round = output[gid].round;
	uint i, j;

	for (i = 0; i < 5; i++)
		ctx[i] = output[gid].sha[i];

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
			tempout[i] = ctx[i];
		for (i = 0; i < (UNICODE_LENGTH + 8) / 4; i++)
			W[i] = block[i];

		PUTCHAR_BE(W, pwlen + 8, round & 255);
		PUTCHAR_BE(W, pwlen + 9, (round >> 8) & 255);

		sha1_empty_final(W, tempout, blocklen * (round + 1));

		PUTCHAR_G(output[gid].iv, round >> 14, GETCHAR(tempout, 16));
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
		sha1_mblock(block, ctx, blocklen);
	}

	output[gid].round = round;
	for (i = 0; i < 5; i++)
		output[gid].sha[i] = ctx[i];
}

#define ADD_BITS(n)	\
	{ \
		if (bits < 9) { \
			hold |= ((uint)*next++ << (24U - bits)); \
			bits += 8; \
		} \
		hold <<= n; \
		bits -= n; \
	}

/*
 * Input is first 16 bytes of RAR buffer decrypted, as-is. It also contain the
 * first 2 bits, which have already been decoded, and have told us we had an
 * LZ block (RAR always use dynamic Huffman table) and keepOldTable was not set.
 *
 * RAR use 20 x (4 bits length, optionally 4 bits zerocount), and reversed
 * byte order.
 *
 * Returns 0 for early rejection, 1 if passed
 */
inline int check_huffman(uchar *next) {
	uint bits, hold, i;
	int left;
	uint ncount[4] = { 0 };
	uchar *count = (uchar*)ncount;
	uchar bit_length[20];

	hold = next[3] + (((uint)next[2]) << 8) + (((uint)next[1]) << 16) + (((uint)next[0]) << 24);

	next += 4;	// we already have the first 32 bits
	hold <<= 2;	// we already processed 2 bits, PPM and keepOldTable
	bits = 32 - 2;

	/* First, read 20 pairs of (bitlength[, zerocount]) */
	for (i = 0 ; i < 20 ; i++) {
		int length, zero_count;

		length = hold >> 28;
		ADD_BITS(4);
		if (length == 15) {
			zero_count = hold >> 28;
			ADD_BITS(4);
			if (zero_count == 0) {
				bit_length[i] = 15;
			} else {
				zero_count += 2;
				while (zero_count-- > 0 && i < sizeof(bit_length) / sizeof(*bit_length))
					bit_length[i++] = 0;
				i--;
			}
		} else {
			bit_length[i] = length;
		}
	}

	/* Count the number of codes for each code length */
	for (i = 0; i < 20; i++) {
		++count[bit_length[i]];
	}

	count[0] = 0;
	if (!ncount[0] && !ncount[1] && !ncount[2] && !ncount[3])
		return 0; /* No codes at all */

	left = 1;
	for (i = 1; i < 16; ++i) {
		left <<= 1;
		left -= count[i];
		if (left < 0) {
			return 0; /* over-subscribed */
		}
	}
	if (left) {
		return 0; /* incomplete set */
	}
	return 1; /* Passed this check! */
}

/*
 * Returns 0 for early rejection, 1 if passed
 */
inline int check_rar(__global rar_file *cur_file, __global uint *_key, __global uint *_iv)
{
	AES_KEY aes_ctx;
	uchar iv[16];
	uchar plain[16 + 8]; /* Some are safety margin for check_huffman() */
	__global uchar *key = (__global uchar*)_key;

	if (cur_file->type == 0) {	/* rar-hp mode */
		memcpy_gp(iv, _iv, 16);
		AES_set_decrypt_key(key, 128, &aes_ctx);
		AES_cbc_decrypt(cur_file->data, plain, 16, &aes_ctx, iv);

		return !memcmp_pc(plain, "\xc4\x3d\x7b\x00\x40\x07\x00", 7);
	} else {
		if (cur_file->method == 0x30) {	/* Stored, not deflated */
			uint64_t size = cur_file->unp_size;
			__global uchar *cipher = cur_file->data;

			/* Check zero-padding */
			if (cur_file->unp_size % 16) {
				const int pad_start = cur_file->unp_size % 16;
				const int pad_size = 16 - pad_start;

				if (cur_file->pack_size == 16)
					memcpy_gp(iv, _iv, 16);
				else
					memcpy_gp(iv, cur_file->last_iv, 16);

				AES_set_decrypt_key(key, 128, &aes_ctx);
				AES_cbc_decrypt(cur_file->last_data, plain, 16, &aes_ctx, iv);

				if (memcmp_pc(&plain[pad_start], "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", pad_size))
					return 0;
			}

			if (cur_file->gpu_size < cur_file->pack_size)
				/* Need to check full size on CPU */
				return 1;

			CRC32_t crc;
			uchar crc_out[4];

			/* Full decryption with CRC check */
			memcpy_gp(iv, _iv, 16);
			AES_set_decrypt_key(key, 128, &aes_ctx);
			CRC32_Init(&crc);

			while (size) {
				uint inlen = (size > 16) ? 16 : size;

				AES_cbc_decrypt(cipher, plain, 16, &aes_ctx, iv);
				CRC32_Update(&crc, plain, inlen);
				size -= inlen;
				cipher += inlen;
			}
			CRC32_Final(crc_out, crc);

			/* Compare computed CRC with stored CRC */
			return !memcmp_pg(crc_out, cur_file->crc.c, 4);

		} else { /* Method 0x31 .. 0x35, RAR deflated */

			/* Decrypt just one block for early rejection */
			memcpy_gp(iv, _iv, 16);
			AES_set_decrypt_key(key, 128, &aes_ctx);
			AES_cbc_decrypt(cur_file->data, plain, 16, &aes_ctx, iv);

			if (plain[0] & 0x80) {
				/* Early rejection for PPM */
				if (!(plain[0] & 0x20) || (plain[1] & 0x80))
					return 0;
			} else {
				/* Early rejection for LZ */
				if ((plain[0] & 0x40) || !check_huffman(plain))
					return 0;
			}

			/* unpack29 needed CPU-side */
			return 1;
		}
	}
}

__kernel void RarFinal(const __global uint *pw_len, __global rar_out *output)
{
	uint gid = get_global_id(0);
	uint block[16], ctx[5];
	uint i;

	for (i = 0; i < 5; i++)
		ctx[i] = output[gid].sha[i];

	/* This is always an empty block (except length) */
	sha1_empty_final(block, ctx, (pw_len[gid] + 8 + 3) * ROUNDS);

	/* No endian-swap and we only use first 128 bits */
	for (i = 0; i < 4; i++)
		output[gid].sha[i] = ctx[i];
}

__kernel void RarCheck(__global rar_out *output, __global rar_file *file)
{
	uint gid = get_global_id(0);

	/* GPU-side early reject */
	output[gid].sha[4] = check_rar(file, output[gid].sha, output[gid].iv);
}

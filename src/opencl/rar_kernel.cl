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

#if gpu_nvidia(DEVICE_INFO) || amd_gcn(DEVICE_INFO)
#define SCALAR
#endif

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define ROUNDS			0x40000

/* Macros for reading/writing chars from int32's */
#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define GETCHAR_G(buf, index) (((const __global uchar*)(buf))[(index)])
#define LASTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & (0xffffff00U << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))

#if gpu_nvidia(DEVICE_INFO)
#define GETCHAR_BE(buf, index) (((__local uchar*)(buf))[(index) ^ 3])
#else
#define GETCHAR_BE(buf, index) (((uchar*)(buf))[(index) ^ 3])
#endif

#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)

/* These use 32-bit stores */
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))
#define PUTCHAR_G	PUTCHAR
#define PUTCHAR_BE_G	PUTCHAR_BE

#else

/* These use byte-adressed stores */
#define PUTCHAR(buf, index, val) ((uchar*)(buf))[(index)] = (val)
#define PUTCHAR_G(buf, index, val) ((__global uchar*)(buf))[(index)] = (val)
#define PUTCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] = (val)
#define PUTCHAR_BE_G(buf, index, val) ((__global uchar*)(buf))[(index) ^ 3] = (val)

#endif

#ifdef SCALAR
inline uint SWAP32(uint x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#else
#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))
#endif

/* SHA1 constants and IVs */
#define K0	0x5A827999
#define K1	0x6ED9EBA1
#define K2	0x8F1BBCDC
#define K3	0xCA62C1D6

#define H1	0x67452301
#define H2	0xEFCDAB89
#define H3	0x98BADCFE
#define H4	0x10325476
#define H5	0xC3D2E1F0

/* raw'n'lean sha1, context kept in output buffer */
inline void sha1_block(uint *W, uint *output) {
	uint A, B, C, D, E, temp;

	A = output[0];
	B = output[1];
	C = output[2];
	D = output[3];
	E = output[4];

#undef R
#define R(t)	  \
	( \
		temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( W[t & 0x0F] = rotate(temp, 1U) ) \
		)

#undef P
#define P(a,b,c,d,e,x)	\
	{ \
		e += rotate(a, 5U) + F(b,c,d) + K + x; \
		b = rotate(b, 30U); \
	}

#ifdef USE_BITSELECT
#define F(x,y,z)	bitselect(z, y, x)
#else
#define F(x,y,z)	(z ^ (x & (y ^ z)))
#endif

#define K		0x5A827999

	P( A, B, C, D, E, W[0]  );
	P( E, A, B, C, D, W[1]  );
	P( D, E, A, B, C, W[2]  );
	P( C, D, E, A, B, W[3]  );
	P( B, C, D, E, A, W[4]  );
	P( A, B, C, D, E, W[5]  );
	P( E, A, B, C, D, W[6]  );
	P( D, E, A, B, C, W[7]  );
	P( C, D, E, A, B, W[8]  );
	P( B, C, D, E, A, W[9]  );
	P( A, B, C, D, E, W[10] );
	P( E, A, B, C, D, W[11] );
	P( D, E, A, B, C, W[12] );
	P( C, D, E, A, B, W[13] );
	P( B, C, D, E, A, W[14] );
	P( A, B, C, D, E, W[15] );
	P( E, A, B, C, D, R(16) );
	P( D, E, A, B, C, R(17) );
	P( C, D, E, A, B, R(18) );
	P( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z)	(x ^ y ^ z)
#define K		0x6ED9EBA1

	P( A, B, C, D, E, R(20) );
	P( E, A, B, C, D, R(21) );
	P( D, E, A, B, C, R(22) );
	P( C, D, E, A, B, R(23) );
	P( B, C, D, E, A, R(24) );
	P( A, B, C, D, E, R(25) );
	P( E, A, B, C, D, R(26) );
	P( D, E, A, B, C, R(27) );
	P( C, D, E, A, B, R(28) );
	P( B, C, D, E, A, R(29) );
	P( A, B, C, D, E, R(30) );
	P( E, A, B, C, D, R(31) );
	P( D, E, A, B, C, R(32) );
	P( C, D, E, A, B, R(33) );
	P( B, C, D, E, A, R(34) );
	P( A, B, C, D, E, R(35) );
	P( E, A, B, C, D, R(36) );
	P( D, E, A, B, C, R(37) );
	P( C, D, E, A, B, R(38) );
	P( B, C, D, E, A, R(39) );

#undef K
#undef F

#ifdef USE_BITSELECT
#define F(x,y,z)	(bitselect(x, y, z) ^ bitselect(x, 0U, y))
#else
#define F(x,y,z)	((x & y) | (z & (x | y)))
#endif
#define K		0x8F1BBCDC

	P( A, B, C, D, E, R(40) );
	P( E, A, B, C, D, R(41) );
	P( D, E, A, B, C, R(42) );
	P( C, D, E, A, B, R(43) );
	P( B, C, D, E, A, R(44) );
	P( A, B, C, D, E, R(45) );
	P( E, A, B, C, D, R(46) );
	P( D, E, A, B, C, R(47) );
	P( C, D, E, A, B, R(48) );
	P( B, C, D, E, A, R(49) );
	P( A, B, C, D, E, R(50) );
	P( E, A, B, C, D, R(51) );
	P( D, E, A, B, C, R(52) );
	P( C, D, E, A, B, R(53) );
	P( B, C, D, E, A, R(54) );
	P( A, B, C, D, E, R(55) );
	P( E, A, B, C, D, R(56) );
	P( D, E, A, B, C, R(57) );
	P( C, D, E, A, B, R(58) );
	P( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z)	(x ^ y ^ z)
#define K		0xCA62C1D6

	P( A, B, C, D, E, R(60) );
	P( E, A, B, C, D, R(61) );
	P( D, E, A, B, C, R(62) );
	P( C, D, E, A, B, R(63) );
	P( B, C, D, E, A, R(64) );
	P( A, B, C, D, E, R(65) );
	P( E, A, B, C, D, R(66) );
	P( D, E, A, B, C, R(67) );
	P( C, D, E, A, B, R(68) );
	P( B, C, D, E, A, R(69) );
	P( A, B, C, D, E, R(70) );
	P( E, A, B, C, D, R(71) );
	P( D, E, A, B, C, R(72) );
	P( C, D, E, A, B, R(73) );
	P( B, C, D, E, A, R(74) );
	P( A, B, C, D, E, R(75) );
	P( E, A, B, C, D, R(76) );
	P( D, E, A, B, C, R(77) );
	P( C, D, E, A, B, R(78) );
	P( B, C, D, E, A, R(79) );

#undef K
#undef F

	output[0] += A;
	output[1] += B;
	output[2] += C;
	output[3] += D;
	output[4] += E;
}

#define sha1_init(output) {	  \
		output[0] = H1; \
		output[1] = H2; \
		output[2] = H3; \
		output[3] = H4; \
		output[4] = H5; \
	}

inline void sha1_final(uint *W, uint *output, const uint tot_len)
{
	uint len = ((tot_len & 63) >> 2) + 1;

	LASTCHAR_BE(W, tot_len & 63, 0x80);

#if UNICODE_LENGTH > 45
	if (len > 13) {
		sha1_block(W, output);
		len = 0;
	}
#endif
	while (len < 15)
		W[len++] = 0;
	W[15] = tot_len << 3;
	sha1_block(W, output);
}

__kernel void RarInit(
	const __global uint *unicode_pw,
	const __global uint *pw_len,
	__constant uint *salt,
	__global uint *RawBuf,
	__global uint *OutputBuf,
	__global uint *round)
{
	uint gid = get_global_id(0);
	__global uint *RawPsw = &RawBuf[gid * (UNICODE_LENGTH + 8) / 4];
	__global uint *output = &OutputBuf[gid * 5];
	uint pwlen = pw_len[gid];
	uint i;

	/* Copy to 1x buffer */
	for (i = 0; i < (pwlen + 3) >> 2; i++)
		RawPsw[i] = SWAP32(unicode_pw[gid * UNICODE_LENGTH / 4 + i]);
#pragma unroll
	for (i = 0; i < 8; i++)
		PUTCHAR_BE_G(RawPsw, pwlen + i, ((__constant uchar*)salt)[i]);
	round[gid] = 0;
	sha1_init(output);
}

__kernel void RarGetIV(
	const __global uint *pw_len,
	const __global uint *RawBuf,
	__global uint *OutputBuf,
	__global uint *round_p,
	__global uint *aes_iv)
{
	uint gid = get_global_id(0);
	uint block[16], output[5];
	uint pwlen = pw_len[gid];
	uint round = round_p[gid];
	uint i;

#pragma unroll
	for (i = 0; i < 5; i++)
		output[i] = OutputBuf[gid * 5 + i];
#pragma unroll
	for (i = 0; i < (UNICODE_LENGTH + 8) / 4; i++)
		block[i] = RawBuf[gid * (UNICODE_LENGTH + 8) / 4 + i];

	PUTCHAR_BE(block, pwlen + 8, round & 255);
	PUTCHAR_BE(block, pwlen + 9, (round >> 8) & 255);
	PUTCHAR_BE(block, pwlen + 10, round >> 16);

#ifdef APPLE
	/* This is the weirdest workaround. Using the sha1_final()
	   works perfectly fine in the RarFinal() subkernel below. */
	PUTCHAR_BE(block, pwlen + 11, 0x80);
	for (i = pwlen + 12; i < 56; i++)
		PUTCHAR_BE(block, pwlen + i, 0);
	block[14] = 0;
	block[15] = ((pwlen + 8 + 3) * (round + 1)) << 3;
	sha1_block(block, output);
#else
	sha1_final(block, output, (pwlen + 8 + 3) * (round + 1));
#endif
	PUTCHAR_G(aes_iv, gid * 16 + (round >> 14), GETCHAR(output, 16));
}

__kernel void RarHashLoop(
	const __global uint *pw_len,
	__global uint *round_p,
	const __global uint *RawBuf,
	__global uint *OutputBuf
#if gpu_nvidia(DEVICE_INFO)
	, __local uint *LocBuf
#endif
	)
{
	uint gid = get_global_id(0);
	uint block[2][16];
	uint output[5];
#if gpu_nvidia(DEVICE_INFO)
	__local uint *RawPsw = &LocBuf[get_local_id(0) * (UNICODE_LENGTH + 8) / 4];
#else
	uint RawPsw[(UNICODE_LENGTH + 8) / 4];
#endif
	uint blocklen = pw_len[gid] + 11;
	uint round = round_p[gid];
	uint i;

#pragma unroll
	for (i = 0; i < (UNICODE_LENGTH + 8) / 4; i++)
		RawPsw[i] = RawBuf[gid * (UNICODE_LENGTH + 8) / 4 + i];

#pragma unroll
	for (i = 0; i < 5; i++)
		output[i] = OutputBuf[gid * 5 + i];

	for (i = 0; i < HASH_LOOPS; i++) {
		uint len = 0, b = 0, j;

		for (j = 0; j < blocklen; j++) {
			do {
				/* At odd character lengths, alignment is 01230123
				 * At even lengths, it is 03210321 */
				switch (len & 3) {
					uint k;

				case 0: /* 32-bit aligned! */
					block[0][((len >> 2) + 0) & 31] = RawPsw[0];
					block[0][((len >> 2) + 1) & 31] = RawPsw[1];
					block[0][((len >> 2) + 2) & 31] = RawPsw[2];
					for (k = 3; k < blocklen >> 2; k++)
						block[0][((len >> 2) + k) & 31] = RawPsw[k];
					break;
				case 1: /* unaligned mod 1 */
					PUTCHAR_BE(block[0], (len + 0) & 127, GETCHAR_BE(RawPsw, 0));
					PUTCHAR_BE(block[0], (len + 1) & 127, GETCHAR_BE(RawPsw, 1));
					PUTCHAR_BE(block[0], (len + 2) & 127, GETCHAR_BE(RawPsw, 2));
					block[0][((len >> 2) + 0 + 1) & 31] = (RawPsw[0] << 24) + (RawPsw[1] >> 8);
					block[0][((len >> 2) + 1 + 1) & 31] = (RawPsw[1] << 24) + (RawPsw[2] >> 8);
					for (k = 2; k < (blocklen >> 2) - 1; k++)
						block[0][((len >> 2) + k + 1) & 31] = (RawPsw[k] << 24) + (RawPsw[k + 1] >> 8);
					block[0][((len >> 2) + k + 1) & 31] = (RawPsw[k] << 24);
					break;
				case 2: /* unaligned mod 2 */
					PUTCHAR_BE(block[0], (len + 0) & 127, GETCHAR_BE(RawPsw, 0));
					PUTCHAR_BE(block[0], (len + 1) & 127, GETCHAR_BE(RawPsw, 1));
					block[0][((len >> 2) + 0 + 1) & 31] = (RawPsw[0] << 16) + (RawPsw[1] >> 16);
					block[0][((len >> 2) + 1 + 1) & 31] = (RawPsw[1] << 16) + (RawPsw[2] >> 16);
					for (k = 2; k < (blocklen >> 2) - 1; k++)
						block[0][((len >> 2) + k + 1) & 31] = (RawPsw[k] << 16) + (RawPsw[k + 1] >> 16);
					block[0][((len >> 2) + k + 1) & 31] = (RawPsw[k] << 16);
					break;
				case 3: /* unaligned mod 3 */
					PUTCHAR_BE(block[0], (len + 0) & 127, GETCHAR_BE(RawPsw, 0));
					block[0][((len >> 2) + 0 + 1) & 31] = (RawPsw[0] << 8) + (RawPsw[1] >> 24);
					block[0][((len >> 2) + 1 + 1) & 31] = (RawPsw[1] << 8) + (RawPsw[2] >> 24);
					for (k = 2; k < (blocklen >> 2) - 1; k++)
						block[0][((len >> 2) + k + 1) & 31] = (RawPsw[k] << 8) + (RawPsw[k + 1] >> 24);
					block[0][((len >> 2) + k + 1) & 31] = (RawPsw[k] << 8);
					break;
				}
				len += blocklen;

				/* Serial */
				PUTCHAR_BE(block[0], (len - 3) & 127, round & 0xff);
				PUTCHAR_BE(block[0], (len - 2) & 127, (round >> 8) & 0xff);
				PUTCHAR_BE(block[0], (len - 1) & 127, round >> 16);

				round++;
			} while ((len & 64) == (b << 6));
			sha1_block(block[b], output);
			b = 1 - b;
		}
	}
	round_p[gid] = round;

#pragma unroll
	for (i = 0; i < 5; i++)
		OutputBuf[gid * 5 + i] = output[i];
}

__kernel void RarFinal(
	const __global uint *pw_len,
	__global uint *OutputBuf,
	__global uint *aes_key)
{
	uint gid = get_global_id(0);
	uint *block[16], output[5];
	uint i;

#pragma unroll
	for (i = 0; i < 5; i++)
		output[i] = OutputBuf[gid * 5 + i];

	sha1_final((uint*)block, (uint*)output, (pw_len[gid] + 8 + 3) * ROUNDS);

	// Still no endian-swap
#pragma unroll
	for (i = 0; i < 4; i++)
		aes_key[gid * 4 + i] = output[i];
}

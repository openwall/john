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

#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define ROUNDS			0x40000

/* SHA1 constants and IVs */
#define H1	0x67452301
#define H2	0xEFCDAB89
#define H3	0x98BADCFE
#define H4	0x10325476
#define H5	0xC3D2E1F0

/*
 * Raw'n'lean sha1, state kept in output buffer.
 * This version does several blocks at a time and
 * does not thrash the input buffer.
 */
inline void sha1_mblock(uint *Win, uint *out, uint blocks)
{
	uint W[16], output[5];
	uint A, B, C, D, E, temp;

	for (temp = 0; temp < 5; temp++)
		output[temp] = out[temp];

	while (blocks--) {
		A = output[0];
		B = output[1];
		C = output[2];
		D = output[3];
		E = output[4];

		for (temp = 0; temp < 16; temp++)
			W[temp] = Win[temp];
#undef R
#define R(t)	  \
		( \
			temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
			W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
			( W[t & 0x0F] = rotate(temp, 1U) ) \
			)

#undef P
#define P(a,b,c,d,e,x)	  \
		{ \
			e += rotate(a, 5U) + F(b,c,d) + K + x; \
			b = rotate(b, 30U); \
		}

#undef F
#ifdef USE_BITSELECT
#define F(x, y, z) bitselect(z, y, x)
#else
#if HAVE_ANDNOT
#define F(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define F(x, y, z) (z ^ (x & (y ^ z)))
#endif
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
#define F(x,y,z)	bitselect(x, y, (z) ^ (x))
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

		Win += 16;
	}

	for (temp = 0; temp < 5; temp++)
		out[temp] = output[temp];
}

/* This version has less overhead but destroys input */
inline void sha1_block(MAYBE_VECTOR_UINT *W, MAYBE_VECTOR_UINT *output) {
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;

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
#define F(x, y, z) bitselect(z, y, x)
#else
#if HAVE_ANDNOT
#define F(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define F(x, y, z) (z ^ (x & (y ^ z)))
#endif
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
#define F(x,y,z)	bitselect(x, y, (z) ^ (x))
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

	while (len < 15)
		W[len++] = 0;
	W[15] = tot_len << 3;
	sha1_block(W, output);
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
		uint tempin[16], tempout[5];

		for (i = 0; i < 5; i++)
			tempout[i] = output[i];
		for (i = 0; i < (UNICODE_LENGTH + 8) / 4; i++)
			tempin[i] = block[i];

		PUTCHAR_BE(tempin, pwlen + 8, round & 255);
		PUTCHAR_BE(tempin, pwlen + 9, (round >> 8) & 255);

#ifdef __OS_X__
		/* This is the weirdest workaround. Using sha1_final()
		   works perfectly fine in the RarFinal() subkernel below. */
		PUTCHAR_BE(tempin, pwlen + 11, 0x80);
		for (i = pwlen + 12; i < 56; i++)
			PUTCHAR_BE(tempin, i, 0);
		tempin[14] = 0;
		tempin[15] = (blocklen * (round + 1)) << 3;
		sha1_block(tempin, tempout);
#else
		sha1_final(tempin, tempout, blocklen * (round + 1));
#endif
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
	sha1_final(block, output, (pw_len[gid] + 8 + 3) * ROUNDS);

	/* No endian-swap and we only use first 128 bits */
	for (i = 0; i < 4; i++)
		aes_key[gid * 4 + i] = output[i];
}

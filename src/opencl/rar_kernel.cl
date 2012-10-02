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

/* These must match the format's defines */
#define PLAINTEXT_LENGTH	16
#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define ROUNDS			0x40000
#define HASH_LOOPS		32

/* Macros for reading/writing chars from int32's */
#ifdef SCALAR
#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define GETCHAR_G(buf, index) (((const __global uchar*)(buf))[(index)])
#else
#define GETCHAR(buf, index) (((buf)[(index)>>2] >> (((index) & 3) << 3)) & 0xffU)
#define GETCHAR_G	GETCHAR
#endif

#define GETCHAR_BE(buf, index) (((buf)[(index)>>2] >> ((3 - ((index) & 3)) << 3)) & 0xffU)
/* The below is faster for AMD at low GWS but doesn't take off at higher. */
//#define GETCHAR_BE(buf, index) (((uchar*)(buf))[(index & ~3U) + (3 - (index & 3))])

#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << ((3 - ((index) & 3)) << 3))) + ((val) << ((3 - ((index) & 3)) << 3))
#define LASTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & (0xffffff00U << ((3 - ((index) & 3)) << 3))) + ((val) << ((3 - ((index) & 3)) << 3))

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
/* This version use global memory and preserves input */
inline void sha1G_block(__global uint *Win, __global uint *output) {
	uint W[16], A, B, C, D, E, temp;

#pragma unroll
	for (temp = 0; temp < 16; temp++)
		W[temp] = Win[temp];

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

/* This version use private memory and destroys input */
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

inline void sha1G_init(__global uint *output) {
	output[0] = H1;
	output[1] = H2;
	output[2] = H3;
	output[3] = H4;
	output[4] = H5;
}

inline void sha1_final(uint *Win, uint *output, const uint tot_len)
{
	uint len = ((tot_len & 63) >> 2) + 1;
	uint W[16], temp;

#pragma unroll
	for (temp = 0; temp < 16; temp++)
		W[temp] = Win[temp];

	LASTCHAR_BE(W, tot_len & 63, 0x80);

#if UNICODE_LENGTH > 52
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

#if 0
#ifdef SCALAR
#define AMD_V
inline void memcpy32(uint *d, const uint *s, uint len)
{
	while (len--)
		*d++ = *s++;
}
#else
#define AMD_V	(uint4*)&
inline void memcpy32(uint4 *d, const uint4 *s, uint len)
{
	while (len >= 4) {
		*d++ = *s++;
		len -= 4;
	}
	while (len--)
		*(uint*)d++ = *(uint*)s++;
}
#endif

void dump_stuff_be(uchar *x, unsigned int size)
{
        unsigned int i;
        for(i=0;i<size;i++)
        {
	        printf("%.2x", x[(i>>2)*4+3-(i&3)]);
                if( (i%4)==3 )
                        printf(" ");
        }
        printf("\n");
}
void dump_stuff_be_msg(__constant char *msg, uchar *x, unsigned int size) {
	printf("%s : ", (char *)msg);
	dump_stuff_be(x, size);
}

//#define printf	if (gid == 0) printf
#endif

__kernel void RarInit(
	const __global uint *unicode_pw,
	const __global uint *pw_len,
	__constant uint *salt,
	__global uint *RawBuf,
	__global uint *OutputBuf,
	__global uint *round)
{
	uint gid = get_global_id(0);
	__global uint *block = &RawBuf[gid * (UNICODE_LENGTH + 11) * 16];
	__global uint *output = &OutputBuf[gid * 5];
	uint pwlen = pw_len[gid];
	uint blocklen = pwlen + 11;
	uint i, j;

	/* Copy to 64x buffer (always ends at SHA-1 block boundary) */
	for (i = 0; i < 64; i++) {
		for (j = 0; j < pwlen; j++)
			PUTCHAR_BE(block, i * blocklen + j, GETCHAR_G(unicode_pw, gid * UNICODE_LENGTH + j));
#pragma unroll
		for (j = 0; j < 8; j++)
			PUTCHAR_BE(block, i * blocklen + pwlen + j, ((__constant uchar*)salt)[j]);
	}
	round[gid] = 0;
	sha1G_init(output);
}

__kernel void RarGetIV(
	const __global uint *pw_len,
	__global uint *RawBuf,
	__global uint *OutputBuf,
	__global uint *round_p,
	__global uint *aes_iv)
{
	uint gid = get_global_id(0);
	__global uint *block = &RawBuf[gid * (UNICODE_LENGTH + 11) * 16];
	__global uint *output = &OutputBuf[gid * 5];
	uint tempin[16], tempout[5];
	uint pwlen = pw_len[gid];
	uint round = round_p[gid];
	uint i;

#pragma unroll
	for (i = 0; i < 5; i++)
		tempout[i] = output[i];
#pragma unroll
	for (i = 0; i < 10; i++)
		tempin[i] = block[i];

	PUTCHAR_BE(tempin, pwlen + 8, round & 255);
	PUTCHAR_BE(tempin, pwlen + 9, (round >> 8) & 255);
	PUTCHAR_BE(tempin, pwlen + 10, round >> 16);

	sha1_final(tempin, tempout, (pwlen + 8 + 3) * (round + 1));
	PUTCHAR(aes_iv, gid * 16 + (round >> 14), GETCHAR(tempout, 16));
}

__kernel void RarHashLoop(
	const __global uint *pw_len,
	__global uint *round_p,
	__global uint *RawBuf,
	__global uint *OutputBuf)
{
	uint gid = get_global_id(0);
	__global uint *block = &RawBuf[gid * (UNICODE_LENGTH + 11) * 16];
	__global uint *output = &OutputBuf[gid * 5];
	uint pwlen = pw_len[gid];
	uint blocklen = pwlen + 11;
	uint round = round_p[gid];
	uint i, j;

	for (j = 0; j < HASH_LOOPS; j++) {
//#pragma unroll /* Not good for nvidia */
		for (i = 0; i < 64; i++, round++) {
			PUTCHAR_BE(block, i * blocklen + pwlen + 8, round & 0xff);
			PUTCHAR_BE(block, i * blocklen + pwlen + 9, (round >> 8) & 0xff);
			PUTCHAR_BE(block, i * blocklen + pwlen + 10, round >> 16);
		}
		for (i = 0; i < blocklen; i++)
			sha1G_block(&block[i * 16], output);
	}
	round_p[gid] = round;
}

__kernel void RarFinal(
	const __global uint *pw_len,
	__global uint *OutputBuf,
	__global uint *aes_key)
{
	uint gid = get_global_id(0);
	uint *tempin[16], tempout[5];
	__global uint *output = &OutputBuf[gid * 5];
	uint i;

#pragma unroll
	for (i = 0; i < 5; i++)
		tempout[i] = output[i];

	sha1_final((uint*)tempin, (uint*)tempout, (pw_len[gid] + 8 + 3) * ROUNDS);

	// Still no endian-swap
	aes_key[gid * 4] = tempout[0];
	aes_key[gid * 4 + 1] = tempout[1];
	aes_key[gid * 4 + 2] = tempout[2];
	aes_key[gid * 4 + 3] = tempout[3];
}

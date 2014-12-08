/*
 * OpenCL SHA1
 *
 * Copyright (c) 2014, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * NOTICE: After changes in headers, you probably need to drop cached
 * kernels to ensure the changes take effect.
 *
 */

#ifndef _OPENCL_SHA1_H
#define _OPENCL_SHA1_H

#include "opencl_misc.h"

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

		Win += 16;
	}

	for (temp = 0; temp < 5; temp++)
		out[temp] = output[temp];
}

/* This version has less overhead but destroys input */
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

#endif

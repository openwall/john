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

#ifndef _OPENCL_SHA1M_H
#define _OPENCL_SHA1M_H

#include "opencl_misc.h"

/*
 * OpenSSL only declares SHA_DIGEST_LENGTH but some code
 * (on host side as well) use SHA1_DIGEST_LENGTH so we
 * declare that as well
 */
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif
#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH 20
#endif

#define SHA1_LUT3 HAVE_LUT3

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

#if SHA1_LUT3
#define F1(x, y, z) lut3(x, y, z, 0xca)
#elif USE_BITSELECT
#define F1(x, y, z) bitselect(z, y, x)
#elif HAVE_ANDNOT
#define F1(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#endif

#if SHA1_LUT3
#define F2(x, y, z) lut3(x, y, z, 0x96)
#else
#define F2(x, y, z) (x ^ y ^ z)
#endif

#if SHA1_LUT3
#define F3(x, y, z) lut3(x, y, z, 0xe8)
#elif USE_BITSELECT
#define F3(x, y, z) bitselect(x, y, (z) ^ (x))
#elif 0 /* Wei Dai's trick, but we let the compiler cache/reuse or not */
#define F3(x, y, z) (y ^ ((x ^ y) & (y ^ z)))
#elif 0
#define F3(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#else
#define F3(x, y, z) ((x & y) | (z & (x | y)))
#endif

#if SHA1_LUT3
#define F4(x, y, z) lut3(x, y, z, 0x96)
#else
#define F4(x, y, z) (x ^ y ^ z)
#endif

#define R(t)	  \
	( \
		temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( r[t & 0x0F] = rotate(temp, 1U) ) \
		)

#define Ro1(t)	  \
	( \
		temp = r[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( r[t & 0x0F] = rotate(temp, 1U) ) \
		)
#define Ro2(t)	  \
	( \
		temp = r[(t -  3) & 0x0F] ^ r[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( r[t & 0x0F] = rotate(temp, 1U) ) \
		)

#define Ro3(t)	  \
	( \
		temp = r[(t -  3) & 0x0F] ^ r[(t - 8) & 0x0F] ^ \
		r[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( r[t & 0x0F] = rotate(temp, 1U) ) \
		)

#define Rr(t)	  \
	( \
		temp = r[(t -  3) & 0x0F] ^ r[(t - 8) & 0x0F] ^ \
		r[(t - 14) & 0x0F] ^ r[ t      & 0x0F], \
		( r[t & 0x0F] = rotate(temp, 1U) ) \
		)

#define R1(t)	  \
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
	P1(B, C, D, E, A, Ro1(19)); \
	P2(A, B, C, D, E, Ro1(20)); \
	P2(E, A, B, C, D, Ro1(21)); \
	P2(D, E, A, B, C, Ro1(22)); \
	P2(C, D, E, A, B, Ro1(23)); \
	P2(B, C, D, E, A, Ro2(24)); \
	P2(A, B, C, D, E, Ro2(25)); \
	P2(E, A, B, C, D, Ro2(26)); \
	P2(D, E, A, B, C, Ro2(27)); \
	P2(C, D, E, A, B, Ro2(28)); \
	P2(B, C, D, E, A, Ro2(29)); \
	P2(A, B, C, D, E, Ro3(30)); \
	P2(E, A, B, C, D, Ro3(31)); \
	P2(D, E, A, B, C, Rr(32)); \
	P2(C, D, E, A, B, Rr(33)); \
	P2(B, C, D, E, A, Rr(34)); \
	P2(A, B, C, D, E, Rr(35)); \
	P2(E, A, B, C, D, Rr(36)); \
	P2(D, E, A, B, C, Rr(37)); \
	P2(C, D, E, A, B, Rr(38)); \
	P2(B, C, D, E, A, Rr(39)); \
	P3(A, B, C, D, E, Rr(40)); \
	P3(E, A, B, C, D, Rr(41)); \
	P3(D, E, A, B, C, Rr(42)); \
	P3(C, D, E, A, B, Rr(43)); \
	P3(B, C, D, E, A, Rr(44)); \
	P3(A, B, C, D, E, Rr(45)); \
	P3(E, A, B, C, D, Rr(46)); \
	P3(D, E, A, B, C, Rr(47)); \
	P3(C, D, E, A, B, Rr(48)); \
	P3(B, C, D, E, A, Rr(49)); \
	P3(A, B, C, D, E, Rr(50)); \
	P3(E, A, B, C, D, Rr(51)); \
	P3(D, E, A, B, C, Rr(52)); \
	P3(C, D, E, A, B, Rr(53)); \
	P3(B, C, D, E, A, Rr(54)); \
	P3(A, B, C, D, E, Rr(55)); \
	P3(E, A, B, C, D, Rr(56)); \
	P3(D, E, A, B, C, Rr(57)); \
	P3(C, D, E, A, B, Rr(58)); \
	P3(B, C, D, E, A, Rr(59)); \
	P4(A, B, C, D, E, Rr(60)); \
	P4(E, A, B, C, D, Rr(61)); \
	P4(D, E, A, B, C, Rr(62)); \
	P4(C, D, E, A, B, Rr(63)); \
	P4(B, C, D, E, A, Rr(64)); \
	P4(A, B, C, D, E, Rr(65)); \
	P4(E, A, B, C, D, Rr(66)); \
	P4(D, E, A, B, C, Rr(67)); \
	P4(C, D, E, A, B, Rr(68)); \
	P4(B, C, D, E, A, Rr(69)); \
	P4(A, B, C, D, E, Rr(70)); \
	P4(E, A, B, C, D, Rr(71)); \
	P4(D, E, A, B, C, Rr(72)); \
	P4(C, D, E, A, B, Rr(73)); \
	P4(B, C, D, E, A, Rr(74)); \
	P4(A, B, C, D, E, Rr(75)); \
	P4(E, A, B, C, D, Rr(76)); \
	P4(D, E, A, B, C, Rr(77)); \
	P4(C, D, E, A, B, Rr(78)); \
	P4(B, C, D, E, A, Rr(79));

#define SHA1_192Z_BEG(A, B, C, D, E, W)	  \
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

#define SHA1_192Z_END(A, B, C, D, E, W)	  \
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
	P2(E, A, B, C, D, R1(31)); \
	P2(D, E, A, B, C, R1(32)); \
	P2(C, D, E, A, B, R1(33)); \
	P2(B, C, D, E, A, R1(34)); \
	P2(A, B, C, D, E, R1(35)); \
	P2(E, A, B, C, D, R1(36)); \
	P2(D, E, A, B, C, R1(37)); \
	P2(C, D, E, A, B, R1(38)); \
	P2(B, C, D, E, A, R1(39)); \
	P3(A, B, C, D, E, R1(40)); \
	P3(E, A, B, C, D, R1(41)); \
	P3(D, E, A, B, C, R1(42)); \
	P3(C, D, E, A, B, R1(43)); \
	P3(B, C, D, E, A, R1(44)); \
	P3(A, B, C, D, E, R1(45)); \
	P3(E, A, B, C, D, R1(46)); \
	P3(D, E, A, B, C, R1(47)); \
	P3(C, D, E, A, B, R1(48)); \
	P3(B, C, D, E, A, R1(49)); \
	P3(A, B, C, D, E, R1(50)); \
	P3(E, A, B, C, D, R1(51)); \
	P3(D, E, A, B, C, R1(52)); \
	P3(C, D, E, A, B, R1(53)); \
	P3(B, C, D, E, A, R1(54)); \
	P3(A, B, C, D, E, R1(55)); \
	P3(E, A, B, C, D, R1(56)); \
	P3(D, E, A, B, C, R1(57)); \
	P3(C, D, E, A, B, R1(58)); \
	P3(B, C, D, E, A, R1(59)); \
	P4(A, B, C, D, E, R1(60)); \
	P4(E, A, B, C, D, R1(61)); \
	P4(D, E, A, B, C, R1(62)); \
	P4(C, D, E, A, B, R1(63)); \
	P4(B, C, D, E, A, R1(64)); \
	P4(A, B, C, D, E, R1(65)); \
	P4(E, A, B, C, D, R1(66)); \
	P4(D, E, A, B, C, R1(67)); \
	P4(C, D, E, A, B, R1(68)); \
	P4(B, C, D, E, A, R1(69)); \
	P4(A, B, C, D, E, R1(70)); \
	P4(E, A, B, C, D, R1(71)); \
	P4(D, E, A, B, C, R1(72)); \
	P4(C, D, E, A, B, R1(73)); \
	P4(B, C, D, E, A, R1(74)); \
	P4(A, B, C, D, E, R1(75)); \
	P4(E, A, B, C, D, R1(76)); \
	P4(D, E, A, B, C, R2(77)); \
	P4(C, D, E, A, B, R2(78)); \
	P4(B, C, D, E, A, R2(79));

#define SHA1_160Z_BEG(A, B, C, D, E, W)	  \
	P1(A, B, C, D, E, W[0]); \
	P1(E, A, B, C, D, W[1]); \
	P1(D, E, A, B, C, W[2]); \
	P1(C, D, E, A, B, W[3]); \
	P1(B, C, D, E, A, W[4]); \
	P1(A, B, C, D, E, W[5]); \
	PZ(E, A, B, C, D); \
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

#define Q20_160 (W[4] = rotate((W[1] ^ W[4]), 1U))
#define Q22_160 (W[6] = rotate(W[3], 1U))

#define SHA1_160Z_END(A, B, C, D, E, W)	  \
	P1(E, A, B, C, D, Q16); \
	P1(D, E, A, B, C, Q17); \
	P1(C, D, E, A, B, Q18); \
	P1(B, C, D, E, A, Q19); \
	P2(A, B, C, D, E, Q20_160); \
	P2(E, A, B, C, D, Q21); \
	P2(D, E, A, B, C, Q22_160); \
	P2(C, D, E, A, B, Q23); \
	P2(B, C, D, E, A, Q24); \
	P2(A, B, C, D, E, Q25); \
	P2(E, A, B, C, D, Q26); \
	P2(D, E, A, B, C, Q27); \
	P2(C, D, E, A, B, Q28); \
	P2(B, C, D, E, A, Q29); \
	P2(A, B, C, D, E, Q30); \
	P2(E, A, B, C, D, R1(31)); \
	P2(D, E, A, B, C, R1(32)); \
	P2(C, D, E, A, B, R1(33)); \
	P2(B, C, D, E, A, R1(34)); \
	P2(A, B, C, D, E, R1(35)); \
	P2(E, A, B, C, D, R1(36)); \
	P2(D, E, A, B, C, R1(37)); \
	P2(C, D, E, A, B, R1(38)); \
	P2(B, C, D, E, A, R1(39)); \
	P3(A, B, C, D, E, R1(40)); \
	P3(E, A, B, C, D, R1(41)); \
	P3(D, E, A, B, C, R1(42)); \
	P3(C, D, E, A, B, R1(43)); \
	P3(B, C, D, E, A, R1(44)); \
	P3(A, B, C, D, E, R1(45)); \
	P3(E, A, B, C, D, R1(46)); \
	P3(D, E, A, B, C, R1(47)); \
	P3(C, D, E, A, B, R1(48)); \
	P3(B, C, D, E, A, R1(49)); \
	P3(A, B, C, D, E, R1(50)); \
	P3(E, A, B, C, D, R1(51)); \
	P3(D, E, A, B, C, R1(52)); \
	P3(C, D, E, A, B, R1(53)); \
	P3(B, C, D, E, A, R1(54)); \
	P3(A, B, C, D, E, R1(55)); \
	P3(E, A, B, C, D, R1(56)); \
	P3(D, E, A, B, C, R1(57)); \
	P3(C, D, E, A, B, R1(58)); \
	P3(B, C, D, E, A, R1(59)); \
	P4(A, B, C, D, E, R1(60)); \
	P4(E, A, B, C, D, R1(61)); \
	P4(D, E, A, B, C, R1(62)); \
	P4(C, D, E, A, B, R1(63)); \
	P4(B, C, D, E, A, R1(64)); \
	P4(A, B, C, D, E, R1(65)); \
	P4(E, A, B, C, D, R1(66)); \
	P4(D, E, A, B, C, R1(67)); \
	P4(C, D, E, A, B, R1(68)); \
	P4(B, C, D, E, A, R1(69)); \
	P4(A, B, C, D, E, R1(70)); \
	P4(E, A, B, C, D, R1(71)); \
	P4(D, E, A, B, C, R1(72)); \
	P4(C, D, E, A, B, R1(73)); \
	P4(B, C, D, E, A, R1(74)); \
	P4(A, B, C, D, E, R1(75)); \
	P4(E, A, B, C, D, R1(76)); \
	P4(D, E, A, B, C, R2(77)); \
	P4(C, D, E, A, B, R2(78)); \
	P4(B, C, D, E, A, R2(79));

#define SHA1_160Z(A, B, C, D, E, W) SHA1_160Z_BEG(A, B, C, D, E, W) SHA1_160Z_END(A, B, C, D, E, W)

#define SHA1_192Z(A, B, C, D, E, W) SHA1_192Z_BEG(A, B, C, D, E, W) SHA1_192Z_END(A, B, C, D, E, W)

#define sha1_init(ctx) {	  \
		ctx[0] = INIT_A; \
		ctx[1] = INIT_B; \
		ctx[2] = INIT_C; \
		ctx[3] = INIT_D; \
		ctx[4] = INIT_E; \
	}

/*
 * The extra a, b, c, d, e variables are a workaround for a really silly
 * AMD bug (seen in e.g. Catalyst 14.9). We should really do without them
 * but somehow we get thrashed output without them.
 * On the other hand, they also seem to work as an optimization for nvidia!
 */
#define sha1_block(itype, W, ctx) {	  \
		itype A, B, C, D, E, temp, r[16]; \
		itype a, b, c, d, e; \
		A = ctx[0]; \
		B = ctx[1]; \
		C = ctx[2]; \
		D = ctx[3]; \
		E = ctx[4]; \
		a=A, b=B, c=C, d=D, e=E; \
		SHA1(A, B, C, D, E, W); \
		ctx[0] = a + A; \
		ctx[1] = b + B; \
		ctx[2] = c + C; \
		ctx[3] = d + D; \
		ctx[4] = e + E; \
	}

#define sha1_single(itype, W, out) {	\
		itype A, B, C, D, E, temp, r[16]; \
		A = INIT_A; \
		B = INIT_B; \
		C = INIT_C; \
		D = INIT_D; \
		E = INIT_E; \
		SHA1(A, B, C, D, E, W); \
		out[0] = A + INIT_A; \
		out[1] = B + INIT_B; \
		out[2] = C + INIT_C; \
		out[3] = D + INIT_D; \
		out[4] = E + INIT_E; \
	}

#define sha1_block_160Z(itype, W, ctx) {	  \
		itype A, B, C, D, E, temp; \
		itype a, b, c, d, e; \
		A = ctx[0]; \
		B = ctx[1]; \
		C = ctx[2]; \
		D = ctx[3]; \
		E = ctx[4]; \
		a=A, b=B, c=C, d=D, e=E; \
		SHA1_160Z(A, B, C, D, E, W); \
		ctx[0] = a + A; \
		ctx[1] = b + B; \
		ctx[2] = c + C; \
		ctx[3] = d + D; \
		ctx[4] = e + E; \
	}

#define sha1_single_160Z(itype, W, out) {	  \
		itype A, B, C, D, E, temp; \
		A = INIT_A; \
		B = INIT_B; \
		C = INIT_C; \
		D = INIT_D; \
		E = INIT_E; \
		SHA1_160Z(A, B, C, D, E, W); \
		out[0] = A + INIT_A; \
		out[1] = B + INIT_B; \
		out[2] = C + INIT_C; \
		out[3] = D + INIT_D; \
		out[4] = E + INIT_E; \
	}

#define sha1_block_192Z(itype, W, ctx) {	  \
		itype A, B, C, D, E, temp; \
		itype a, b, c, d, e; \
		A = ctx[0]; \
		B = ctx[1]; \
		C = ctx[2]; \
		D = ctx[3]; \
		E = ctx[4]; \
		a=A, b=B, c=C, d=D, e=E; \
		SHA1_192Z(A, B, C, D, E, W); \
		ctx[0] = a + A; \
		ctx[1] = b + B; \
		ctx[2] = c + C; \
		ctx[3] = d + D; \
		ctx[4] = e + E; \
	}

#define sha1_single_192Z(itype, W, out) {	  \
		itype A, B, C, D, E, temp; \
		A = INIT_A; \
		B = INIT_B; \
		C = INIT_C; \
		D = INIT_D; \
		E = INIT_E; \
		SHA1_192Z(A, B, C, D, E, W); \
		out[0] = A + INIT_A; \
		out[1] = B + INIT_B; \
		out[2] = C + INIT_C; \
		out[3] = D + INIT_D; \
		out[4] = E + INIT_E; \
	}

#endif /* _OPENCL_SHA1M_H */

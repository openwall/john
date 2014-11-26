/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>,
 * Copyright (c) 2012 Milen Rangelov and Copyright (c) 2012-2013 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_md5.h"

typedef struct {
	uint keymic[16 / 4];
} mic_t;

typedef struct {
	uint  length;
	uint  eapol[(256 + 64) / 4];
	uint  eapol_size;
	uint  data[(64 + 12) / 4]; // pre-processed mac and nonce
	uchar salt[36]; // essid
} wpapsk_salt;

/*
typedef struct {
	MAYBE_VECTOR_UINT W[5];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	MAYBE_VECTOR_UINT out[5];
	MAYBE_VECTOR_UINT partial[5];
} wpapsk_state;
*/
// Using a coalesced buffer instead, eg. state[(IPAD + i) * gws + gid]
//      W    0
#define IPAD 5
#define OPAD 10
#define OUT 15
#define PARTIAL 20

#ifdef OLD_NVIDIA /* Lukas' original SHA-1 */

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

#ifdef USE_BITSELECT
#define F1(x, y, z)	bitselect(z, y, x)
#else
#define F1(x, y, z)	(z ^ (x & (y ^ z)))
#endif

#define F2(x, y, z)		(x ^ y ^ z)

#ifdef USE_BITSELECT
#define F3(x, y, z)	(bitselect(x, y, z) ^ bitselect(x, 0U, y))
#else
#define F3(x, y, z)	((x & y) | (z & (x | y)))
#endif

#define F4(x, y, z)		(x ^ y ^ z)

#if 1 // Significantly faster, at least on nvidia
#define S(x, n)	rotate((x), (uint)(n))
#else
#define S(x, n)	((x << n) | ((x) >> (32 - n)))
#endif

#define R(t)	  \
	( \
		temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( W[t & 0x0F] = S(temp, 1) ) \
		)

#define R2(t)	  \
	( \
		S((W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		   W[(t - 14) & 0x0F] ^ W[ t      & 0x0F]), 1) \
		)

#define P1(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F1(b, c, d) + K1 + x; b = S(b, 30); \
	}

#define P2(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F2(b, c, d) + K2 + x; b = S(b, 30); \
	}

#define P3(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F3(b, c, d) + K3 + x; b = S(b, 30); \
	}

#define P4(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F4(b, c, d) + K4 + x; b = S(b, 30); \
	}

#define PZ(a, b, c, d, e)	  \
	{ \
		e += S(a, 5) + F1(b, c, d) + K1 ; b = S(b, 30); \
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
	P1(B, C, D, E, A, R(19)); \
	P2(A, B, C, D, E, R(20)); \
	P2(E, A, B, C, D, R(21)); \
	P2(D, E, A, B, C, R(22)); \
	P2(C, D, E, A, B, R(23)); \
	P2(B, C, D, E, A, R(24)); \
	P2(A, B, C, D, E, R(25)); \
	P2(E, A, B, C, D, R(26)); \
	P2(D, E, A, B, C, R(27)); \
	P2(C, D, E, A, B, R(28)); \
	P2(B, C, D, E, A, R(29)); \
	P2(A, B, C, D, E, R(30)); \
	P2(E, A, B, C, D, R(31)); \
	P2(D, E, A, B, C, R(32)); \
	P2(C, D, E, A, B, R(33)); \
	P2(B, C, D, E, A, R(34)); \
	P2(A, B, C, D, E, R(35)); \
	P2(E, A, B, C, D, R(36)); \
	P2(D, E, A, B, C, R(37)); \
	P2(C, D, E, A, B, R(38)); \
	P2(B, C, D, E, A, R(39)); \
	P3(A, B, C, D, E, R(40)); \
	P3(E, A, B, C, D, R(41)); \
	P3(D, E, A, B, C, R(42)); \
	P3(C, D, E, A, B, R(43)); \
	P3(B, C, D, E, A, R(44)); \
	P3(A, B, C, D, E, R(45)); \
	P3(E, A, B, C, D, R(46)); \
	P3(D, E, A, B, C, R(47)); \
	P3(C, D, E, A, B, R(48)); \
	P3(B, C, D, E, A, R(49)); \
	P3(A, B, C, D, E, R(50)); \
	P3(E, A, B, C, D, R(51)); \
	P3(D, E, A, B, C, R(52)); \
	P3(C, D, E, A, B, R(53)); \
	P3(B, C, D, E, A, R(54)); \
	P3(A, B, C, D, E, R(55)); \
	P3(E, A, B, C, D, R(56)); \
	P3(D, E, A, B, C, R(57)); \
	P3(C, D, E, A, B, R(58)); \
	P3(B, C, D, E, A, R(59)); \
	P4(A, B, C, D, E, R(60)); \
	P4(E, A, B, C, D, R(61)); \
	P4(D, E, A, B, C, R(62)); \
	P4(C, D, E, A, B, R(63)); \
	P4(B, C, D, E, A, R(64)); \
	P4(A, B, C, D, E, R(65)); \
	P4(E, A, B, C, D, R(66)); \
	P4(D, E, A, B, C, R(67)); \
	P4(C, D, E, A, B, R(68)); \
	P4(B, C, D, E, A, R(69)); \
	P4(A, B, C, D, E, R(70)); \
	P4(E, A, B, C, D, R(71)); \
	P4(D, E, A, B, C, R(72)); \
	P4(C, D, E, A, B, R(73)); \
	P4(B, C, D, E, A, R(74)); \
	P4(A, B, C, D, E, R(75)); \
	P4(E, A, B, C, D, R(76)); \
	P4(D, E, A, B, C, R(77)); \
	P4(C, D, E, A, B, R(78)); \
	P4(B, C, D, E, A, R(79));

#define SHA1_SHORT_BEG(A, B, C, D, E, W)	  \
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

#define Q16 (W[0] = S((W[2] ^ W[0]), 1))
#define Q17 (W[1] = S((W[3] ^ W[1]), 1))
#define Q18 (W[2] = S((W[15] ^ W[4] ^ W[2]), 1))
#define Q19 (W[3] = S((W[0]  ^ W[5] ^ W[3]), 1))
#define Q20 (W[4] = S((W[1]  ^ W[4]), 1))
#define Q21 (W[5] = S((W[2] ^ W[5]), 1))
#define Q22 (W[6] = S(W[3], 1))
#define Q23 (W[7] = S((W[4] ^ W[15]), 1))
#define Q24 (W[8] = S((W[5] ^ W[0]), 1))
#define Q25 (W[9] = S((W[6] ^ W[1]), 1))
#define Q26 (W[10] = S((W[7] ^ W[2]), 1))
#define Q27 (W[11] = S((W[8] ^ W[3]), 1))
#define Q28 (W[12] = S((W[9] ^ W[4]), 1))
#define Q29 (W[13] = S((W[10] ^ W[5] ^ W[15]), 1))
#define Q30 (W[14] = S((W[11] ^ W[6] ^ W[0]), 1))

#define SHA1_SHORT_END(A, B, C, D, E, W)	  \
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
	P2(E, A, B, C, D, R(31)); \
	P2(D, E, A, B, C, R(32)); \
	P2(C, D, E, A, B, R(33)); \
	P2(B, C, D, E, A, R(34)); \
	P2(A, B, C, D, E, R(35)); \
	P2(E, A, B, C, D, R(36)); \
	P2(D, E, A, B, C, R(37)); \
	P2(C, D, E, A, B, R(38)); \
	P2(B, C, D, E, A, R(39)); \
	P3(A, B, C, D, E, R(40)); \
	P3(E, A, B, C, D, R(41)); \
	P3(D, E, A, B, C, R(42)); \
	P3(C, D, E, A, B, R(43)); \
	P3(B, C, D, E, A, R(44)); \
	P3(A, B, C, D, E, R(45)); \
	P3(E, A, B, C, D, R(46)); \
	P3(D, E, A, B, C, R(47)); \
	P3(C, D, E, A, B, R(48)); \
	P3(B, C, D, E, A, R(49)); \
	P3(A, B, C, D, E, R(50)); \
	P3(E, A, B, C, D, R(51)); \
	P3(D, E, A, B, C, R(52)); \
	P3(C, D, E, A, B, R(53)); \
	P3(B, C, D, E, A, R(54)); \
	P3(A, B, C, D, E, R(55)); \
	P3(E, A, B, C, D, R(56)); \
	P3(D, E, A, B, C, R(57)); \
	P3(C, D, E, A, B, R(58)); \
	P3(B, C, D, E, A, R(59)); \
	P4(A, B, C, D, E, R(60)); \
	P4(E, A, B, C, D, R(61)); \
	P4(D, E, A, B, C, R(62)); \
	P4(C, D, E, A, B, R(63)); \
	P4(B, C, D, E, A, R(64)); \
	P4(A, B, C, D, E, R(65)); \
	P4(E, A, B, C, D, R(66)); \
	P4(D, E, A, B, C, R(67)); \
	P4(C, D, E, A, B, R(68)); \
	P4(B, C, D, E, A, R(69)); \
	P4(A, B, C, D, E, R(70)); \
	P4(E, A, B, C, D, R(71)); \
	P4(D, E, A, B, C, R(72)); \
	P4(C, D, E, A, B, R(73)); \
	P4(B, C, D, E, A, R(74)); \
	P4(A, B, C, D, E, R(75)); \
	P4(E, A, B, C, D, R(76)); \
	P4(D, E, A, B, C, R2(77)); \
	P4(C, D, E, A, B, R2(78)); \
	P4(B, C, D, E, A, R2(79));

#define SHA1_SHORT(A, B, C, D, E, W) SHA1_SHORT_BEG(A, B, C, D, E, W) SHA1_SHORT_END(A, B, C, D, E, W)

#define sha1_init(o) {	  \
		o[0] = INIT_A; \
		o[1] = INIT_B; \
		o[2] = INIT_C; \
		o[3] = INIT_D; \
		o[4] = INIT_E; \
	}

#define sha1_block(b, o) {	\
		A = o[0]; \
		B = o[1]; \
		C = o[2]; \
		D = o[3]; \
		E = o[4]; \
		SHA1(A, B, C, D, E, b); \
		o[0] += A; \
		o[1] += B; \
		o[2] += C; \
		o[3] += D; \
		o[4] += E; \
	}

#define sha1_block_short(b, o) {	\
		A = o[0]; \
		B = o[1]; \
		C = o[2]; \
		D = o[3]; \
		E = o[4]; \
		SHA1_SHORT(A, B, C, D, E, b); \
		o[0] += A; \
		o[1] += B; \
		o[2] += C; \
		o[3] += D; \
		o[4] += E; \
	}

#else // Milen's SHA-1, faster for AMD

#ifdef USE_BITSELECT
#define F_00_19(bb, cc, dd) (bitselect((dd), (cc), (bb)))
#define F_20_39(bb, cc, dd)  ((bb) ^ (cc) ^ (dd))
#define F_40_59(bb, cc, dd) (bitselect((cc), (bb), ((dd)^(cc))))
#define F_60_79(bb, cc, dd)  F_20_39((bb), (cc), (dd))
#else
#define F_00_19(bb, cc, dd)  ((((cc) ^ (dd)) & (bb)) ^ (dd))
#define F_20_39(bb, cc, dd)  ((cc) ^ (bb) ^ (dd))
#define F_40_59(bb, cc, dd)  (((bb) & (cc)) | (((bb)|(cc)) & (dd)))
#define F_60_79(bb, cc, dd)  F_20_39(bb, cc, dd)
#endif

#define ROTATE1(aa, bb, cc, dd, ee, x) (ee) = (ee) + rotate((aa), S2) + F_00_19((bb), (cc), (dd)) + (x); (ee) = (ee) + K; (bb) = rotate((bb), S3)
#define ROTATE1_NULL(aa, bb, cc, dd, ee)  (ee) = (ee) + rotate((aa), S2) + F_00_19((bb), (cc), (dd)) + K; (bb) = rotate((bb), S3)
#define ROTATE2_F(aa, bb, cc, dd, ee, x) (ee) = (ee) + rotate((aa), S2) + F_20_39((bb), (cc), (dd)) + (x) + K; (bb) = rotate((bb), S3)
#define ROTATE3_F(aa, bb, cc, dd, ee, x) (ee) = (ee) + rotate((aa), S2) + F_40_59((bb), (cc), (dd)) + (x) + K; (bb) = rotate((bb), S3)
#define ROTATE4_F(aa, bb, cc, dd, ee, x) (ee) = (ee) + rotate((aa), S2) + F_60_79((bb), (cc), (dd)) + (x) + K; (bb) = rotate((bb), S3)

#define S1 1U
#define S2 5U
#define S3 30U

#define H0 (uint)0x67452301
#define H1 (uint)0xEFCDAB89
#define H2 (uint)0x98BADCFE
#define H3 (uint)0x10325476
#define H4 (uint)0xC3D2E1F0

/* raw'n'lean sha1, context kept in output buffer.
   Note that we thrash the input buffer! */
/* The extra a-e variables are a workaround for an AMD bug in Cat 14.6b */
#define sha1_block(W, output) {	  \
		MAYBE_VECTOR_UINT a, b, c, d, e; \
		a = A = output[0]; \
		b = B = output[1]; \
		c = C = output[2]; \
		d = D = output[3]; \
		e = E = output[4]; \
		K = 0x5A827999; \
		ROTATE1(A, B, C, D, E, W[0]); \
		ROTATE1(E, A, B, C, D, W[1]); \
		ROTATE1(D, E, A, B, C, W[2]); \
		ROTATE1(C, D, E, A, B, W[3]); \
		ROTATE1(B, C, D, E, A, W[4]); \
		ROTATE1(A, B, C, D, E, W[5]); \
		ROTATE1(E, A, B, C, D, W[6]); \
		ROTATE1(D, E, A, B, C, W[7]); \
		ROTATE1(C, D, E, A, B, W[8]); \
		ROTATE1(B, C, D, E, A, W[9]); \
		ROTATE1(A, B, C, D, E, W[10]); \
		ROTATE1(E, A, B, C, D, W[11]); \
		ROTATE1(D, E, A, B, C, W[12]); \
		ROTATE1(C, D, E, A, B, W[13]); \
		ROTATE1(B, C, D, E, A, W[14]); \
		ROTATE1(A, B, C, D, E, W[15]); \
		temp = rotate((W[13] ^ W[8] ^ W[2] ^ W[0]), S1); ROTATE1(E, A, B, C, D, temp); \
		W[0] = rotate((W[14] ^ W[9] ^ W[3] ^ W[1]), S1); ROTATE1(D, E, A, B, C, W[0]); \
		W[1] = rotate((W[15] ^ W[10] ^ W[4] ^ W[2]), S1); ROTATE1(C, D, E, A, B, W[1]); \
		W[2] = rotate((temp ^ W[11] ^ W[5] ^ W[3]), S1);  ROTATE1(B, C, D, E, A, W[2]); \
		K = 0x6ED9EBA1; \
		W[3] = rotate((W[0] ^ W[12] ^ W[6] ^ W[4]), S1); ROTATE2_F(A, B, C, D, E, W[3]); \
		W[4] = rotate((W[1] ^ W[13] ^ W[7] ^ W[5]), S1); ROTATE2_F(E, A, B, C, D, W[4]); \
		W[5] = rotate((W[2] ^ W[14] ^ W[8] ^ W[6]), S1); ROTATE2_F(D, E, A, B, C, W[5]); \
		W[6] = rotate((W[3] ^ W[15] ^ W[9] ^ W[7]), S1); ROTATE2_F(C, D, E, A, B, W[6]); \
		W[7] = rotate((W[4] ^ temp ^ W[10] ^ W[8]), S1); ROTATE2_F(B, C, D, E, A, W[7]); \
		W[8] = rotate((W[5] ^ W[0] ^ W[11] ^ W[9]), S1); ROTATE2_F(A, B, C, D, E, W[8]); \
		W[9] = rotate((W[6] ^ W[1] ^ W[12] ^ W[10]), S1); ROTATE2_F(E, A, B, C, D, W[9]); \
		W[10] = rotate((W[7] ^ W[2] ^ W[13] ^ W[11]), S1); ROTATE2_F(D, E, A, B, C, W[10]); \
		W[11] = rotate((W[8] ^ W[3] ^ W[14] ^ W[12]), S1); ROTATE2_F(C, D, E, A, B, W[11]); \
		W[12] = rotate((W[9] ^ W[4] ^ W[15] ^ W[13]), S1); ROTATE2_F(B, C, D, E, A, W[12]); \
		W[13] = rotate((W[10] ^ W[5] ^ temp ^ W[14]), S1); ROTATE2_F(A, B, C, D, E, W[13]); \
		W[14] = rotate((W[11] ^ W[6] ^ W[0] ^ W[15]), S1); ROTATE2_F(E, A, B, C, D, W[14]); \
		W[15] = rotate((W[12] ^ W[7] ^ W[1] ^ temp), S1); ROTATE2_F(D, E, A, B, C, W[15]); \
		temp = rotate((W[13] ^ W[8] ^ W[2] ^ W[0]), S1); ROTATE2_F(C, D, E, A, B, temp); \
		W[0] = rotate(W[14] ^ W[9] ^ W[3] ^ W[1], S1); ROTATE2_F(B, C, D, E, A, W[0]); \
		W[1] = rotate(W[15] ^ W[10] ^ W[4] ^ W[2], S1); ROTATE2_F(A, B, C, D, E, W[1]); \
		W[2] = rotate(temp ^ W[11] ^ W[5] ^ W[3], S1); ROTATE2_F(E, A, B, C, D, W[2]); \
		W[3] = rotate(W[0] ^ W[12] ^ W[6] ^ W[4], S1); ROTATE2_F(D, E, A, B, C, W[3]); \
		W[4] = rotate(W[1] ^ W[13] ^ W[7] ^ W[5], S1); ROTATE2_F(C, D, E, A, B, W[4]); \
		W[5] = rotate(W[2] ^ W[14] ^ W[8] ^ W[6], S1); ROTATE2_F(B, C, D, E, A, W[5]); \
		K = 0x8F1BBCDC; \
		W[6] = rotate(W[3] ^ W[15] ^ W[9] ^ W[7], S1); ROTATE3_F(A, B, C, D, E, W[6]); \
		W[7] = rotate(W[4] ^ temp ^ W[10] ^ W[8], S1); ROTATE3_F(E, A, B, C, D, W[7]); \
		W[8] = rotate(W[5] ^ W[0] ^ W[11] ^ W[9], S1); ROTATE3_F(D, E, A, B, C, W[8]); \
		W[9] = rotate(W[6] ^ W[1] ^ W[12] ^ W[10], S1); ROTATE3_F(C, D, E, A, B, W[9]); \
		W[10] = rotate(W[7] ^ W[2] ^ W[13] ^ W[11], S1); ROTATE3_F(B, C, D, E, A, W[10]); \
		W[11] = rotate(W[8] ^ W[3] ^ W[14] ^ W[12], S1); ROTATE3_F(A, B, C, D, E, W[11]); \
		W[12] = rotate(W[9] ^ W[4] ^ W[15] ^ W[13], S1); ROTATE3_F(E, A, B, C, D, W[12]); \
		W[13] = rotate(W[10] ^ W[5] ^ temp ^ W[14], S1); ROTATE3_F(D, E, A, B, C, W[13]); \
		W[14] = rotate(W[11] ^ W[6] ^ W[0] ^ W[15], S1); ROTATE3_F(C, D, E, A, B, W[14]); \
		W[15] = rotate(W[12] ^ W[7] ^ W[1] ^ temp, S1); ROTATE3_F(B, C, D, E, A, W[15]); \
		temp = rotate(W[13] ^ W[8] ^ W[2] ^ W[0], S1); ROTATE3_F(A, B, C, D, E, temp); \
		W[0] = rotate(W[14] ^ W[9] ^ W[3] ^ W[1], S1); ROTATE3_F(E, A, B, C, D, W[0]); \
		W[1] = rotate(W[15] ^ W[10] ^ W[4] ^ W[2], S1); ROTATE3_F(D, E, A, B, C, W[1]); \
		W[2] = rotate(temp ^ W[11] ^ W[5] ^ W[3], S1); ROTATE3_F(C, D, E, A, B, W[2]); \
		W[3] = rotate(W[0] ^ W[12] ^ W[6] ^ W[4], S1); ROTATE3_F(B, C, D, E, A, W[3]); \
		W[4] = rotate(W[1] ^ W[13] ^ W[7] ^ W[5], S1); ROTATE3_F(A, B, C, D, E, W[4]); \
		W[5] = rotate(W[2] ^ W[14] ^ W[8] ^ W[6], S1); ROTATE3_F(E, A, B, C, D, W[5]); \
		W[6] = rotate(W[3] ^ W[15] ^ W[9] ^ W[7], S1); ROTATE3_F(D, E, A, B, C, W[6]); \
		W[7] = rotate(W[4] ^ temp ^ W[10] ^ W[8], S1); ROTATE3_F(C, D, E, A, B, W[7]); \
		W[8] = rotate(W[5] ^ W[0] ^ W[11] ^ W[9], S1); ROTATE3_F(B, C, D, E, A, W[8]); \
		K = 0xCA62C1D6; \
		W[9] = rotate(W[6] ^ W[1] ^ W[12] ^ W[10], S1); ROTATE4_F(A, B, C, D, E, W[9]); \
		W[10] = rotate(W[7] ^ W[2] ^ W[13] ^ W[11], S1); ROTATE4_F(E, A, B, C, D, W[10]); \
		W[11] = rotate(W[8] ^ W[3] ^ W[14] ^ W[12], S1); ROTATE4_F(D, E, A, B, C, W[11]); \
		W[12] = rotate(W[9] ^ W[4] ^ W[15] ^ W[13], S1); ROTATE4_F(C, D, E, A, B, W[12]); \
		W[13] = rotate(W[10] ^ W[5] ^ temp ^ W[14], S1); ROTATE4_F(B, C, D, E, A, W[13]); \
		W[14] = rotate(W[11] ^ W[6] ^ W[0] ^ W[15], S1); ROTATE4_F(A, B, C, D, E, W[14]); \
		W[15] = rotate(W[12] ^ W[7] ^ W[1] ^ temp, S1); ROTATE4_F(E, A, B, C, D, W[15]); \
		temp = rotate(W[13] ^ W[8] ^ W[2] ^ W[0], S1); ROTATE4_F(D, E, A, B, C, temp); \
		W[0] = rotate(W[14] ^ W[9] ^ W[3] ^ W[1], S1); ROTATE4_F(C, D, E, A, B, W[0]); \
		W[1] = rotate(W[15] ^ W[10] ^ W[4] ^ W[2], S1); ROTATE4_F(B, C, D, E, A, W[1]); \
		W[2] = rotate(temp ^ W[11] ^ W[5] ^ W[3], S1); ROTATE4_F(A, B, C, D, E, W[2]); \
		W[3] = rotate(W[0] ^ W[12] ^ W[6] ^ W[4], S1); ROTATE4_F(E, A, B, C, D, W[3]); \
		W[4] = rotate(W[1] ^ W[13] ^ W[7] ^ W[5], S1); ROTATE4_F(D, E, A, B, C, W[4]); \
		W[5] = rotate(W[2] ^ W[14] ^ W[8] ^ W[6], S1); ROTATE4_F(C, D, E, A, B, W[5]); \
		W[6] = rotate(W[3] ^ W[15] ^ W[9] ^ W[7], S1); ROTATE4_F(B, C, D, E, A, W[6]); \
		W[7] = rotate(W[4] ^ temp ^ W[10] ^ W[8], S1); ROTATE4_F(A, B, C, D, E, W[7]); \
		W[8] = rotate(W[5] ^ W[0] ^ W[11] ^ W[9], S1); ROTATE4_F(E, A, B, C, D, W[8]); \
		W[9] = rotate(W[6] ^ W[1] ^ W[12] ^ W[10], S1); ROTATE4_F(D, E, A, B, C, W[9]); \
		W[10] = rotate(W[7] ^ W[2] ^ W[13] ^ W[11], S1); ROTATE4_F(C, D, E, A, B, W[10]); \
		W[11] = rotate(W[8] ^ W[3] ^ W[14] ^ W[12], S1); ROTATE4_F(B, C, D, E, A, W[11]); \
		output[0] = a + A; \
		output[1] = b + B; \
		output[2] = c + C; \
		output[3] = d + D; \
		output[4] = e + E; \
	}

#define sha1_init(output) {	  \
		output[0] = H0; \
		output[1] = H1; \
		output[2] = H2; \
		output[3] = H3; \
		output[4] = H4; \
	}
#endif /* Lukas or Milen */

inline void hmac_sha1(__global MAYBE_VECTOR_UINT *state,
                      MAYBE_CONSTANT uchar *salt, uint saltlen, uchar add)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[5];
#ifndef OLD_NVIDIA
	MAYBE_VECTOR_UINT K;
#endif
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);

	for (i = 0; i < 5; i++)
		output[i] = state[(IPAD + i) * gws + gid];

	for (i = 0; i < 15; i++)
		W[i] = 0;

	for (i = 0; i < saltlen; i++)
		PUTCHAR_BE(W, i, salt[i]);
	PUTCHAR_BE(W, saltlen + 3, add);
	PUTCHAR_BE(W, saltlen + 4, 0x80);
	W[15] = (64 + saltlen + 4) << 3;
	sha1_block(W, output);

	for (i = 0; i < 5; i++)
		W[i] = output[i];
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;

	for (i = 0; i < 5; i++)
		output[i] = state[(OPAD + i) * gws + gid];
#ifdef OLD_NVIDIA
	sha1_block_short(W, output);
#else
	for (i = 6; i < 15; i++)
		W[i] = 0;
	sha1_block(W, output);
#endif

	for (i = 0; i < 5; i++)
		state[(OUT + i) * gws + gid] = output[i];
}

inline void preproc(__global const MAYBE_VECTOR_UINT *key,
                    __global MAYBE_VECTOR_UINT *state, uint pad, uint padding)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[5];
#ifndef OLD_NVIDIA
	MAYBE_VECTOR_UINT K;
#endif
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);

	for (i = 0; i < 16; i++)
		W[i] = key[i] ^ padding;

	sha1_init(output);
	sha1_block(W, output);

	for (i = 0; i < 5; i++)
		state[(pad + i) * gws + gid] = output[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_init(__global const MAYBE_VECTOR_UINT *inbuffer,
                 MAYBE_CONSTANT wpapsk_salt *salt,
                 __global MAYBE_VECTOR_UINT *state)
{
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint i;

	preproc(&inbuffer[gid * 16], state, IPAD, 0x36363636);
	preproc(&inbuffer[gid * 16], state, OPAD, 0x5c5c5c5c);

	hmac_sha1(state, salt->salt, salt->length, 0x01);

	for (i = 0; i < 5; i++)
		state[i * gws + gid] = state[(OUT + i) * gws + gid];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_loop(__global MAYBE_VECTOR_UINT *state)
{
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint i, j;
#ifndef OLD_NVIDIA
	MAYBE_VECTOR_UINT K;
#endif
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	MAYBE_VECTOR_UINT output[5];
	MAYBE_VECTOR_UINT state_out[5];

	for (i = 0; i < 5; i++) {
		W[i] = state[i * gws + gid];
		ipad[i] = state[(i + IPAD) * gws + gid];
		opad[i] = state[(i + OPAD) * gws + gid];
		state_out[i] = state[(i + OUT) * gws + gid];
	}

	for (j = 0; j < HASH_LOOPS; j++) {
		for (i = 0; i < 5; i++)
			output[i] = ipad[i];
		W[5] = 0x80000000;
		W[15] = (64 + 20) << 3;
#ifdef OLD_NVIDIA
		sha1_block_short(W, output);
#else
		for (i = 6; i < 15; i++)
			W[i] = 0;
		sha1_block(W, output);
#endif

		for (i = 0; i < 5; i++)
			W[i] = output[i];
		W[5] = 0x80000000;
		W[15] = (64 + 20) << 3;
		for (i = 0; i < 5; i++)
			output[i] = opad[i];
#ifdef OLD_NVIDIA
		sha1_block_short(W, output);
#else
		for (i = 6; i < 15; i++)
			W[i] = 0;
		sha1_block(W, output);
#endif

		for (i = 0; i < 5; i++)
			W[i] = output[i];

		for (i = 0; i < 5; i++)
			state_out[i] ^= output[i];
	}

	for (i = 0; i < 5; i++) {
		state[i * gws + gid] = W[i];
		state[(i + OUT) * gws + gid] = state_out[i];
	}
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_pass2(MAYBE_CONSTANT wpapsk_salt *salt,
                  __global MAYBE_VECTOR_UINT *state)
{
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint i;

	for (i = 0; i < 5; i++)
		state[(i + PARTIAL) * gws + gid] = state[(i + OUT) * gws + gid];
	for (i = 0; i < 5; i++)
		state[(i + OUT) * gws + gid] =
			VSWAP32(state[(i + OUT) * gws + gid]);

	hmac_sha1(state, salt->salt, salt->length, 0x02);

	for (i = 0; i < 5; i++)
		state[i * gws + gid] = state[(OUT + i) * gws + gid];
}

//__constant uchar *text = "Pairwise key expansion\0";
//__constant uint text[6] = { 0x72696150, 0x65736977, 0x79656b20, 0x70786520, 0x69736e61, 0x00006e6f };
__constant uint text[6] = { 0x50616972, 0x77697365, 0x206b6579, 0x20657870, 0x616e7369, 0x6f6e0000 };

inline void prf_512(const MAYBE_VECTOR_UINT *key,
                    MAYBE_CONSTANT uint *data,
                    MAYBE_VECTOR_UINT *ret)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
#ifndef OLD_NVIDIA
	MAYBE_VECTOR_UINT K;
#endif
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;

	// HMAC(EVP_sha1(), key, 32, (text.data), 100, ret, NULL);

	/* ipad */
	for (i = 0; i < 8; i++)
		W[i] = 0x36363636 ^ key[i]; // key is already swapped
	for (i = 8; i < 16; i++)
		W[i] = 0x36363636;
	sha1_init(ipad);
	sha1_block(W, ipad); // update(ipad)

	/* 64 first bytes */
	for (i = 0; i < 6; i++)
		W[i] = text[i];
	for (i = 5; i < 15; i++) {
		W[i] = (W[i] & 0xffffff00) | *data >> 24;
		W[i + 1] = *data++ << 8;
	}
	W[15] |= *data >> 24;
	sha1_block(W, ipad); // update(data)

	/* 36 remaining bytes */
	W[0] = *data++ << 8;
	for (i = 0; i < 8; i++) {
		W[i] = (W[i] & 0xffffff00) | *data >> 24;
		W[i + 1] = *data++ << 8;
	}
	W[9] = 0x80000000;
	for (i = 10; i < 15; i++)
		W[i] = 0;
	W[15] = (64 + 100) << 3;
	sha1_block(W, ipad); // update(data) + final

	/* opad */
	for (i = 0; i < 8; i++)
		W[i] = 0x5c5c5c5c ^ key[i];
	for (i = 8; i < 16; i++)
		W[i] = 0x5c5c5c5c;
	sha1_init(opad);
	sha1_block(W, opad); // update(opad)

	for (i = 0; i < 5; i++)
		W[i] = ipad[i];
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;
#ifdef OLD_NVIDIA
	sha1_block_short(W, opad);
#else
	for (i = 6; i < 15; i++)
		W[i] = 0;
	sha1_block(W, opad); // update(digest) + final
#endif

	/* Only 16 bits used */
	for (i = 0; i < 4; i++)
		ret[i] = opad[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_final_md5(__global MAYBE_VECTOR_UINT *state,
                      MAYBE_CONSTANT wpapsk_salt *salt,
                      __global mic_t *mic)
{
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	MAYBE_VECTOR_UINT outbuffer[8];
	MAYBE_VECTOR_UINT prf[4];
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT a, b, c, d;
	MAYBE_VECTOR_UINT ipad[4], opad[4];
	uint i, eapol_blocks;
	MAYBE_CONSTANT uint *cp = salt->eapol;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[(PARTIAL + i) * gws + gid];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[(OUT + i) * gws + gid];

	prf_512(outbuffer, salt->data, prf);

	// HMAC(EVP_md5(), prf, 16, hccap.eapol, hccap.eapol_size, mic[gid].keymic, NULL);
	// prf is the key (16 bytes)
	// eapol is the message (eapol_size blocks, already prepared with 0x80 and len)
	for (i = 0; i < 4; i++)
		W[i] = 0x36363636 ^ VSWAP32(prf[i]);
	for (i = 4; i < 16; i++)
		W[i] = 0x36363636;
	md5_init(ipad);
	md5_block(W, ipad); /* md5_update(ipad, 64) */

	/* eapol_blocks (of MD5),
	 * eapol data + 0x80, null padded and len set in set_salt() */
	eapol_blocks = salt->eapol_size;

	/* At least this will not diverge */
	while (eapol_blocks--) {
		for (i = 0; i < 16; i++)
			W[i] = *cp++;
		md5_block(W, ipad); /* md5_update(), md5_final() */
	}

	for (i = 0; i < 4; i++)
		W[i] = 0x5c5c5c5c ^ VSWAP32(prf[i]);
	for (i = 4; i < 16; i++)
		W[i] = 0x5c5c5c5c;
	md5_init(opad);
	md5_block(W, opad); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		W[i] = ipad[i];
	W[4] = 0x80;
	for (i = 5; i < 14; i++)
		W[i] = 0;
	W[14] = (64 + 16) << 3;
	W[15] = 0;
	md5_block(W, opad); /* md5_update(ipad, 16), md5_final() */

	for (i = 0; i < 4; i++)
#ifdef SCALAR
		mic[gid].keymic[i] = opad[i];
#else

#define VEC_OUT(NUM)	  \
		mic[gid * V_WIDTH + 0x##NUM].keymic[i] = opad[i].s##NUM

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

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_final_sha1(__global MAYBE_VECTOR_UINT *state,
                       MAYBE_CONSTANT wpapsk_salt *salt,
                       __global mic_t *mic)
{
	MAYBE_VECTOR_UINT outbuffer[8];
	MAYBE_VECTOR_UINT prf[4];
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	uint i, eapol_blocks;
	MAYBE_CONSTANT uint *cp = salt->eapol;
#ifndef OLD_NVIDIA
	MAYBE_VECTOR_UINT K;
#endif
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[(PARTIAL + i) * gws + gid];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[(OUT + i) * gws + gid];

	prf_512(outbuffer, salt->data, prf);

	// HMAC(EVP_sha1(), prf, 16, hccap.eapol, hccap.eapol_size, mic[gid].keymic, NULL);
	// prf is the key (16 bytes)
	// eapol is the message (eapol_size bytes)
	for (i = 0; i < 4; i++)
		W[i] = 0x36363636 ^ prf[i];
	for (i = 4; i < 16; i++)
		W[i] = 0x36363636;
	sha1_init(ipad);
	sha1_block(W, ipad);

	/* eapol_blocks (of SHA1),
	 * eapol data + 0x80, null padded and len set in set_salt() */
	eapol_blocks = salt->eapol_size;

	/* At least this will not diverge */
	while (eapol_blocks--) {
		for (i = 0; i < 16; i++)
			W[i] = *cp++;

		sha1_block(W, ipad);
	}

	for (i = 0; i < 4; i++)
		W[i] = 0x5c5c5c5c ^ prf[i];
	for (i = 4; i < 16; i++)
		W[i] = 0x5c5c5c5c;

	sha1_init(opad);
	sha1_block(W, opad);

	for (i = 0; i < 5; i++)
		W[i] = ipad[i];
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;
#ifdef OLD_NVIDIA
	sha1_block_short(W, opad);
#else
	for (i = 6; i < 15; i++)
		W[i] = 0;
	sha1_block(W, opad);
#endif

	/* We only use 16 bytes */
	for (i = 0; i < 4; i++)
#ifdef SCALAR
		mic[gid].keymic[i] = SWAP32(opad[i]);
#else

#undef VEC_OUT
#define VEC_OUT(NUM)	  \
	mic[gid * V_WIDTH + 0x##NUM].keymic[i] = SWAP32(opad[i].s##NUM)

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

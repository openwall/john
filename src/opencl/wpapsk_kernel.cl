/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>,
 * Copyright (c) 2012 Milen Rangelov and Copyright (c) 2012 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"

#if (defined(VECTORIZE) || (!defined(SCALAR) && gpu_amd(DEVICE_INFO) && !amd_gcn(DEVICE_INFO)))
#define MAYBE_VECTOR_UINT	uint4
#ifndef VECTORIZE
#define VECTORIZE
#endif
#else
#define MAYBE_VECTOR_UINT	uint
#ifndef SCALAR
#define SCALAR
#endif
#endif

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

/* Workaround for problem seen with 9600GT */
#if gpu_nvidia(DEVICE_INFO)
#define MAYBE_CONSTANT	__global const
#else
#define MAYBE_CONSTANT	__constant
#endif

#if gpu_nvidia(DEVICE_INFO) || amd_gcn(DEVICE_INFO)
inline uint SWAP32(uint x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#else
#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))
#endif

typedef struct {
	uint  length;
	uchar v[PLAINTEXT_LENGTH + 1];
} wpapsk_password;

typedef struct
{
	uint keymic[16 / 4];
} mic_t;

typedef struct {
	uint  length;
	uint  eapol[(256 + 64) / 4];
	uint  eapol_size;
	uint  data[(64 + 12) / 4]; // pre-processed mac and nonce
	uchar salt[36]; // essid
} wpapsk_salt;

typedef struct {
	uint W[5];
	uint ipad[5];
	uint opad[5];
	uint out[5];
	uint partial[5];
} wpapsk_state;

#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))
#define XORCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2]) ^ ((val) << ((((index) & 3) ^ 3) << 3))
#else
#define PUTCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] = (val)
#define XORCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] ^= (val)
#endif

#if gpu_nvidia(DEVICE_INFO) /* Lukas' original SHA-1 */

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
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
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
#define sha1_block(W, output) {	  \
		A = output[0]; \
		B = output[1]; \
		C = output[2]; \
		D = output[3]; \
		E = output[4]; \
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
		output[0] += A; \
		output[1] += B; \
		output[2] += C; \
		output[3] += D; \
		output[4] += E; \
	}

#define sha1_init(output) {	  \
		output[0] = H0; \
		output[1] = H1; \
		output[2] = H2; \
		output[3] = H3; \
		output[4] = H4; \
	}
#endif /* Lukas or Milen */

/* The basic MD5 functions */
#ifdef USE_BITSELECT
#define F(x, y, z)	bitselect((z), (y), (x))
#define G(x, y, z)	bitselect((y), (x), (z))
#else
#define F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)	((y) ^ ((z) & ((x) ^ (y))))
#endif

#define H(x, y, z)	((x) ^ (y) ^ (z))
#define I(x, y, z)	((y) ^ ((x) | ~(z)))


/* The MD5 transformation for all four rounds. */
#define STEP(f, a, b, c, d, x, t, s)	  \
	(a) += f((b), (c), (d)) + (x) + (t); \
	    (a) = rotate((a), (uint)(s)); \
	    (a) += (b)


/* Raw'n'lean MD5 with context in output buffer */
/* NOTE: This version thrashes the input block! */
#define md5_block(block, output)  \
	{ \
		uint a, b, c, d; \
		a = output[0]; \
		b = output[1]; \
		c = output[2]; \
		d = output[3]; \
		STEP(F, a, b, c, d, block[0], 0xd76aa478, 7); \
		STEP(F, d, a, b, c, block[1], 0xe8c7b756, 12); \
		STEP(F, c, d, a, b, block[2], 0x242070db, 17); \
		STEP(F, b, c, d, a, block[3], 0xc1bdceee, 22); \
		STEP(F, a, b, c, d, block[4], 0xf57c0faf, 7); \
		STEP(F, d, a, b, c, block[5], 0x4787c62a, 12); \
		STEP(F, c, d, a, b, block[6], 0xa8304613, 17); \
		STEP(F, b, c, d, a, block[7], 0xfd469501, 22); \
		STEP(F, a, b, c, d, block[8], 0x698098d8, 7); \
		STEP(F, d, a, b, c, block[9], 0x8b44f7af, 12); \
		STEP(F, c, d, a, b, block[10], 0xffff5bb1, 17); \
		STEP(F, b, c, d, a, block[11], 0x895cd7be, 22); \
		STEP(F, a, b, c, d, block[12], 0x6b901122, 7); \
		STEP(F, d, a, b, c, block[13], 0xfd987193, 12); \
		STEP(F, c, d, a, b, block[14], 0xa679438e, 17); \
		STEP(F, b, c, d, a, block[15], 0x49b40821, 22); \
		STEP(G, a, b, c, d, block[1], 0xf61e2562, 5); \
		STEP(G, d, a, b, c, block[6], 0xc040b340, 9); \
		STEP(G, c, d, a, b, block[11], 0x265e5a51, 14); \
		STEP(G, b, c, d, a, block[0], 0xe9b6c7aa, 20); \
		STEP(G, a, b, c, d, block[5], 0xd62f105d, 5); \
		STEP(G, d, a, b, c, block[10], 0x02441453, 9); \
		STEP(G, c, d, a, b, block[15], 0xd8a1e681, 14); \
		STEP(G, b, c, d, a, block[4], 0xe7d3fbc8, 20); \
		STEP(G, a, b, c, d, block[9], 0x21e1cde6, 5); \
		STEP(G, d, a, b, c, block[14], 0xc33707d6, 9); \
		STEP(G, c, d, a, b, block[3], 0xf4d50d87, 14); \
		STEP(G, b, c, d, a, block[8], 0x455a14ed, 20); \
		STEP(G, a, b, c, d, block[13], 0xa9e3e905, 5); \
		STEP(G, d, a, b, c, block[2], 0xfcefa3f8, 9); \
		STEP(G, c, d, a, b, block[7], 0x676f02d9, 14); \
		STEP(G, b, c, d, a, block[12], 0x8d2a4c8a, 20); \
		STEP(H, a, b, c, d, block[5], 0xfffa3942, 4); \
		STEP(H, d, a, b, c, block[8], 0x8771f681, 11); \
		STEP(H, c, d, a, b, block[11], 0x6d9d6122, 16); \
		STEP(H, b, c, d, a, block[14], 0xfde5380c, 23); \
		STEP(H, a, b, c, d, block[1], 0xa4beea44, 4); \
		STEP(H, d, a, b, c, block[4], 0x4bdecfa9, 11); \
		STEP(H, c, d, a, b, block[7], 0xf6bb4b60, 16); \
		STEP(H, b, c, d, a, block[10], 0xbebfbc70, 23); \
		STEP(H, a, b, c, d, block[13], 0x289b7ec6, 4); \
		STEP(H, d, a, b, c, block[0], 0xeaa127fa, 11); \
		STEP(H, c, d, a, b, block[3], 0xd4ef3085, 16); \
		STEP(H, b, c, d, a, block[6], 0x04881d05, 23); \
		STEP(H, a, b, c, d, block[9], 0xd9d4d039, 4); \
		STEP(H, d, a, b, c, block[12], 0xe6db99e5, 11); \
		STEP(H, c, d, a, b, block[15], 0x1fa27cf8, 16); \
		STEP(H, b, c, d, a, block[2], 0xc4ac5665, 23); \
		STEP(I, a, b, c, d, block[0], 0xf4292244, 6); \
		STEP(I, d, a, b, c, block[7], 0x432aff97, 10); \
		STEP(I, c, d, a, b, block[14], 0xab9423a7, 15); \
		STEP(I, b, c, d, a, block[5], 0xfc93a039, 21); \
		STEP(I, a, b, c, d, block[12], 0x655b59c3, 6); \
		STEP(I, d, a, b, c, block[3], 0x8f0ccc92, 10); \
		STEP(I, c, d, a, b, block[10], 0xffeff47d, 15); \
		STEP(I, b, c, d, a, block[1], 0x85845dd1, 21); \
		STEP(I, a, b, c, d, block[8], 0x6fa87e4f, 6); \
		STEP(I, d, a, b, c, block[15], 0xfe2ce6e0, 10); \
		STEP(I, c, d, a, b, block[6], 0xa3014314, 15); \
		STEP(I, b, c, d, a, block[13], 0x4e0811a1, 21); \
		STEP(I, a, b, c, d, block[4], 0xf7537e82, 6); \
		STEP(I, d, a, b, c, block[11], 0xbd3af235, 10); \
		STEP(I, c, d, a, b, block[2], 0x2ad7d2bb, 15); \
		STEP(I, b, c, d, a, block[9], 0xeb86d391, 21); \
		output[0] += a; \
		output[1] += b; \
		output[2] += c; \
		output[3] += d; \
	}


#define md5_init(output) {	  \
		output[0] = 0x67452301; \
		output[1] = 0xefcdab89; \
		output[2] = 0x98badcfe; \
		output[3] = 0x10325476; \
	}

#define dump_stuff_msg(msg, x, size) {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (size)/4; ii++) \
			printf("%08x ", x[ii]); \
		printf("\n"); \
	}

inline void preproc(__global const uchar *key, uint keylen,
                    __global uint *state, uint padding)
{
	uint i;
	uint W[16];
	uint output[5];
#if !gpu_nvidia(DEVICE_INFO)
	uint K;
#endif
	uint A, B, C, D, E, temp;

	for (i = 0; i < 16; i++)
		W[i] = padding;

	for (i = 0; i < keylen; i++)
		XORCHAR_BE(W, i, key[i]);

	sha1_init(output);
	sha1_block(W, output);

	for (i = 0; i < 5; i++)
		state[i] = output[i];
}

inline void hmac_sha1(__global uint *state,
                      __global uint *ipad,
                      __global uint *opad,
                      MAYBE_CONSTANT uchar *salt, uint saltlen, uchar add)
{
	uint i;
	uint W[16];
	uint output[5];
#if !gpu_nvidia(DEVICE_INFO)
	uint K;
#endif
	uint A, B, C, D, E, temp;

	for (i = 0; i < 5; i++)
		output[i] = ipad[i];

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
		output[i] = opad[i];
#if gpu_nvidia(DEVICE_INFO)
	sha1_block_short(W, output);
#else
	for (i = 6; i < 15; i++)
		W[i] = 0;
	sha1_block(W, output);
#endif

	for (i = 0; i < 5; i++)
		state[i] = output[i];
}

__kernel void wpapsk_init(__global const wpapsk_password *inbuffer,
                          MAYBE_CONSTANT wpapsk_salt *salt,
                          __global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i;

	preproc(inbuffer[gid].v, inbuffer[gid].length, state[gid].ipad, 0x36363636);
	preproc(inbuffer[gid].v, inbuffer[gid].length, state[gid].opad, 0x5c5c5c5c);

	hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad, salt->salt, salt->length, 0x01);

	for (i = 0; i < 5; i++)
		state[gid].W[i] = state[gid].out[i];
}

__kernel void wpapsk_loop(__global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i, j;
#if !gpu_nvidia(DEVICE_INFO)
	MAYBE_VECTOR_UINT K;
#endif
	MAYBE_VECTOR_UINT A, B, C, D, E, temp;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	MAYBE_VECTOR_UINT output[5];
	MAYBE_VECTOR_UINT state_out[5];

#ifdef VECTORIZE
	for (i = 0; i < 5; i++) {
		W[i].s0 = state[gid*4+0].W[i];
		W[i].s1 = state[gid*4+1].W[i];
		W[i].s2 = state[gid*4+2].W[i];
		W[i].s3 = state[gid*4+3].W[i];
	}
	for (i = 0; i < 5; i++) {
		ipad[i].s0 = state[gid*4+0].ipad[i];
		ipad[i].s1 = state[gid*4+1].ipad[i];
		ipad[i].s2 = state[gid*4+2].ipad[i];
		ipad[i].s3 = state[gid*4+3].ipad[i];
	}
	for (i = 0; i < 5; i++) {
		opad[i].s0 = state[gid*4+0].opad[i];
		opad[i].s1 = state[gid*4+1].opad[i];
		opad[i].s2 = state[gid*4+2].opad[i];
		opad[i].s3 = state[gid*4+3].opad[i];
	}
	for (i = 0; i < 5; i++) {
		state_out[i].s0 = state[gid*4+0].out[i];
		state_out[i].s1 = state[gid*4+1].out[i];
		state_out[i].s2 = state[gid*4+2].out[i];
		state_out[i].s3 = state[gid*4+3].out[i];
	}
#else
	for (i = 0; i < 5; i++)
		W[i] = state[gid].W[i];
	for (i = 0; i < 5; i++)
		ipad[i] = state[gid].ipad[i];
	for (i = 0; i < 5; i++)
		opad[i] = state[gid].opad[i];
	for (i = 0; i < 5; i++)
		state_out[i] = state[gid].out[i];
#endif

	for (j = 0; j < HASH_LOOPS; j++) {
		for (i = 0; i < 5; i++)
			output[i] = ipad[i];
		W[5] = 0x80000000;
		W[15] = (64 + 20) << 3;
#if gpu_nvidia(DEVICE_INFO)
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
#if gpu_nvidia(DEVICE_INFO)
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

#ifdef VECTORIZE
	for (i = 0; i < 5; i++) {
		state[gid*4+0].W[i] = W[i].s0;
		state[gid*4+1].W[i] = W[i].s1;
		state[gid*4+2].W[i] = W[i].s2;
		state[gid*4+3].W[i] = W[i].s3;
	}
	for (i = 0; i < 5; i++) {
		state[gid*4+0].out[i] = state_out[i].s0;
		state[gid*4+1].out[i] = state_out[i].s1;
		state[gid*4+2].out[i] = state_out[i].s2;
		state[gid*4+3].out[i] = state_out[i].s3;
	}
#else
	for (i = 0; i < 5; i++)
		state[gid].W[i] = W[i];
	for (i = 0; i < 5; i++)
		state[gid].out[i] = state_out[i];
#endif
}

__kernel void wpapsk_pass2(MAYBE_CONSTANT wpapsk_salt *salt,
                           __global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i;

	for (i = 0; i < 5; i++)
		state[gid].partial[i] = state[gid].out[i];
	for (i = 0; i < 5; i++)
		state[gid].out[i] = SWAP32(state[gid].out[i]);

	hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad, salt->salt, salt->length, 0x02);

	for (i = 0; i < 5; i++)
		state[gid].W[i] = state[gid].out[i];
}

inline void prf_512(const uint *key, MAYBE_CONSTANT uint *data, uint *ret)
{
	//const uchar *text = "Pairwise key expansion\0";
	//const uint text[6] = { 0x72696150, 0x65736977, 0x79656b20, 0x70786520, 0x69736e61, 0x00006e6f };
	const uint text[6] = { 0x50616972, 0x77697365, 0x206b6579, 0x20657870, 0x616e7369, 0x6f6e0000 };
	uint i;
	uint W[16];
	uint ipad[5];
	uint opad[5];
#if !gpu_nvidia(DEVICE_INFO)
	uint K;
#endif
	uint A, B, C, D, E, temp;

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
#if gpu_nvidia(DEVICE_INFO)
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

__kernel void wpapsk_final_md5(__global wpapsk_state *state,
                               MAYBE_CONSTANT wpapsk_salt *salt,
                               __global mic_t *mic)
{
	uint gid = get_global_id(0);
	uint outbuffer[8];
	uint prf[4];
	uint W[16];
	uint ipad[4], opad[4];
	uint i, eapol_blocks;
	MAYBE_CONSTANT uint *cp = salt->eapol;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[gid].partial[i];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[gid].out[i];

	prf_512(outbuffer, salt->data, prf);

	// HMAC(EVP_md5(), prf, 16, hccap.eapol, hccap.eapol_size, mic[gid].keymic, NULL);
	// prf is the key (16 bytes)
	// eapol is the message (eapol_size blocks, already prepared with 0x80 and len)
	for (i = 0; i < 4; i++)
		W[i] = 0x36363636 ^ SWAP32(prf[i]);
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
		W[i] = 0x5c5c5c5c ^ SWAP32(prf[i]);
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
		mic[gid].keymic[i] = opad[i];
}

__kernel void wpapsk_final_sha1(__global wpapsk_state *state,
                               MAYBE_CONSTANT wpapsk_salt *salt,
                               __global mic_t *mic)
{
	uint outbuffer[8];
	uint prf[4];
	uint gid = get_global_id(0);
	uint W[16];
	uint ipad[5];
	uint opad[5];
	uint i, eapol_blocks;
	MAYBE_CONSTANT uint *cp = salt->eapol;
#if !gpu_nvidia(DEVICE_INFO)
	uint K;
#endif
	uint A, B, C, D, E, temp;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[gid].partial[i];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[gid].out[i];

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
#if gpu_nvidia(DEVICE_INFO)
	sha1_block_short(W, opad);
#else
	for (i = 6; i < 15; i++)
		W[i] = 0;
	sha1_block(W, opad);
#endif

	/* We only use 16 bytes */
	for (i = 0; i < 4; i++)
		mic[gid].keymic[i] = SWAP32(opad[i]);
}

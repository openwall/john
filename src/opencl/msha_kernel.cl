/*
 * This code is copyright (c) 2013 magnum
 * and hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

/* Macros for reading/writing chars from int32's */
#if no_byte_addressable(DEVICE_INFO)
/* 32-bit stores */
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))
#else
/* Byte-adressed stores */
#define PUTCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] = (val)
#endif

#define INIT_A          0x67452301
#define INIT_B          0xefcdab89
#define INIT_C          0x98badcfe
#define INIT_D          0x10325476
#define INIT_E          0xc3d2e1f0

#define SQRT_2          0x5a827999
#define SQRT_3          0x6ed9eba1

#define K1              0x5a827999
#define K2              0x6ed9eba1
#define K3              0x8f1bbcdc
#define K4              0xca62c1d6

#ifdef USE_BITSELECT
#define F1(x, y, z)     bitselect(z, y, x)
#else
#define F1(x, y, z)     (z ^ (x & (y ^ z)))
#endif

#define F2(x, y, z)     (x ^ y ^ z)

#ifdef USE_BITSELECT
#define F3(x, y, z)     (bitselect(x, y, z) ^ bitselect(x, 0U, y))
#else
#define F3(x, y, z)     ((x & y) | (z & (x | y)))
#endif

#define F4(x, y, z)     (x ^ y ^ z)

#define R(t)	  \
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

#define Q16 (W[0] = rotate((W[2] ^ W[0]), 1U))
#define Q17 (W[1] = rotate((W[3] ^ W[1]), 1U))
#define Q18 (W[2] = rotate((W[15] ^ W[4] ^ W[2]), 1U))
#define Q19 (W[3] = rotate((W[0]  ^ W[5] ^ W[3]), 1U))
#define Q20 (W[4] = rotate((W[1]  ^ W[4]), 1U))
#define Q21 (W[5] = rotate((W[2] ^ W[5]), 1U))
#define Q22 (W[6] = rotate(W[3], 1U))
#define Q23 (W[7] = rotate((W[4] ^ W[15]), 1U))
#define Q24 (W[8] = rotate((W[5] ^ W[0]), 1U))
#define Q25 (W[9] = rotate((W[6] ^ W[1]), 1U))
#define Q26 (W[10] = rotate((W[7] ^ W[2]), 1U))
#define Q27 (W[11] = rotate((W[8] ^ W[3]), 1U))
#define Q28 (W[12] = rotate((W[9] ^ W[4]), 1U))
#define Q29 (W[13] = rotate((W[10] ^ W[5] ^ W[15]), 1U))
#define Q30 (W[14] = rotate((W[11] ^ W[6] ^ W[0]), 1U))

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

#define sha1_single(b, o) {	\
		A = INIT_A; \
		B = INIT_B; \
		C = INIT_C; \
		D = INIT_D; \
		E = INIT_E; \
		SHA1(A, B, C, D, E, b); \
		o[0] = A + INIT_A; \
		o[1] = B + INIT_B; \
		o[2] = C + INIT_C; \
		o[3] = D + INIT_D; \
		o[4] = E + INIT_E; \
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

#define sha1_single_short(b, o) {	\
		A = INIT_A; \
		B = INIT_B; \
		C = INIT_C; \
		D = INIT_D; \
		E = INIT_E; \
		SHA1_SHORT(A, B, C, D, E, b); \
		o[0] = A + INIT_A; \
		o[1] = B + INIT_B; \
		o[2] = C + INIT_C; \
		o[3] = D + INIT_D; \
		o[4] = E + INIT_E; \
	}


__kernel void mysqlsha1_crypt_kernel(__global const uchar *key,
                                     __global const uint *index,
                                     __global uint *digest)
{
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint W[16] = { 0 };
	uint output[5];
	uint A, B, C, D, E, temp;
	uint i;
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	key += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	for (i = 0; i < len; i++)
		PUTCHAR_BE(W, i, key[i]);
	PUTCHAR_BE(W, i, 0x80);
	W[15] = i << 3;
	sha1_single(W, output);

	W[0] = output[0];
	W[1] = output[1];
	W[2] = output[2];
	W[3] = output[3];
	W[4] = output[4];
	W[5] = 0x80000000;
#if 0
	for (i = 6; i < 16; i++)
		W[i] = 0;
	W[15] = 20 << 3;
	sha1_single(W, output);
#else
	W[15] = 20 << 3;
	sha1_single_short(W, output);
#endif
	for (i = 0; i < 5; i++)
		digest[i * gws + gid] = output[i];
}

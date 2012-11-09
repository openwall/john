/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>
 * and Copyright (c) 2012 magnum, and it is hereby released to the general
 * public under the following terms: Redistribution and use in source and
 * binary forms, with or without modification, are permitted.
 */

#include "opencl_device_info.h"

#if gpu_nvidia(DEVICE_INFO) || amd_gcn(DEVICE_INFO)
#define SCALAR
#endif

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

/* Workaround for driver bug seen in version 295.49 */
#if gpu_nvidia(DEVICE_INFO)
#define MAYBE_CONSTANT __global const
#else
#define MAYBE_CONSTANT	__constant
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

typedef struct {
	uint  length;
	uchar v[PLAINTEXT_LENGTH];
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
	uchar salt[15]; // essid
} wpapsk_salt;

typedef struct {
	uint W[5];
	uint ipad[5];
	uint opad[5];
	uint out[5];
	uint partial[5];
} wpapsk_state;

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

#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))
#define XORCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2]) ^ ((val) << ((((index) & 3) ^ 3) << 3))
#else
#define PUTCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] = (val)
#define XORCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] ^= (val)
#endif

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
inline void md5_block(uint *W, uint *output)
{
	uint a, b, c, d;

	a = output[0];
	b = output[1];
	c = output[2];
	d = output[3];

	/* Round 1 */
	STEP(F, a, b, c, d, W[0], 0xd76aa478, 7);
	STEP(F, d, a, b, c, W[1], 0xe8c7b756, 12);
	STEP(F, c, d, a, b, W[2], 0x242070db, 17);
	STEP(F, b, c, d, a, W[3], 0xc1bdceee, 22);
	STEP(F, a, b, c, d, W[4], 0xf57c0faf, 7);
	STEP(F, d, a, b, c, W[5], 0x4787c62a, 12);
	STEP(F, c, d, a, b, W[6], 0xa8304613, 17);
	STEP(F, b, c, d, a, W[7], 0xfd469501, 22);
	STEP(F, a, b, c, d, W[8], 0x698098d8, 7);
	STEP(F, d, a, b, c, W[9], 0x8b44f7af, 12);
	STEP(F, c, d, a, b, W[10], 0xffff5bb1, 17);
	STEP(F, b, c, d, a, W[11], 0x895cd7be, 22);
	STEP(F, a, b, c, d, W[12], 0x6b901122, 7);
	STEP(F, d, a, b, c, W[13], 0xfd987193, 12);
	STEP(F, c, d, a, b, W[14], 0xa679438e, 17);
	STEP(F, b, c, d, a, W[15], 0x49b40821, 22);

	/* Round 2 */
	STEP(G, a, b, c, d, W[1], 0xf61e2562, 5);
	STEP(G, d, a, b, c, W[6], 0xc040b340, 9);
	STEP(G, c, d, a, b, W[11], 0x265e5a51, 14);
	STEP(G, b, c, d, a, W[0], 0xe9b6c7aa, 20);
	STEP(G, a, b, c, d, W[5], 0xd62f105d, 5);
	STEP(G, d, a, b, c, W[10], 0x02441453, 9);
	STEP(G, c, d, a, b, W[15], 0xd8a1e681, 14);
	STEP(G, b, c, d, a, W[4], 0xe7d3fbc8, 20);
	STEP(G, a, b, c, d, W[9], 0x21e1cde6, 5);
	STEP(G, d, a, b, c, W[14], 0xc33707d6, 9);
	STEP(G, c, d, a, b, W[3], 0xf4d50d87, 14);
	STEP(G, b, c, d, a, W[8], 0x455a14ed, 20);
	STEP(G, a, b, c, d, W[13], 0xa9e3e905, 5);
	STEP(G, d, a, b, c, W[2], 0xfcefa3f8, 9);
	STEP(G, c, d, a, b, W[7], 0x676f02d9, 14);
	STEP(G, b, c, d, a, W[12], 0x8d2a4c8a, 20);

	/* Round 3 */
	STEP(H, a, b, c, d, W[5], 0xfffa3942, 4);
	STEP(H, d, a, b, c, W[8], 0x8771f681, 11);
	STEP(H, c, d, a, b, W[11], 0x6d9d6122, 16);
	STEP(H, b, c, d, a, W[14], 0xfde5380c, 23);
	STEP(H, a, b, c, d, W[1], 0xa4beea44, 4);
	STEP(H, d, a, b, c, W[4], 0x4bdecfa9, 11);
	STEP(H, c, d, a, b, W[7], 0xf6bb4b60, 16);
	STEP(H, b, c, d, a, W[10], 0xbebfbc70, 23);
	STEP(H, a, b, c, d, W[13], 0x289b7ec6, 4);
	STEP(H, d, a, b, c, W[0], 0xeaa127fa, 11);
	STEP(H, c, d, a, b, W[3], 0xd4ef3085, 16);
	STEP(H, b, c, d, a, W[6], 0x04881d05, 23);
	STEP(H, a, b, c, d, W[9], 0xd9d4d039, 4);
	STEP(H, d, a, b, c, W[12], 0xe6db99e5, 11);
	STEP(H, c, d, a, b, W[15], 0x1fa27cf8, 16);
	STEP(H, b, c, d, a, W[2], 0xc4ac5665, 23);

	/* Round 4 */
	STEP(I, a, b, c, d, W[0], 0xf4292244, 6);
	STEP(I, d, a, b, c, W[7], 0x432aff97, 10);
	STEP(I, c, d, a, b, W[14], 0xab9423a7, 15);
	STEP(I, b, c, d, a, W[5], 0xfc93a039, 21);
	STEP(I, a, b, c, d, W[12], 0x655b59c3, 6);
	STEP(I, d, a, b, c, W[3], 0x8f0ccc92, 10);
	STEP(I, c, d, a, b, W[10], 0xffeff47d, 15);
	STEP(I, b, c, d, a, W[1], 0x85845dd1, 21);
	STEP(I, a, b, c, d, W[8], 0x6fa87e4f, 6);
	STEP(I, d, a, b, c, W[15], 0xfe2ce6e0, 10);
	STEP(I, c, d, a, b, W[6], 0xa3014314, 15);
	STEP(I, b, c, d, a, W[13], 0x4e0811a1, 21);
	STEP(I, a, b, c, d, W[4], 0xf7537e82, 6);
	STEP(I, d, a, b, c, W[11], 0xbd3af235, 10);
	STEP(I, c, d, a, b, W[2], 0x2ad7d2bb, 15);
	STEP(I, b, c, d, a, W[9], 0xeb86d391, 21);

	output[0] += a;
	output[1] += b;
	output[2] += c;
	output[3] += d;
}


#define md5_init(output) {	  \
	output[0] = 0x67452301; \
	output[1] = 0xefcdab89; \
	output[2] = 0x98badcfe; \
	output[3] = 0x10325476; \
	}

inline void preproc(__global const uchar *key, uint keylen,
                    __global uint *state, uchar var1, uint var4)
{
	uint i;
	uint W[16], temp;
	uint A = INIT_A;
	uint B = INIT_B;
	uint C = INIT_C;
	uint D = INIT_D;
	uint E = INIT_E;

	for (i = 0; i < 16; i++)
		W[i] = var4;

	for (i = 0; i < keylen; i++)
		XORCHAR_BE(W, i, key[i]);

	SHA1(A, B, C, D, E, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;
}

inline void hmac_sha1(__global uint *output,
                      __global uint *ipad,
                      __global uint *opad,
                      MAYBE_CONSTANT uchar *salt, uint saltlen, uchar add)
{
	uint i;
	uint W[16], temp;
	uint A, B, C, D, E;

	for (i = 0; i < 16; i++)
		W[i] = 0;

	for (i = 0; i < saltlen; i++)
		PUTCHAR_BE(W, i, salt[i]);

	PUTCHAR_BE(W, saltlen + 3, add);
	PUTCHAR_BE(W, saltlen + 4, 0x80);
	W[15] = (64 + saltlen + 4) << 3;

	A = ipad[0];
	B = ipad[1];
	C = ipad[2];
	D = ipad[3];
	E = ipad[4];

	SHA1(A, B, C, D, E, W);

	A += ipad[0];
	B += ipad[1];
	C += ipad[2];
	D += ipad[3];
	E += ipad[4];

	W[0] = A;
	W[1] = B;
	W[2] = C;
	W[3] = D;
	W[4] = E;
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;

	A = opad[0];
	B = opad[1];
	C = opad[2];
	D = opad[3];
	E = opad[4];

	SHA1_SHORT(A, B, C, D, E, W);

	A += opad[0];
	B += opad[1];
	C += opad[2];
	D += opad[3];
	E += opad[4];

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
}

__kernel void wpapsk_init(__global const wpapsk_password *inbuffer,
                          MAYBE_CONSTANT wpapsk_salt *salt,
                          __global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i;

	preproc(inbuffer[gid].v, inbuffer[gid].length, state[gid].ipad, 0x36, 0x36363636);
	preproc(inbuffer[gid].v, inbuffer[gid].length, state[gid].opad, 0x5c, 0x5c5c5c5c);

	hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad, salt->salt, salt->length, 0x01);

	for (i = 0; i < 5; i++)
		state[gid].W[i] = state[gid].out[i];
}

__kernel void wpapsk_loop(__global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i;
	uint temp, W[16];
	uint ipad[5];
	uint opad[5];
	uint out[5];
	uint A, B, C, D, E;

	for (i = 0; i < 5; i++)
		W[i] = state[gid].W[i];
	for (i = 0; i < 5; i++)
		ipad[i] = state[gid].ipad[i];
	for (i = 0; i < 5; i++)
		opad[i] = state[gid].opad[i];
	for (i = 0; i < 5; i++)
		out[i] = state[gid].out[i];

	for (i = 0; i < HASH_LOOPS; i++) {
		A = ipad[0];
		B = ipad[1];
		C = ipad[2];
		D = ipad[3];
		E = ipad[4];

		W[5] = 0x80000000;
		W[15] = (64 + 20) << 3;

		SHA1_SHORT(A, B, C, D, E, W);

		A += ipad[0];
		B += ipad[1];
		C += ipad[2];
		D += ipad[3];
		E += ipad[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = 0x80000000;
		W[15] = (64 + 20) << 3;

		A = opad[0];
		B = opad[1];
		C = opad[2];
		D = opad[3];
		E = opad[4];

		SHA1_SHORT(A, B, C, D, E, W);

		A += opad[0];
		B += opad[1];
		C += opad[2];
		D += opad[3];
		E += opad[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;

		out[0] ^= A;
		out[1] ^= B;
		out[2] ^= C;
		out[3] ^= D;
		out[4] ^= E;
	}

	for (i = 0; i < 5; i++)
		state[gid].W[i] = W[i];
	for (i = 0; i < 5; i++)
		state[gid].ipad[i] = ipad[i];
	for (i = 0; i < 5; i++)
		state[gid].opad[i] = opad[i];
	for (i = 0; i < 5; i++)
		state[gid].out[i] = out[i];
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

#define dump_stuff_msg(msg, x, size) {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (size)/4; ii++) \
			printf("%08x ", x[ii]); \
		printf("\n"); \
	}

inline void prf_512(const uint *key, MAYBE_CONSTANT uint *data, uint *ret)
{
	//const uchar *text = "Pairwise key expansion\0";
	//const uint text[6] = { 0x72696150, 0x65736977, 0x79656b20, 0x70786520, 0x69736e61, 0x00006e6f };
	const uint text[6] = { 0x50616972, 0x77697365, 0x206b6579, 0x20657870, 0x616e7369, 0x6f6e0000 };
	uint i;
	uint output[5];
	uint hash[5];
	uint W[16], temp;
	uint A, B, C, D, E;

	// HMAC(EVP_sha1(), key, 32, (text.data), 100, ret, NULL);

	for (i = 0; i < 8; i++)
		W[i] = 0x36363636 ^ key[i]; // key is already swapped
	for (i = 8; i < 16; i++)
		W[i] = 0x36363636;

	sha1_init(output);
	sha1_block(W, output); // update(ipad)

	/* 64 first bytes */
	for (i = 0; i < 6; i++)
		W[i] = text[i];
	for (i = 5; i < 15; i++) {
		W[i] = (W[i] & 0xffffff00) | *data >> 24;
		W[i + 1] = *data++ << 8;
	}
	W[15] |= *data >> 24;

	sha1_block(W, output); // update(data)

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

	sha1_block(W, output); // update(data) + final

	for (i = 0; i < 5; i++)
		hash[i] = output[i];
	for (i = 0; i < 8; i++)
		W[i] = 0x5c5c5c5c ^ key[i];
	for (i = 8; i < 16; i++)
		W[i] = 0x5c5c5c5c;

	sha1_init(output);
	sha1_block(W, output); // update(opad)

	for (i = 0; i < 5; i++)
		W[i] = hash[i];
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;
	sha1_block_short(W, output); // update(digest) + final

	/* Only 16 bits used */
	for (i = 0; i < 4; i++)
		ret[i] = output[i];
}

__kernel void wpapsk_final_md5(__global wpapsk_state *state,
                               MAYBE_CONSTANT wpapsk_salt *salt,
                               __global mic_t *mic)
{
	uint outbuffer[8];
	uint prf[4];
	uint W[16];
	uint output[4], hash[4];
	uint gid = get_global_id(0);
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
	md5_init(output);
	for (i = 0; i < 4; i++)
		W[i] = 0x36363636 ^ SWAP32(prf[i]);
	for (i = 4; i < 16; i++)
		W[i] = 0x36363636;
	md5_block(W, output); /* md5_update(ipad, 64) */

	/* eapol_blocks (of MD5),
	 * eapol data + 0x80, null padded and len set in set_salt() */
	eapol_blocks = salt->eapol_size;
	//printf("md5 eapol blocks: %u\n", eapol_blocks);

	/* At least this will not diverge */
	while (eapol_blocks--) {
		for (i = 0; i < 16; i++)
			W[i] = *cp++;
		md5_block(W, output); /* md5_update(), md5_final() */
	}

	for (i = 0; i < 4; i++)
		hash[i] = output[i];
	md5_init(output);
	for (i = 0; i < 4; i++)
		W[i] = 0x5c5c5c5c ^ SWAP32(prf[i]);
	for (i = 4; i < 16; i++)
		W[i] = 0x5c5c5c5c;
	md5_block(W, output); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		W[i] = hash[i];
	W[4] = 0x80;
	for (i = 5; i < 14; i++)
		W[i] = 0;
	W[14] = (64 + 16) << 3;
	W[15] = 0;
	md5_block(W, output); /* md5_update(hash, 16), md5_final() */

	for (i = 0; i < 4; i++)
		mic[gid].keymic[i] = output[i];
}

__kernel void wpapsk_final_sha1(__global wpapsk_state *state,
                               MAYBE_CONSTANT wpapsk_salt *salt,
                               __global mic_t *mic)
{
	uint outbuffer[8];
	uint prf[4];
	uint gid = get_global_id(0);
	uint ipad[5];
	uint opad[5];
	uint W[16], temp;
	uint A, B, C, D, E;
	uint i, eapol_blocks;
	MAYBE_CONSTANT uint *cp = salt->eapol;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[gid].partial[i];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[gid].out[i];

	prf_512(outbuffer, salt->data, prf);

	// HMAC(EVP_sha1(), prf, 16, hccap.eapol, hccap.eapol_size, mic[gid].keymic, NULL);
	// prf is the key (16 bytes)
	// eapol is the message (eapol_size bytes)
	A = INIT_A;
	B = INIT_B;
	C = INIT_C;
	D = INIT_D;
	E = INIT_E;

	for (i = 0; i < 4; i++)
		W[i] = 0x36363636 ^ prf[i];
	for (i = 4; i < 16; i++)
		W[i] = 0x36363636;

	SHA1(A, B, C, D, E, W);

	A += INIT_A;
	B += INIT_B;
	C += INIT_C;
	D += INIT_D;
	E += INIT_E;

	ipad[0] = A;
	ipad[1] = B;
	ipad[2] = C;
	ipad[3] = D;
	ipad[4] = E;

	A = INIT_A;
	B = INIT_B;
	C = INIT_C;
	D = INIT_D;
	E = INIT_E;

	for (i = 0; i < 4; i++)
		W[i] = 0x5c5c5c5c ^ prf[i];
	for (i = 4; i < 16; i++)
		W[i] = 0x5c5c5c5c;

	SHA1(A, B, C, D, E, W);

	A += INIT_A;
	B += INIT_B;
	C += INIT_C;
	D += INIT_D;
	E += INIT_E;

	opad[0] = A;
	opad[1] = B;
	opad[2] = C;
	opad[3] = D;
	opad[4] = E;

	A = ipad[0];
	B = ipad[1];
	C = ipad[2];
	D = ipad[3];
	E = ipad[4];

	/* eapol_blocks (of SHA1),
	 * eapol data + 0x80, null padded and len set in set_salt() */
	eapol_blocks = salt->eapol_size;

	/* At least this will not diverge */
	while (eapol_blocks--) {
		for (i = 0; i < 16; i++)
			W[i] = *cp++;

		SHA1(A, B, C, D, E, W);

		A += ipad[0];
		B += ipad[1];
		C += ipad[2];
		D += ipad[3];
		E += ipad[4];

		ipad[0] = A;
		ipad[1] = B;
		ipad[2] = C;
		ipad[3] = D;
		ipad[4] = E;
	}

	W[0] = A;
	W[1] = B;
	W[2] = C;
	W[3] = D;
	W[4] = E;
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;

	A = opad[0];
	B = opad[1];
	C = opad[2];
	D = opad[3];
	E = opad[4];

	SHA1_SHORT(A, B, C, D, E, W);

	/* We only use 16 bytes */
	mic[gid].keymic[0] = SWAP32(A + opad[0]);
	mic[gid].keymic[1] = SWAP32(B + opad[1]);
	mic[gid].keymic[2] = SWAP32(C + opad[2]);
	mic[gid].keymic[3] = SWAP32(D + opad[3]);
}

/*
 * RIPEMD-160 implementation. Copyright (c) 2015, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#ifndef RIPEMD160_DIGEST_LENGTH
#define RIPEMD160_DIGEST_LENGTH 20
#endif

#undef RIPEMD_LUT3 /* No good for this format, just here for reference */

#if RIPEMD_LUT3
#define F1(x, y, z)   lut3(x, y, z, 0x96)
#define F2(x, y, z)   lut3(x, y, z, 0xca)
#define F3(x, y, z)   lut3(x, y, z, 0x59)
#define F4(x, y, z)   lut3(x, y, z, 0xe4)
#define F5(x, y, z)   lut3(x, y, z, 0x2d)
#elif USE_BITSELECT
#define F1(x, y, z)   ((x) ^ (y) ^ (z))
#define F2(x, y, z)   bitselect(z, y, x)
#define F3(x, y, z)   (((x) | ~(y)) ^ (z))
#define F4(x, y, z)   bitselect(y, x, z)
#define F5(x, y, z)   ((x) ^ ((y) | ~(z)))
#else
#define F1(x, y, z)   ((x) ^ (y) ^ (z))
#define F2(x, y, z)   ((((y) ^ (z)) & (x)) ^ (z))
#define F3(x, y, z)   (((x) | ~(y)) ^ (z))
#define F4(x, y, z)   ((((x) ^ (y)) & (z)) ^ (y))
#define F5(x, y, z)   ((x) ^ ((y) | ~(z)))
#endif

#define INIT_A 0x67452301U
#define INIT_B 0xefcdab89U
#define INIT_C 0x98badcfeU
#define INIT_D 0x10325476U
#define INIT_E 0xc3d2e1f0U

#define K11    0x00000000U
#define K12    0x5a827999U
#define K13    0x6ed9eba1U
#define K14    0x8f1bbcdcU
#define K15    0xa953fd4eU

#define K21    0x50a28be6U
#define K22    0x5c4dd124U
#define K23    0x6d703ef3U
#define K24    0x7a6d76e9U
#define K25    0x00000000U

#define RR(a, b, c, d, e, f, s, r, k)  do { \
		a = rotate(a + f(b, c, d) + r + k, (uint)s) + e; \
		c = rotate(c, 10U); \
	} while (0)

#define ROUND1(a, b, c, d, e, f, s, r, k) \
	RR(a ## 1, b ## 1, c ## 1, d ## 1, e ## 1, f, s, r, K1 ## k)

#define ROUND2(a, b, c, d, e, f, s, r, k) \
	RR(a ## 2, b ## 2, c ## 2, d ## 2, e ## 2, f, s, r, K2 ## k)

/* Input is raw Merkle Damgard */
inline void ripemd160(uint *W, uint *ctx)
{
	uint A1, B1, C1, D1, E1;
	uint A2, B2, C2, D2, E2;
	uint tmp;

	A1 = A2 = ctx[0];
	B1 = B2 = ctx[1];
	C1 = C2 = ctx[2];
	D1 = D2 = ctx[3];
	E1 = E2 = ctx[4];

	ROUND1(A, B, C, D, E, F1, 11, W[0], 1);
	ROUND1(E, A, B, C, D, F1, 14, W[1], 1);
	ROUND1(D, E, A, B, C, F1, 15, W[2], 1);
	ROUND1(C, D, E, A, B, F1, 12, W[3], 1);
	ROUND1(B, C, D, E, A, F1,  5, W[4], 1);
	ROUND1(A, B, C, D, E, F1,  8, W[5], 1);
	ROUND1(E, A, B, C, D, F1,  7, W[6], 1);
	ROUND1(D, E, A, B, C, F1,  9, W[7], 1);
	ROUND1(C, D, E, A, B, F1, 11, W[8], 1);
	ROUND1(B, C, D, E, A, F1, 13, W[9], 1);
	ROUND1(A, B, C, D, E, F1, 14, W[10], 1);
	ROUND1(E, A, B, C, D, F1, 15, W[11], 1);
	ROUND1(D, E, A, B, C, F1,  6, W[12], 1);
	ROUND1(C, D, E, A, B, F1,  7, W[13], 1);
	ROUND1(B, C, D, E, A, F1,  9, W[14], 1);
	ROUND1(A, B, C, D, E, F1,  8, W[15], 1);

	ROUND2(A, B, C, D, E, F5,  8, W[5], 1);
	ROUND2(E, A, B, C, D, F5,  9, W[14], 1);
	ROUND2(D, E, A, B, C, F5,  9, W[7], 1);
	ROUND2(C, D, E, A, B, F5, 11, W[0], 1);
	ROUND2(B, C, D, E, A, F5, 13, W[9], 1);
	ROUND2(A, B, C, D, E, F5, 15, W[2], 1);
	ROUND2(E, A, B, C, D, F5, 15, W[11], 1);
	ROUND2(D, E, A, B, C, F5,  5, W[4], 1);
	ROUND2(C, D, E, A, B, F5,  7, W[13], 1);
	ROUND2(B, C, D, E, A, F5,  7, W[6], 1);
	ROUND2(A, B, C, D, E, F5,  8, W[15], 1);
	ROUND2(E, A, B, C, D, F5, 11, W[8], 1);
	ROUND2(D, E, A, B, C, F5, 14, W[1], 1);
	ROUND2(C, D, E, A, B, F5, 14, W[10], 1);
	ROUND2(B, C, D, E, A, F5, 12, W[3], 1);
	ROUND2(A, B, C, D, E, F5,  6, W[12], 1);

	ROUND1(E, A, B, C, D, F2,  7, W[7], 2);
	ROUND1(D, E, A, B, C, F2,  6, W[4], 2);
	ROUND1(C, D, E, A, B, F2,  8, W[13], 2);
	ROUND1(B, C, D, E, A, F2, 13, W[1], 2);
	ROUND1(A, B, C, D, E, F2, 11, W[10], 2);
	ROUND1(E, A, B, C, D, F2,  9, W[6], 2);
	ROUND1(D, E, A, B, C, F2,  7, W[15], 2);
	ROUND1(C, D, E, A, B, F2, 15, W[3], 2);
	ROUND1(B, C, D, E, A, F2,  7, W[12], 2);
	ROUND1(A, B, C, D, E, F2, 12, W[0], 2);
	ROUND1(E, A, B, C, D, F2, 15, W[9], 2);
	ROUND1(D, E, A, B, C, F2,  9, W[5], 2);
	ROUND1(C, D, E, A, B, F2, 11, W[2], 2);
	ROUND1(B, C, D, E, A, F2,  7, W[14], 2);
	ROUND1(A, B, C, D, E, F2, 13, W[11], 2);
	ROUND1(E, A, B, C, D, F2, 12, W[8], 2);

	ROUND2(E, A, B, C, D, F4,  9, W[6], 2);
	ROUND2(D, E, A, B, C, F4, 13, W[11], 2);
	ROUND2(C, D, E, A, B, F4, 15, W[3], 2);
	ROUND2(B, C, D, E, A, F4,  7, W[7], 2);
	ROUND2(A, B, C, D, E, F4, 12, W[0], 2);
	ROUND2(E, A, B, C, D, F4,  8, W[13], 2);
	ROUND2(D, E, A, B, C, F4,  9, W[5], 2);
	ROUND2(C, D, E, A, B, F4, 11, W[10], 2);
	ROUND2(B, C, D, E, A, F4,  7, W[14], 2);
	ROUND2(A, B, C, D, E, F4,  7, W[15], 2);
	ROUND2(E, A, B, C, D, F4, 12, W[8], 2);
	ROUND2(D, E, A, B, C, F4,  7, W[12], 2);
	ROUND2(C, D, E, A, B, F4,  6, W[4], 2);
	ROUND2(B, C, D, E, A, F4, 15, W[9], 2);
	ROUND2(A, B, C, D, E, F4, 13, W[1], 2);
	ROUND2(E, A, B, C, D, F4, 11, W[2], 2);

	ROUND1(D, E, A, B, C, F3, 11, W[3], 3);
	ROUND1(C, D, E, A, B, F3, 13, W[10], 3);
	ROUND1(B, C, D, E, A, F3,  6, W[14], 3);
	ROUND1(A, B, C, D, E, F3,  7, W[4], 3);
	ROUND1(E, A, B, C, D, F3, 14, W[9], 3);
	ROUND1(D, E, A, B, C, F3,  9, W[15], 3);
	ROUND1(C, D, E, A, B, F3, 13, W[8], 3);
	ROUND1(B, C, D, E, A, F3, 15, W[1], 3);
	ROUND1(A, B, C, D, E, F3, 14, W[2], 3);
	ROUND1(E, A, B, C, D, F3,  8, W[7], 3);
	ROUND1(D, E, A, B, C, F3, 13, W[0], 3);
	ROUND1(C, D, E, A, B, F3,  6, W[6], 3);
	ROUND1(B, C, D, E, A, F3,  5, W[13], 3);
	ROUND1(A, B, C, D, E, F3, 12, W[11], 3);
	ROUND1(E, A, B, C, D, F3,  7, W[5], 3);
	ROUND1(D, E, A, B, C, F3,  5, W[12], 3);

	ROUND2(D, E, A, B, C, F3,  9, W[15], 3);
	ROUND2(C, D, E, A, B, F3,  7, W[5], 3);
	ROUND2(B, C, D, E, A, F3, 15, W[1], 3);
	ROUND2(A, B, C, D, E, F3, 11, W[3], 3);
	ROUND2(E, A, B, C, D, F3,  8, W[7], 3);
	ROUND2(D, E, A, B, C, F3,  6, W[14], 3);
	ROUND2(C, D, E, A, B, F3,  6, W[6], 3);
	ROUND2(B, C, D, E, A, F3, 14, W[9], 3);
	ROUND2(A, B, C, D, E, F3, 12, W[11], 3);
	ROUND2(E, A, B, C, D, F3, 13, W[8], 3);
	ROUND2(D, E, A, B, C, F3,  5, W[12], 3);
	ROUND2(C, D, E, A, B, F3, 14, W[2], 3);
	ROUND2(B, C, D, E, A, F3, 13, W[10], 3);
	ROUND2(A, B, C, D, E, F3, 13, W[0], 3);
	ROUND2(E, A, B, C, D, F3,  7, W[4], 3);
	ROUND2(D, E, A, B, C, F3,  5, W[13], 3);

	ROUND1(C, D, E, A, B, F4, 11, W[1], 4);
	ROUND1(B, C, D, E, A, F4, 12, W[9], 4);
	ROUND1(A, B, C, D, E, F4, 14, W[11], 4);
	ROUND1(E, A, B, C, D, F4, 15, W[10], 4);
	ROUND1(D, E, A, B, C, F4, 14, W[0], 4);
	ROUND1(C, D, E, A, B, F4, 15, W[8], 4);
	ROUND1(B, C, D, E, A, F4,  9, W[12], 4);
	ROUND1(A, B, C, D, E, F4,  8, W[4], 4);
	ROUND1(E, A, B, C, D, F4,  9, W[13], 4);
	ROUND1(D, E, A, B, C, F4, 14, W[3], 4);
	ROUND1(C, D, E, A, B, F4,  5, W[7], 4);
	ROUND1(B, C, D, E, A, F4,  6, W[15], 4);
	ROUND1(A, B, C, D, E, F4,  8, W[14], 4);
	ROUND1(E, A, B, C, D, F4,  6, W[5], 4);
	ROUND1(D, E, A, B, C, F4,  5, W[6], 4);
	ROUND1(C, D, E, A, B, F4, 12, W[2], 4);

	ROUND2(C, D, E, A, B, F2, 15, W[8], 4);
	ROUND2(B, C, D, E, A, F2,  5, W[6], 4);
	ROUND2(A, B, C, D, E, F2,  8, W[4], 4);
	ROUND2(E, A, B, C, D, F2, 11, W[1], 4);
	ROUND2(D, E, A, B, C, F2, 14, W[3], 4);
	ROUND2(C, D, E, A, B, F2, 14, W[11], 4);
	ROUND2(B, C, D, E, A, F2,  6, W[15], 4);
	ROUND2(A, B, C, D, E, F2, 14, W[0], 4);
	ROUND2(E, A, B, C, D, F2,  6, W[5], 4);
	ROUND2(D, E, A, B, C, F2,  9, W[12], 4);
	ROUND2(C, D, E, A, B, F2, 12, W[2], 4);
	ROUND2(B, C, D, E, A, F2,  9, W[13], 4);
	ROUND2(A, B, C, D, E, F2, 12, W[9], 4);
	ROUND2(E, A, B, C, D, F2,  5, W[7], 4);
	ROUND2(D, E, A, B, C, F2, 15, W[10], 4);
	ROUND2(C, D, E, A, B, F2,  8, W[14], 4);

	ROUND1(B, C, D, E, A, F5,  9, W[4], 5);
	ROUND1(A, B, C, D, E, F5, 15, W[0], 5);
	ROUND1(E, A, B, C, D, F5,  5, W[5], 5);
	ROUND1(D, E, A, B, C, F5, 11, W[9], 5);
	ROUND1(C, D, E, A, B, F5,  6, W[7], 5);
	ROUND1(B, C, D, E, A, F5,  8, W[12], 5);
	ROUND1(A, B, C, D, E, F5, 13, W[2], 5);
	ROUND1(E, A, B, C, D, F5, 12, W[10], 5);
	ROUND1(D, E, A, B, C, F5,  5, W[14], 5);
	ROUND1(C, D, E, A, B, F5, 12, W[1], 5);
	ROUND1(B, C, D, E, A, F5, 13, W[3], 5);
	ROUND1(A, B, C, D, E, F5, 14, W[8], 5);
	ROUND1(E, A, B, C, D, F5, 11, W[11], 5);
	ROUND1(D, E, A, B, C, F5,  8, W[6], 5);
	ROUND1(C, D, E, A, B, F5,  5, W[15], 5);
	ROUND1(B, C, D, E, A, F5,  6, W[13], 5);

	ROUND2(B, C, D, E, A, F1,  8, W[12], 5);
	ROUND2(A, B, C, D, E, F1,  5, W[15], 5);
	ROUND2(E, A, B, C, D, F1, 12, W[10], 5);
	ROUND2(D, E, A, B, C, F1,  9, W[4], 5);
	ROUND2(C, D, E, A, B, F1, 12, W[1], 5);
	ROUND2(B, C, D, E, A, F1,  5, W[5], 5);
	ROUND2(A, B, C, D, E, F1, 14, W[8], 5);
	ROUND2(E, A, B, C, D, F1,  6, W[7], 5);
	ROUND2(D, E, A, B, C, F1,  8, W[6], 5);
	ROUND2(C, D, E, A, B, F1, 13, W[2], 5);
	ROUND2(B, C, D, E, A, F1,  6, W[13], 5);
	ROUND2(A, B, C, D, E, F1,  5, W[14], 5);
	ROUND2(E, A, B, C, D, F1, 15, W[0], 5);
	ROUND2(D, E, A, B, C, F1, 13, W[3], 5);
	ROUND2(C, D, E, A, B, F1, 11, W[9], 5);
	ROUND2(B, C, D, E, A, F1, 11, W[11], 5);

	tmp = ctx[1] + C1 + D2;
	ctx[1] = ctx[2] + D1 + E2;
	ctx[2] = ctx[3] + E1 + A2;
	ctx[3] = ctx[4] + A1 + B2;
	ctx[4] = ctx[0] + B1 + C2;
	ctx[0] = tmp;
}

/* Input is last output; length is 160 bits */
inline void ripemd160_160Z(uint *W, uint *ctx)
{
	uint A1, B1, C1, D1, E1;
	uint A2, B2, C2, D2, E2;
	uint tmp;

	A1 = A2 = ctx[0];
	B1 = B2 = ctx[1];
	C1 = C2 = ctx[2];
	D1 = D2 = ctx[3];
	E1 = E2 = ctx[4];

	ROUND1(A, B, C, D, E, F1, 11, W[0], 1);
	ROUND1(E, A, B, C, D, F1, 14, W[1], 1);
	ROUND1(D, E, A, B, C, F1, 15, W[2], 1);
	ROUND1(C, D, E, A, B, F1, 12, W[3], 1);
	ROUND1(B, C, D, E, A, F1,  5, W[4], 1);
	ROUND1(A, B, C, D, E, F1,  8, 0x80, 1);
	ROUND1(E, A, B, C, D, F1,  7, 0, 1);
	ROUND1(D, E, A, B, C, F1,  9, 0, 1);
	ROUND1(C, D, E, A, B, F1, 11, 0, 1);
	ROUND1(B, C, D, E, A, F1, 13, 0, 1);
	ROUND1(A, B, C, D, E, F1, 14, 0, 1);
	ROUND1(E, A, B, C, D, F1, 15, 0, 1);
	ROUND1(D, E, A, B, C, F1,  6, 0, 1);
	ROUND1(C, D, E, A, B, F1,  7, 0, 1);
	ROUND1(B, C, D, E, A, F1,  9, 0x2a0, 1);
	ROUND1(A, B, C, D, E, F1,  8, 0, 1);

	ROUND2(A, B, C, D, E, F5,  8, 0x80, 1);
	ROUND2(E, A, B, C, D, F5,  9, 0x2a0, 1);
	ROUND2(D, E, A, B, C, F5,  9, 0, 1);
	ROUND2(C, D, E, A, B, F5, 11, W[0], 1);
	ROUND2(B, C, D, E, A, F5, 13, 0, 1);
	ROUND2(A, B, C, D, E, F5, 15, W[2], 1);
	ROUND2(E, A, B, C, D, F5, 15, 0, 1);
	ROUND2(D, E, A, B, C, F5,  5, W[4], 1);
	ROUND2(C, D, E, A, B, F5,  7, 0, 1);
	ROUND2(B, C, D, E, A, F5,  7, 0, 1);
	ROUND2(A, B, C, D, E, F5,  8, 0, 1);
	ROUND2(E, A, B, C, D, F5, 11, 0, 1);
	ROUND2(D, E, A, B, C, F5, 14, W[1], 1);
	ROUND2(C, D, E, A, B, F5, 14, 0, 1);
	ROUND2(B, C, D, E, A, F5, 12, W[3], 1);
	ROUND2(A, B, C, D, E, F5,  6, 0, 1);

	ROUND1(E, A, B, C, D, F2,  7, 0, 2);
	ROUND1(D, E, A, B, C, F2,  6, W[4], 2);
	ROUND1(C, D, E, A, B, F2,  8, 0, 2);
	ROUND1(B, C, D, E, A, F2, 13, W[1], 2);
	ROUND1(A, B, C, D, E, F2, 11, 0, 2);
	ROUND1(E, A, B, C, D, F2,  9, 0, 2);
	ROUND1(D, E, A, B, C, F2,  7, 0, 2);
	ROUND1(C, D, E, A, B, F2, 15, W[3], 2);
	ROUND1(B, C, D, E, A, F2,  7, 0, 2);
	ROUND1(A, B, C, D, E, F2, 12, W[0], 2);
	ROUND1(E, A, B, C, D, F2, 15, 0, 2);
	ROUND1(D, E, A, B, C, F2,  9, 0x80, 2);
	ROUND1(C, D, E, A, B, F2, 11, W[2], 2);
	ROUND1(B, C, D, E, A, F2,  7, 0x2a0, 2);
	ROUND1(A, B, C, D, E, F2, 13, 0, 2);
	ROUND1(E, A, B, C, D, F2, 12, 0, 2);

	ROUND2(E, A, B, C, D, F4,  9, 0, 2);
	ROUND2(D, E, A, B, C, F4, 13, 0, 2);
	ROUND2(C, D, E, A, B, F4, 15, W[3], 2);
	ROUND2(B, C, D, E, A, F4,  7, 0, 2);
	ROUND2(A, B, C, D, E, F4, 12, W[0], 2);
	ROUND2(E, A, B, C, D, F4,  8, 0, 2);
	ROUND2(D, E, A, B, C, F4,  9, 0x80, 2);
	ROUND2(C, D, E, A, B, F4, 11, 0, 2);
	ROUND2(B, C, D, E, A, F4,  7, 0x2a0, 2);
	ROUND2(A, B, C, D, E, F4,  7, 0, 2);
	ROUND2(E, A, B, C, D, F4, 12, 0, 2);
	ROUND2(D, E, A, B, C, F4,  7, 0, 2);
	ROUND2(C, D, E, A, B, F4,  6, W[4], 2);
	ROUND2(B, C, D, E, A, F4, 15, 0, 2);
	ROUND2(A, B, C, D, E, F4, 13, W[1], 2);
	ROUND2(E, A, B, C, D, F4, 11, W[2], 2);

	ROUND1(D, E, A, B, C, F3, 11, W[3], 3);
	ROUND1(C, D, E, A, B, F3, 13, 0, 3);
	ROUND1(B, C, D, E, A, F3,  6, 0x2a0, 3);
	ROUND1(A, B, C, D, E, F3,  7, W[4], 3);
	ROUND1(E, A, B, C, D, F3, 14, 0, 3);
	ROUND1(D, E, A, B, C, F3,  9, 0, 3);
	ROUND1(C, D, E, A, B, F3, 13, 0, 3);
	ROUND1(B, C, D, E, A, F3, 15, W[1], 3);
	ROUND1(A, B, C, D, E, F3, 14, W[2], 3);
	ROUND1(E, A, B, C, D, F3,  8, 0, 3);
	ROUND1(D, E, A, B, C, F3, 13, W[0], 3);
	ROUND1(C, D, E, A, B, F3,  6, 0, 3);
	ROUND1(B, C, D, E, A, F3,  5, 0, 3);
	ROUND1(A, B, C, D, E, F3, 12, 0, 3);
	ROUND1(E, A, B, C, D, F3,  7, 0x80, 3);
	ROUND1(D, E, A, B, C, F3,  5, 0, 3);

	ROUND2(D, E, A, B, C, F3,  9, 0, 3);
	ROUND2(C, D, E, A, B, F3,  7, 0x80, 3);
	ROUND2(B, C, D, E, A, F3, 15, W[1], 3);
	ROUND2(A, B, C, D, E, F3, 11, W[3], 3);
	ROUND2(E, A, B, C, D, F3,  8, 0, 3);
	ROUND2(D, E, A, B, C, F3,  6, 0x2a0, 3);
	ROUND2(C, D, E, A, B, F3,  6, 0, 3);
	ROUND2(B, C, D, E, A, F3, 14, 0, 3);
	ROUND2(A, B, C, D, E, F3, 12, 0, 3);
	ROUND2(E, A, B, C, D, F3, 13, 0, 3);
	ROUND2(D, E, A, B, C, F3,  5, 0, 3);
	ROUND2(C, D, E, A, B, F3, 14, W[2], 3);
	ROUND2(B, C, D, E, A, F3, 13, 0, 3);
	ROUND2(A, B, C, D, E, F3, 13, W[0], 3);
	ROUND2(E, A, B, C, D, F3,  7, W[4], 3);
	ROUND2(D, E, A, B, C, F3,  5, 0, 3);

	ROUND1(C, D, E, A, B, F4, 11, W[1], 4);
	ROUND1(B, C, D, E, A, F4, 12, 0, 4);
	ROUND1(A, B, C, D, E, F4, 14, 0, 4);
	ROUND1(E, A, B, C, D, F4, 15, 0, 4);
	ROUND1(D, E, A, B, C, F4, 14, W[0], 4);
	ROUND1(C, D, E, A, B, F4, 15, 0, 4);
	ROUND1(B, C, D, E, A, F4,  9, 0, 4);
	ROUND1(A, B, C, D, E, F4,  8, W[4], 4);
	ROUND1(E, A, B, C, D, F4,  9, 0, 4);
	ROUND1(D, E, A, B, C, F4, 14, W[3], 4);
	ROUND1(C, D, E, A, B, F4,  5, 0, 4);
	ROUND1(B, C, D, E, A, F4,  6, 0, 4);
	ROUND1(A, B, C, D, E, F4,  8, 0x2a0, 4);
	ROUND1(E, A, B, C, D, F4,  6, 0x80, 4);
	ROUND1(D, E, A, B, C, F4,  5, 0, 4);
	ROUND1(C, D, E, A, B, F4, 12, W[2], 4);

	ROUND2(C, D, E, A, B, F2, 15, 0, 4);
	ROUND2(B, C, D, E, A, F2,  5, 0, 4);
	ROUND2(A, B, C, D, E, F2,  8, W[4], 4);
	ROUND2(E, A, B, C, D, F2, 11, W[1], 4);
	ROUND2(D, E, A, B, C, F2, 14, W[3], 4);
	ROUND2(C, D, E, A, B, F2, 14, 0, 4);
	ROUND2(B, C, D, E, A, F2,  6, 0, 4);
	ROUND2(A, B, C, D, E, F2, 14, W[0], 4);
	ROUND2(E, A, B, C, D, F2,  6, 0x80, 4);
	ROUND2(D, E, A, B, C, F2,  9, 0, 4);
	ROUND2(C, D, E, A, B, F2, 12, W[2], 4);
	ROUND2(B, C, D, E, A, F2,  9, 0, 4);
	ROUND2(A, B, C, D, E, F2, 12, 0, 4);
	ROUND2(E, A, B, C, D, F2,  5, 0, 4);
	ROUND2(D, E, A, B, C, F2, 15, 0, 4);
	ROUND2(C, D, E, A, B, F2,  8, 0x2a0, 4);

	ROUND1(B, C, D, E, A, F5,  9, W[4], 5);
	ROUND1(A, B, C, D, E, F5, 15, W[0], 5);
	ROUND1(E, A, B, C, D, F5,  5, 0x80, 5);
	ROUND1(D, E, A, B, C, F5, 11, 0, 5);
	ROUND1(C, D, E, A, B, F5,  6, 0, 5);
	ROUND1(B, C, D, E, A, F5,  8, 0, 5);
	ROUND1(A, B, C, D, E, F5, 13, W[2], 5);
	ROUND1(E, A, B, C, D, F5, 12, 0, 5);
	ROUND1(D, E, A, B, C, F5,  5, 0x2a0, 5);
	ROUND1(C, D, E, A, B, F5, 12, W[1], 5);
	ROUND1(B, C, D, E, A, F5, 13, W[3], 5);
	ROUND1(A, B, C, D, E, F5, 14, 0, 5);
	ROUND1(E, A, B, C, D, F5, 11, 0, 5);
	ROUND1(D, E, A, B, C, F5,  8, 0, 5);
	ROUND1(C, D, E, A, B, F5,  5, 0, 5);
	ROUND1(B, C, D, E, A, F5,  6, 0, 5);

	ROUND2(B, C, D, E, A, F1,  8, 0, 5);
	ROUND2(A, B, C, D, E, F1,  5, 0, 5);
	ROUND2(E, A, B, C, D, F1, 12, 0, 5);
	ROUND2(D, E, A, B, C, F1,  9, W[4], 5);
	ROUND2(C, D, E, A, B, F1, 12, W[1], 5);
	ROUND2(B, C, D, E, A, F1,  5, 0x80, 5);
	ROUND2(A, B, C, D, E, F1, 14, 0, 5);
	ROUND2(E, A, B, C, D, F1,  6, 0, 5);
	ROUND2(D, E, A, B, C, F1,  8, 0, 5);
	ROUND2(C, D, E, A, B, F1, 13, W[2], 5);
	ROUND2(B, C, D, E, A, F1,  6, 0, 5);
	ROUND2(A, B, C, D, E, F1,  5, 0x2a0, 5);
	ROUND2(E, A, B, C, D, F1, 15, W[0], 5);
	ROUND2(D, E, A, B, C, F1, 13, W[3], 5);
	ROUND2(C, D, E, A, B, F1, 11, 0, 5);
	ROUND2(B, C, D, E, A, F1, 11, 0, 5);

	tmp = ctx[1] + C1 + D2;
	ctx[1] = ctx[2] + D1 + E2;
	ctx[2] = ctx[3] + E1 + A2;
	ctx[3] = ctx[4] + A1 + B2;
	ctx[4] = ctx[0] + B1 + C2;
	ctx[0] = tmp;
}

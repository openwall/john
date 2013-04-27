/* $Id: ripemd.c 216 2010-06-08 09:46:57Z tp $ */
/*
 * RIPEMD-160 implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>

#include "sph_ripemd.h"

/*
 * Round functions for RIPEMD (original).
 */
#define F(x, y, z)    ((((y) ^ (z)) & (x)) ^ (z))
#define G(x, y, z)    (((x) & (y)) | (((x) | (y)) & (z)))
#define H(x, y, z)    ((x) ^ (y) ^ (z))

static const sph_u32 oIV[5] = {
	SPH_C32(0x67452301), SPH_C32(0xEFCDAB89),
	SPH_C32(0x98BADCFE), SPH_C32(0x10325476)
};

/*
 * Round functions for RIPEMD-128 and RIPEMD-160.
 */
#define F1(x, y, z)   ((x) ^ (y) ^ (z))
#define F2(x, y, z)   ((((y) ^ (z)) & (x)) ^ (z))
#define F3(x, y, z)   (((x) | ~(y)) ^ (z))
#define F4(x, y, z)   ((((x) ^ (y)) & (z)) ^ (y))
#define F5(x, y, z)   ((x) ^ ((y) | ~(z)))

static const sph_u32 IV[5] = {
	SPH_C32(0x67452301), SPH_C32(0xEFCDAB89), SPH_C32(0x98BADCFE),
	SPH_C32(0x10325476), SPH_C32(0xC3D2E1F0)
};

#define ROTL    SPH_ROTL32

/* ===================================================================== */
/*
 * RIPEMD (original hash, deprecated).
 */

#define FF1(A, B, C, D, X, s)   do { \
		sph_u32 tmp = SPH_T32((A) + F(B, C, D) + (X)); \
		(A) = ROTL(tmp, (s)); \
	} while (0)

#define GG1(A, B, C, D, X, s)   do { \
		sph_u32 tmp = SPH_T32((A) + G(B, C, D) \
			+ (X) + SPH_C32(0x5A827999)); \
		(A) = ROTL(tmp, (s)); \
	} while (0)

#define HH1(A, B, C, D, X, s)   do { \
		sph_u32 tmp = SPH_T32((A) + H(B, C, D) \
			+ (X) + SPH_C32(0x6ED9EBA1)); \
		(A) = ROTL(tmp, (s)); \
	} while (0)

#define FF2(A, B, C, D, X, s)   do { \
		sph_u32 tmp = SPH_T32((A) + F(B, C, D) \
			+ (X) + SPH_C32(0x50A28BE6)); \
		(A) = ROTL(tmp, (s)); \
	} while (0)

#define GG2(A, B, C, D, X, s)   do { \
		sph_u32 tmp = SPH_T32((A) + G(B, C, D) + (X)); \
		(A) = ROTL(tmp, (s)); \
	} while (0)

#define HH2(A, B, C, D, X, s)   do { \
		sph_u32 tmp = SPH_T32((A) + H(B, C, D) \
			+ (X) + SPH_C32(0x5C4DD124)); \
		(A) = ROTL(tmp, (s)); \
	} while (0)

#define RIPEMD_ROUND_BODY(in, h)   do { \
		sph_u32 A1, B1, C1, D1; \
		sph_u32 A2, B2, C2, D2; \
		sph_u32 tmp; \
 \
		A1 = A2 = (h)[0]; \
		B1 = B2 = (h)[1]; \
		C1 = C2 = (h)[2]; \
		D1 = D2 = (h)[3]; \
 \
		FF1(A1, B1, C1, D1, in( 0), 11); \
		FF1(D1, A1, B1, C1, in( 1), 14); \
		FF1(C1, D1, A1, B1, in( 2), 15); \
		FF1(B1, C1, D1, A1, in( 3), 12); \
		FF1(A1, B1, C1, D1, in( 4),  5); \
		FF1(D1, A1, B1, C1, in( 5),  8); \
		FF1(C1, D1, A1, B1, in( 6),  7); \
		FF1(B1, C1, D1, A1, in( 7),  9); \
		FF1(A1, B1, C1, D1, in( 8), 11); \
		FF1(D1, A1, B1, C1, in( 9), 13); \
		FF1(C1, D1, A1, B1, in(10), 14); \
		FF1(B1, C1, D1, A1, in(11), 15); \
		FF1(A1, B1, C1, D1, in(12),  6); \
		FF1(D1, A1, B1, C1, in(13),  7); \
		FF1(C1, D1, A1, B1, in(14),  9); \
		FF1(B1, C1, D1, A1, in(15),  8); \
 \
		GG1(A1, B1, C1, D1, in( 7),  7); \
		GG1(D1, A1, B1, C1, in( 4),  6); \
		GG1(C1, D1, A1, B1, in(13),  8); \
		GG1(B1, C1, D1, A1, in( 1), 13); \
		GG1(A1, B1, C1, D1, in(10), 11); \
		GG1(D1, A1, B1, C1, in( 6),  9); \
		GG1(C1, D1, A1, B1, in(15),  7); \
		GG1(B1, C1, D1, A1, in( 3), 15); \
		GG1(A1, B1, C1, D1, in(12),  7); \
		GG1(D1, A1, B1, C1, in( 0), 12); \
		GG1(C1, D1, A1, B1, in( 9), 15); \
		GG1(B1, C1, D1, A1, in( 5),  9); \
		GG1(A1, B1, C1, D1, in(14),  7); \
		GG1(D1, A1, B1, C1, in( 2), 11); \
		GG1(C1, D1, A1, B1, in(11), 13); \
		GG1(B1, C1, D1, A1, in( 8), 12); \
 \
		HH1(A1, B1, C1, D1, in( 3), 11); \
		HH1(D1, A1, B1, C1, in(10), 13); \
		HH1(C1, D1, A1, B1, in( 2), 14); \
		HH1(B1, C1, D1, A1, in( 4),  7); \
		HH1(A1, B1, C1, D1, in( 9), 14); \
		HH1(D1, A1, B1, C1, in(15),  9); \
		HH1(C1, D1, A1, B1, in( 8), 13); \
		HH1(B1, C1, D1, A1, in( 1), 15); \
		HH1(A1, B1, C1, D1, in(14),  6); \
		HH1(D1, A1, B1, C1, in( 7),  8); \
		HH1(C1, D1, A1, B1, in( 0), 13); \
		HH1(B1, C1, D1, A1, in( 6),  6); \
		HH1(A1, B1, C1, D1, in(11), 12); \
		HH1(D1, A1, B1, C1, in(13),  5); \
		HH1(C1, D1, A1, B1, in( 5),  7); \
		HH1(B1, C1, D1, A1, in(12),  5); \
 \
		FF2(A2, B2, C2, D2, in( 0), 11); \
		FF2(D2, A2, B2, C2, in( 1), 14); \
		FF2(C2, D2, A2, B2, in( 2), 15); \
		FF2(B2, C2, D2, A2, in( 3), 12); \
		FF2(A2, B2, C2, D2, in( 4),  5); \
		FF2(D2, A2, B2, C2, in( 5),  8); \
		FF2(C2, D2, A2, B2, in( 6),  7); \
		FF2(B2, C2, D2, A2, in( 7),  9); \
		FF2(A2, B2, C2, D2, in( 8), 11); \
		FF2(D2, A2, B2, C2, in( 9), 13); \
		FF2(C2, D2, A2, B2, in(10), 14); \
		FF2(B2, C2, D2, A2, in(11), 15); \
		FF2(A2, B2, C2, D2, in(12),  6); \
		FF2(D2, A2, B2, C2, in(13),  7); \
		FF2(C2, D2, A2, B2, in(14),  9); \
		FF2(B2, C2, D2, A2, in(15),  8); \
 \
		GG2(A2, B2, C2, D2, in( 7),  7); \
		GG2(D2, A2, B2, C2, in( 4),  6); \
		GG2(C2, D2, A2, B2, in(13),  8); \
		GG2(B2, C2, D2, A2, in( 1), 13); \
		GG2(A2, B2, C2, D2, in(10), 11); \
		GG2(D2, A2, B2, C2, in( 6),  9); \
		GG2(C2, D2, A2, B2, in(15),  7); \
		GG2(B2, C2, D2, A2, in( 3), 15); \
		GG2(A2, B2, C2, D2, in(12),  7); \
		GG2(D2, A2, B2, C2, in( 0), 12); \
		GG2(C2, D2, A2, B2, in( 9), 15); \
		GG2(B2, C2, D2, A2, in( 5),  9); \
		GG2(A2, B2, C2, D2, in(14),  7); \
		GG2(D2, A2, B2, C2, in( 2), 11); \
		GG2(C2, D2, A2, B2, in(11), 13); \
		GG2(B2, C2, D2, A2, in( 8), 12); \
 \
		HH2(A2, B2, C2, D2, in( 3), 11); \
		HH2(D2, A2, B2, C2, in(10), 13); \
		HH2(C2, D2, A2, B2, in( 2), 14); \
		HH2(B2, C2, D2, A2, in( 4),  7); \
		HH2(A2, B2, C2, D2, in( 9), 14); \
		HH2(D2, A2, B2, C2, in(15),  9); \
		HH2(C2, D2, A2, B2, in( 8), 13); \
		HH2(B2, C2, D2, A2, in( 1), 15); \
		HH2(A2, B2, C2, D2, in(14),  6); \
		HH2(D2, A2, B2, C2, in( 7),  8); \
		HH2(C2, D2, A2, B2, in( 0), 13); \
		HH2(B2, C2, D2, A2, in( 6),  6); \
		HH2(A2, B2, C2, D2, in(11), 12); \
		HH2(D2, A2, B2, C2, in(13),  5); \
		HH2(C2, D2, A2, B2, in( 5),  7); \
		HH2(B2, C2, D2, A2, in(12),  5); \
 \
		tmp = SPH_T32((h)[1] + C1 + D2); \
		(h)[1] = SPH_T32((h)[2] + D1 + A2); \
		(h)[2] = SPH_T32((h)[3] + A1 + B2); \
		(h)[3] = SPH_T32((h)[0] + B1 + C2); \
		(h)[0] = tmp; \
	} while (0)

/*
 * One round of RIPEMD. The data must be aligned for 32-bit access.
 */
static void
ripemd_round(const unsigned char *data, sph_u32 r[5])
{
#if SPH_LITTLE_FAST

#define RIPEMD_IN(x)   sph_dec32le_aligned(data + (4 * (x)))

#else

	sph_u32 X_var[16];
	int i;

	for (i = 0; i < 16; i ++)
		X_var[i] = sph_dec32le_aligned(data + 4 * i);
#define RIPEMD_IN(x)   X_var[x]

#endif
	RIPEMD_ROUND_BODY(RIPEMD_IN, r);
#undef RIPEMD_IN
}

/* see sph_ripemd.h */
void
sph_ripemd_init(void *cc)
{
	sph_ripemd_context *sc;

	sc = cc;
	memcpy(sc->val, oIV, sizeof sc->val);
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = sc->count_low = 0;
#endif
}

#define RFUN   ripemd_round
#define HASH   ripemd
#define LE32   1
#include "md_helper.c"
#undef RFUN
#undef HASH
#undef LE32

/* see sph_ripemd.h */
void
sph_ripemd_close(void *cc, void *dst)
{
	ripemd_close(cc, dst, 4);
	sph_ripemd_init(cc);
}

/* see sph_ripemd.h */
void
sph_ripemd_comp(const sph_u32 msg[16], sph_u32 val[4])
{
#define RIPEMD_IN(x)   msg[x]
	RIPEMD_ROUND_BODY(RIPEMD_IN, val);
#undef RIPEMD_IN
}

/* ===================================================================== */
/*
 * RIPEMD-128.
 */

/*
 * Round constants for RIPEMD-128.
 */
#define sK11   SPH_C32(0x00000000)
#define sK12   SPH_C32(0x5A827999)
#define sK13   SPH_C32(0x6ED9EBA1)
#define sK14   SPH_C32(0x8F1BBCDC)

#define sK21   SPH_C32(0x50A28BE6)
#define sK22   SPH_C32(0x5C4DD124)
#define sK23   SPH_C32(0x6D703EF3)
#define sK24   SPH_C32(0x00000000)

#define sRR(a, b, c, d, f, s, r, k)   do { \
		a = ROTL(SPH_T32(a + f(b, c, d) + r + k), s); \
	} while (0)

#define sROUND1(a, b, c, d, f, s, r, k)  \
	sRR(a ## 1, b ## 1, c ## 1, d ## 1, f, s, r, sK1 ## k)

#define sROUND2(a, b, c, d, f, s, r, k)  \
	sRR(a ## 2, b ## 2, c ## 2, d ## 2, f, s, r, sK2 ## k)

/*
 * This macro defines the body for a RIPEMD-128 compression function
 * implementation. The "in" parameter should evaluate, when applied to a
 * numerical input parameter from 0 to 15, to an expression which yields
 * the corresponding input block. The "h" parameter should evaluate to
 * an array or pointer expression designating the array of 4 words which
 * contains the input and output of the compression function.
 */

#define RIPEMD128_ROUND_BODY(in, h)   do { \
		sph_u32 A1, B1, C1, D1; \
		sph_u32 A2, B2, C2, D2; \
		sph_u32 tmp; \
 \
		A1 = A2 = (h)[0]; \
		B1 = B2 = (h)[1]; \
		C1 = C2 = (h)[2]; \
		D1 = D2 = (h)[3]; \
 \
		sROUND1(A, B, C, D, F1, 11, in( 0),  1); \
		sROUND1(D, A, B, C, F1, 14, in( 1),  1); \
		sROUND1(C, D, A, B, F1, 15, in( 2),  1); \
		sROUND1(B, C, D, A, F1, 12, in( 3),  1); \
		sROUND1(A, B, C, D, F1,  5, in( 4),  1); \
		sROUND1(D, A, B, C, F1,  8, in( 5),  1); \
		sROUND1(C, D, A, B, F1,  7, in( 6),  1); \
		sROUND1(B, C, D, A, F1,  9, in( 7),  1); \
		sROUND1(A, B, C, D, F1, 11, in( 8),  1); \
		sROUND1(D, A, B, C, F1, 13, in( 9),  1); \
		sROUND1(C, D, A, B, F1, 14, in(10),  1); \
		sROUND1(B, C, D, A, F1, 15, in(11),  1); \
		sROUND1(A, B, C, D, F1,  6, in(12),  1); \
		sROUND1(D, A, B, C, F1,  7, in(13),  1); \
		sROUND1(C, D, A, B, F1,  9, in(14),  1); \
		sROUND1(B, C, D, A, F1,  8, in(15),  1); \
 \
		sROUND1(A, B, C, D, F2,  7, in( 7),  2); \
		sROUND1(D, A, B, C, F2,  6, in( 4),  2); \
		sROUND1(C, D, A, B, F2,  8, in(13),  2); \
		sROUND1(B, C, D, A, F2, 13, in( 1),  2); \
		sROUND1(A, B, C, D, F2, 11, in(10),  2); \
		sROUND1(D, A, B, C, F2,  9, in( 6),  2); \
		sROUND1(C, D, A, B, F2,  7, in(15),  2); \
		sROUND1(B, C, D, A, F2, 15, in( 3),  2); \
		sROUND1(A, B, C, D, F2,  7, in(12),  2); \
		sROUND1(D, A, B, C, F2, 12, in( 0),  2); \
		sROUND1(C, D, A, B, F2, 15, in( 9),  2); \
		sROUND1(B, C, D, A, F2,  9, in( 5),  2); \
		sROUND1(A, B, C, D, F2, 11, in( 2),  2); \
		sROUND1(D, A, B, C, F2,  7, in(14),  2); \
		sROUND1(C, D, A, B, F2, 13, in(11),  2); \
		sROUND1(B, C, D, A, F2, 12, in( 8),  2); \
 \
		sROUND1(A, B, C, D, F3, 11, in( 3),  3); \
		sROUND1(D, A, B, C, F3, 13, in(10),  3); \
		sROUND1(C, D, A, B, F3,  6, in(14),  3); \
		sROUND1(B, C, D, A, F3,  7, in( 4),  3); \
		sROUND1(A, B, C, D, F3, 14, in( 9),  3); \
		sROUND1(D, A, B, C, F3,  9, in(15),  3); \
		sROUND1(C, D, A, B, F3, 13, in( 8),  3); \
		sROUND1(B, C, D, A, F3, 15, in( 1),  3); \
		sROUND1(A, B, C, D, F3, 14, in( 2),  3); \
		sROUND1(D, A, B, C, F3,  8, in( 7),  3); \
		sROUND1(C, D, A, B, F3, 13, in( 0),  3); \
		sROUND1(B, C, D, A, F3,  6, in( 6),  3); \
		sROUND1(A, B, C, D, F3,  5, in(13),  3); \
		sROUND1(D, A, B, C, F3, 12, in(11),  3); \
		sROUND1(C, D, A, B, F3,  7, in( 5),  3); \
		sROUND1(B, C, D, A, F3,  5, in(12),  3); \
 \
		sROUND1(A, B, C, D, F4, 11, in( 1),  4); \
		sROUND1(D, A, B, C, F4, 12, in( 9),  4); \
		sROUND1(C, D, A, B, F4, 14, in(11),  4); \
		sROUND1(B, C, D, A, F4, 15, in(10),  4); \
		sROUND1(A, B, C, D, F4, 14, in( 0),  4); \
		sROUND1(D, A, B, C, F4, 15, in( 8),  4); \
		sROUND1(C, D, A, B, F4,  9, in(12),  4); \
		sROUND1(B, C, D, A, F4,  8, in( 4),  4); \
		sROUND1(A, B, C, D, F4,  9, in(13),  4); \
		sROUND1(D, A, B, C, F4, 14, in( 3),  4); \
		sROUND1(C, D, A, B, F4,  5, in( 7),  4); \
		sROUND1(B, C, D, A, F4,  6, in(15),  4); \
		sROUND1(A, B, C, D, F4,  8, in(14),  4); \
		sROUND1(D, A, B, C, F4,  6, in( 5),  4); \
		sROUND1(C, D, A, B, F4,  5, in( 6),  4); \
		sROUND1(B, C, D, A, F4, 12, in( 2),  4); \
 \
		sROUND2(A, B, C, D, F4,  8, in( 5),  1); \
		sROUND2(D, A, B, C, F4,  9, in(14),  1); \
		sROUND2(C, D, A, B, F4,  9, in( 7),  1); \
		sROUND2(B, C, D, A, F4, 11, in( 0),  1); \
		sROUND2(A, B, C, D, F4, 13, in( 9),  1); \
		sROUND2(D, A, B, C, F4, 15, in( 2),  1); \
		sROUND2(C, D, A, B, F4, 15, in(11),  1); \
		sROUND2(B, C, D, A, F4,  5, in( 4),  1); \
		sROUND2(A, B, C, D, F4,  7, in(13),  1); \
		sROUND2(D, A, B, C, F4,  7, in( 6),  1); \
		sROUND2(C, D, A, B, F4,  8, in(15),  1); \
		sROUND2(B, C, D, A, F4, 11, in( 8),  1); \
		sROUND2(A, B, C, D, F4, 14, in( 1),  1); \
		sROUND2(D, A, B, C, F4, 14, in(10),  1); \
		sROUND2(C, D, A, B, F4, 12, in( 3),  1); \
		sROUND2(B, C, D, A, F4,  6, in(12),  1); \
 \
		sROUND2(A, B, C, D, F3,  9, in( 6),  2); \
		sROUND2(D, A, B, C, F3, 13, in(11),  2); \
		sROUND2(C, D, A, B, F3, 15, in( 3),  2); \
		sROUND2(B, C, D, A, F3,  7, in( 7),  2); \
		sROUND2(A, B, C, D, F3, 12, in( 0),  2); \
		sROUND2(D, A, B, C, F3,  8, in(13),  2); \
		sROUND2(C, D, A, B, F3,  9, in( 5),  2); \
		sROUND2(B, C, D, A, F3, 11, in(10),  2); \
		sROUND2(A, B, C, D, F3,  7, in(14),  2); \
		sROUND2(D, A, B, C, F3,  7, in(15),  2); \
		sROUND2(C, D, A, B, F3, 12, in( 8),  2); \
		sROUND2(B, C, D, A, F3,  7, in(12),  2); \
		sROUND2(A, B, C, D, F3,  6, in( 4),  2); \
		sROUND2(D, A, B, C, F3, 15, in( 9),  2); \
		sROUND2(C, D, A, B, F3, 13, in( 1),  2); \
		sROUND2(B, C, D, A, F3, 11, in( 2),  2); \
 \
		sROUND2(A, B, C, D, F2,  9, in(15),  3); \
		sROUND2(D, A, B, C, F2,  7, in( 5),  3); \
		sROUND2(C, D, A, B, F2, 15, in( 1),  3); \
		sROUND2(B, C, D, A, F2, 11, in( 3),  3); \
		sROUND2(A, B, C, D, F2,  8, in( 7),  3); \
		sROUND2(D, A, B, C, F2,  6, in(14),  3); \
		sROUND2(C, D, A, B, F2,  6, in( 6),  3); \
		sROUND2(B, C, D, A, F2, 14, in( 9),  3); \
		sROUND2(A, B, C, D, F2, 12, in(11),  3); \
		sROUND2(D, A, B, C, F2, 13, in( 8),  3); \
		sROUND2(C, D, A, B, F2,  5, in(12),  3); \
		sROUND2(B, C, D, A, F2, 14, in( 2),  3); \
		sROUND2(A, B, C, D, F2, 13, in(10),  3); \
		sROUND2(D, A, B, C, F2, 13, in( 0),  3); \
		sROUND2(C, D, A, B, F2,  7, in( 4),  3); \
		sROUND2(B, C, D, A, F2,  5, in(13),  3); \
 \
		sROUND2(A, B, C, D, F1, 15, in( 8),  4); \
		sROUND2(D, A, B, C, F1,  5, in( 6),  4); \
		sROUND2(C, D, A, B, F1,  8, in( 4),  4); \
		sROUND2(B, C, D, A, F1, 11, in( 1),  4); \
		sROUND2(A, B, C, D, F1, 14, in( 3),  4); \
		sROUND2(D, A, B, C, F1, 14, in(11),  4); \
		sROUND2(C, D, A, B, F1,  6, in(15),  4); \
		sROUND2(B, C, D, A, F1, 14, in( 0),  4); \
		sROUND2(A, B, C, D, F1,  6, in( 5),  4); \
		sROUND2(D, A, B, C, F1,  9, in(12),  4); \
		sROUND2(C, D, A, B, F1, 12, in( 2),  4); \
		sROUND2(B, C, D, A, F1,  9, in(13),  4); \
		sROUND2(A, B, C, D, F1, 12, in( 9),  4); \
		sROUND2(D, A, B, C, F1,  5, in( 7),  4); \
		sROUND2(C, D, A, B, F1, 15, in(10),  4); \
		sROUND2(B, C, D, A, F1,  8, in(14),  4); \
 \
		tmp = SPH_T32((h)[1] + C1 + D2); \
		(h)[1] = SPH_T32((h)[2] + D1 + A2); \
		(h)[2] = SPH_T32((h)[3] + A1 + B2); \
		(h)[3] = SPH_T32((h)[0] + B1 + C2); \
		(h)[0] = tmp; \
	} while (0)

/*
 * One round of RIPEMD-128. The data must be aligned for 32-bit access.
 */
static void
ripemd128_round(const unsigned char *data, sph_u32 r[5])
{
#if SPH_LITTLE_FAST

#define RIPEMD128_IN(x)   sph_dec32le_aligned(data + (4 * (x)))

#else

	sph_u32 X_var[16];
	int i;

	for (i = 0; i < 16; i ++)
		X_var[i] = sph_dec32le_aligned(data + 4 * i);
#define RIPEMD128_IN(x)   X_var[x]

#endif
	RIPEMD128_ROUND_BODY(RIPEMD128_IN, r);
#undef RIPEMD128_IN
}

/* see sph_ripemd.h */
void
sph_ripemd128_init(void *cc)
{
	sph_ripemd128_context *sc;

	sc = cc;
	memcpy(sc->val, IV, sizeof sc->val);
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = sc->count_low = 0;
#endif
}

#define RFUN   ripemd128_round
#define HASH   ripemd128
#define LE32   1
#include "md_helper.c"
#undef RFUN
#undef HASH
#undef LE32

/* see sph_ripemd.h */
void
sph_ripemd128_close(void *cc, void *dst)
{
	ripemd128_close(cc, dst, 4);
	sph_ripemd128_init(cc);
}

/* see sph_ripemd.h */
void
sph_ripemd128_comp(const sph_u32 msg[16], sph_u32 val[4])
{
#define RIPEMD128_IN(x)   msg[x]
	RIPEMD128_ROUND_BODY(RIPEMD128_IN, val);
#undef RIPEMD128_IN
}

/* ===================================================================== */
/*
 * RIPEMD-160.
 */

/*
 * Round constants for RIPEMD-160.
 */
#define K11    SPH_C32(0x00000000)
#define K12    SPH_C32(0x5A827999)
#define K13    SPH_C32(0x6ED9EBA1)
#define K14    SPH_C32(0x8F1BBCDC)
#define K15    SPH_C32(0xA953FD4E)

#define K21    SPH_C32(0x50A28BE6)
#define K22    SPH_C32(0x5C4DD124)
#define K23    SPH_C32(0x6D703EF3)
#define K24    SPH_C32(0x7A6D76E9)
#define K25    SPH_C32(0x00000000)

#define RR(a, b, c, d, e, f, s, r, k)   do { \
		a = SPH_T32(ROTL(SPH_T32(a + f(b, c, d) + r + k), s) + e); \
		c = ROTL(c, 10); \
	} while (0)

#define ROUND1(a, b, c, d, e, f, s, r, k)  \
	RR(a ## 1, b ## 1, c ## 1, d ## 1, e ## 1, f, s, r, K1 ## k)

#define ROUND2(a, b, c, d, e, f, s, r, k)  \
	RR(a ## 2, b ## 2, c ## 2, d ## 2, e ## 2, f, s, r, K2 ## k)

/*
 * This macro defines the body for a RIPEMD-160 compression function
 * implementation. The "in" parameter should evaluate, when applied to a
 * numerical input parameter from 0 to 15, to an expression which yields
 * the corresponding input block. The "h" parameter should evaluate to
 * an array or pointer expression designating the array of 5 words which
 * contains the input and output of the compression function.
 */

#define RIPEMD160_ROUND_BODY(in, h)   do { \
		sph_u32 A1, B1, C1, D1, E1; \
		sph_u32 A2, B2, C2, D2, E2; \
		sph_u32 tmp; \
 \
		A1 = A2 = (h)[0]; \
		B1 = B2 = (h)[1]; \
		C1 = C2 = (h)[2]; \
		D1 = D2 = (h)[3]; \
		E1 = E2 = (h)[4]; \
 \
		ROUND1(A, B, C, D, E, F1, 11, in( 0),  1); \
		ROUND1(E, A, B, C, D, F1, 14, in( 1),  1); \
		ROUND1(D, E, A, B, C, F1, 15, in( 2),  1); \
		ROUND1(C, D, E, A, B, F1, 12, in( 3),  1); \
		ROUND1(B, C, D, E, A, F1,  5, in( 4),  1); \
		ROUND1(A, B, C, D, E, F1,  8, in( 5),  1); \
		ROUND1(E, A, B, C, D, F1,  7, in( 6),  1); \
		ROUND1(D, E, A, B, C, F1,  9, in( 7),  1); \
		ROUND1(C, D, E, A, B, F1, 11, in( 8),  1); \
		ROUND1(B, C, D, E, A, F1, 13, in( 9),  1); \
		ROUND1(A, B, C, D, E, F1, 14, in(10),  1); \
		ROUND1(E, A, B, C, D, F1, 15, in(11),  1); \
		ROUND1(D, E, A, B, C, F1,  6, in(12),  1); \
		ROUND1(C, D, E, A, B, F1,  7, in(13),  1); \
		ROUND1(B, C, D, E, A, F1,  9, in(14),  1); \
		ROUND1(A, B, C, D, E, F1,  8, in(15),  1); \
 \
		ROUND1(E, A, B, C, D, F2,  7, in( 7),  2); \
		ROUND1(D, E, A, B, C, F2,  6, in( 4),  2); \
		ROUND1(C, D, E, A, B, F2,  8, in(13),  2); \
		ROUND1(B, C, D, E, A, F2, 13, in( 1),  2); \
		ROUND1(A, B, C, D, E, F2, 11, in(10),  2); \
		ROUND1(E, A, B, C, D, F2,  9, in( 6),  2); \
		ROUND1(D, E, A, B, C, F2,  7, in(15),  2); \
		ROUND1(C, D, E, A, B, F2, 15, in( 3),  2); \
		ROUND1(B, C, D, E, A, F2,  7, in(12),  2); \
		ROUND1(A, B, C, D, E, F2, 12, in( 0),  2); \
		ROUND1(E, A, B, C, D, F2, 15, in( 9),  2); \
		ROUND1(D, E, A, B, C, F2,  9, in( 5),  2); \
		ROUND1(C, D, E, A, B, F2, 11, in( 2),  2); \
		ROUND1(B, C, D, E, A, F2,  7, in(14),  2); \
		ROUND1(A, B, C, D, E, F2, 13, in(11),  2); \
		ROUND1(E, A, B, C, D, F2, 12, in( 8),  2); \
 \
		ROUND1(D, E, A, B, C, F3, 11, in( 3),  3); \
		ROUND1(C, D, E, A, B, F3, 13, in(10),  3); \
		ROUND1(B, C, D, E, A, F3,  6, in(14),  3); \
		ROUND1(A, B, C, D, E, F3,  7, in( 4),  3); \
		ROUND1(E, A, B, C, D, F3, 14, in( 9),  3); \
		ROUND1(D, E, A, B, C, F3,  9, in(15),  3); \
		ROUND1(C, D, E, A, B, F3, 13, in( 8),  3); \
		ROUND1(B, C, D, E, A, F3, 15, in( 1),  3); \
		ROUND1(A, B, C, D, E, F3, 14, in( 2),  3); \
		ROUND1(E, A, B, C, D, F3,  8, in( 7),  3); \
		ROUND1(D, E, A, B, C, F3, 13, in( 0),  3); \
		ROUND1(C, D, E, A, B, F3,  6, in( 6),  3); \
		ROUND1(B, C, D, E, A, F3,  5, in(13),  3); \
		ROUND1(A, B, C, D, E, F3, 12, in(11),  3); \
		ROUND1(E, A, B, C, D, F3,  7, in( 5),  3); \
		ROUND1(D, E, A, B, C, F3,  5, in(12),  3); \
 \
		ROUND1(C, D, E, A, B, F4, 11, in( 1),  4); \
		ROUND1(B, C, D, E, A, F4, 12, in( 9),  4); \
		ROUND1(A, B, C, D, E, F4, 14, in(11),  4); \
		ROUND1(E, A, B, C, D, F4, 15, in(10),  4); \
		ROUND1(D, E, A, B, C, F4, 14, in( 0),  4); \
		ROUND1(C, D, E, A, B, F4, 15, in( 8),  4); \
		ROUND1(B, C, D, E, A, F4,  9, in(12),  4); \
		ROUND1(A, B, C, D, E, F4,  8, in( 4),  4); \
		ROUND1(E, A, B, C, D, F4,  9, in(13),  4); \
		ROUND1(D, E, A, B, C, F4, 14, in( 3),  4); \
		ROUND1(C, D, E, A, B, F4,  5, in( 7),  4); \
		ROUND1(B, C, D, E, A, F4,  6, in(15),  4); \
		ROUND1(A, B, C, D, E, F4,  8, in(14),  4); \
		ROUND1(E, A, B, C, D, F4,  6, in( 5),  4); \
		ROUND1(D, E, A, B, C, F4,  5, in( 6),  4); \
		ROUND1(C, D, E, A, B, F4, 12, in( 2),  4); \
 \
		ROUND1(B, C, D, E, A, F5,  9, in( 4),  5); \
		ROUND1(A, B, C, D, E, F5, 15, in( 0),  5); \
		ROUND1(E, A, B, C, D, F5,  5, in( 5),  5); \
		ROUND1(D, E, A, B, C, F5, 11, in( 9),  5); \
		ROUND1(C, D, E, A, B, F5,  6, in( 7),  5); \
		ROUND1(B, C, D, E, A, F5,  8, in(12),  5); \
		ROUND1(A, B, C, D, E, F5, 13, in( 2),  5); \
		ROUND1(E, A, B, C, D, F5, 12, in(10),  5); \
		ROUND1(D, E, A, B, C, F5,  5, in(14),  5); \
		ROUND1(C, D, E, A, B, F5, 12, in( 1),  5); \
		ROUND1(B, C, D, E, A, F5, 13, in( 3),  5); \
		ROUND1(A, B, C, D, E, F5, 14, in( 8),  5); \
		ROUND1(E, A, B, C, D, F5, 11, in(11),  5); \
		ROUND1(D, E, A, B, C, F5,  8, in( 6),  5); \
		ROUND1(C, D, E, A, B, F5,  5, in(15),  5); \
		ROUND1(B, C, D, E, A, F5,  6, in(13),  5); \
 \
		ROUND2(A, B, C, D, E, F5,  8, in( 5),  1); \
		ROUND2(E, A, B, C, D, F5,  9, in(14),  1); \
		ROUND2(D, E, A, B, C, F5,  9, in( 7),  1); \
		ROUND2(C, D, E, A, B, F5, 11, in( 0),  1); \
		ROUND2(B, C, D, E, A, F5, 13, in( 9),  1); \
		ROUND2(A, B, C, D, E, F5, 15, in( 2),  1); \
		ROUND2(E, A, B, C, D, F5, 15, in(11),  1); \
		ROUND2(D, E, A, B, C, F5,  5, in( 4),  1); \
		ROUND2(C, D, E, A, B, F5,  7, in(13),  1); \
		ROUND2(B, C, D, E, A, F5,  7, in( 6),  1); \
		ROUND2(A, B, C, D, E, F5,  8, in(15),  1); \
		ROUND2(E, A, B, C, D, F5, 11, in( 8),  1); \
		ROUND2(D, E, A, B, C, F5, 14, in( 1),  1); \
		ROUND2(C, D, E, A, B, F5, 14, in(10),  1); \
		ROUND2(B, C, D, E, A, F5, 12, in( 3),  1); \
		ROUND2(A, B, C, D, E, F5,  6, in(12),  1); \
 \
		ROUND2(E, A, B, C, D, F4,  9, in( 6),  2); \
		ROUND2(D, E, A, B, C, F4, 13, in(11),  2); \
		ROUND2(C, D, E, A, B, F4, 15, in( 3),  2); \
		ROUND2(B, C, D, E, A, F4,  7, in( 7),  2); \
		ROUND2(A, B, C, D, E, F4, 12, in( 0),  2); \
		ROUND2(E, A, B, C, D, F4,  8, in(13),  2); \
		ROUND2(D, E, A, B, C, F4,  9, in( 5),  2); \
		ROUND2(C, D, E, A, B, F4, 11, in(10),  2); \
		ROUND2(B, C, D, E, A, F4,  7, in(14),  2); \
		ROUND2(A, B, C, D, E, F4,  7, in(15),  2); \
		ROUND2(E, A, B, C, D, F4, 12, in( 8),  2); \
		ROUND2(D, E, A, B, C, F4,  7, in(12),  2); \
		ROUND2(C, D, E, A, B, F4,  6, in( 4),  2); \
		ROUND2(B, C, D, E, A, F4, 15, in( 9),  2); \
		ROUND2(A, B, C, D, E, F4, 13, in( 1),  2); \
		ROUND2(E, A, B, C, D, F4, 11, in( 2),  2); \
 \
		ROUND2(D, E, A, B, C, F3,  9, in(15),  3); \
		ROUND2(C, D, E, A, B, F3,  7, in( 5),  3); \
		ROUND2(B, C, D, E, A, F3, 15, in( 1),  3); \
		ROUND2(A, B, C, D, E, F3, 11, in( 3),  3); \
		ROUND2(E, A, B, C, D, F3,  8, in( 7),  3); \
		ROUND2(D, E, A, B, C, F3,  6, in(14),  3); \
		ROUND2(C, D, E, A, B, F3,  6, in( 6),  3); \
		ROUND2(B, C, D, E, A, F3, 14, in( 9),  3); \
		ROUND2(A, B, C, D, E, F3, 12, in(11),  3); \
		ROUND2(E, A, B, C, D, F3, 13, in( 8),  3); \
		ROUND2(D, E, A, B, C, F3,  5, in(12),  3); \
		ROUND2(C, D, E, A, B, F3, 14, in( 2),  3); \
		ROUND2(B, C, D, E, A, F3, 13, in(10),  3); \
		ROUND2(A, B, C, D, E, F3, 13, in( 0),  3); \
		ROUND2(E, A, B, C, D, F3,  7, in( 4),  3); \
		ROUND2(D, E, A, B, C, F3,  5, in(13),  3); \
 \
		ROUND2(C, D, E, A, B, F2, 15, in( 8),  4); \
		ROUND2(B, C, D, E, A, F2,  5, in( 6),  4); \
		ROUND2(A, B, C, D, E, F2,  8, in( 4),  4); \
		ROUND2(E, A, B, C, D, F2, 11, in( 1),  4); \
		ROUND2(D, E, A, B, C, F2, 14, in( 3),  4); \
		ROUND2(C, D, E, A, B, F2, 14, in(11),  4); \
		ROUND2(B, C, D, E, A, F2,  6, in(15),  4); \
		ROUND2(A, B, C, D, E, F2, 14, in( 0),  4); \
		ROUND2(E, A, B, C, D, F2,  6, in( 5),  4); \
		ROUND2(D, E, A, B, C, F2,  9, in(12),  4); \
		ROUND2(C, D, E, A, B, F2, 12, in( 2),  4); \
		ROUND2(B, C, D, E, A, F2,  9, in(13),  4); \
		ROUND2(A, B, C, D, E, F2, 12, in( 9),  4); \
		ROUND2(E, A, B, C, D, F2,  5, in( 7),  4); \
		ROUND2(D, E, A, B, C, F2, 15, in(10),  4); \
		ROUND2(C, D, E, A, B, F2,  8, in(14),  4); \
 \
		ROUND2(B, C, D, E, A, F1,  8, in(12),  5); \
		ROUND2(A, B, C, D, E, F1,  5, in(15),  5); \
		ROUND2(E, A, B, C, D, F1, 12, in(10),  5); \
		ROUND2(D, E, A, B, C, F1,  9, in( 4),  5); \
		ROUND2(C, D, E, A, B, F1, 12, in( 1),  5); \
		ROUND2(B, C, D, E, A, F1,  5, in( 5),  5); \
		ROUND2(A, B, C, D, E, F1, 14, in( 8),  5); \
		ROUND2(E, A, B, C, D, F1,  6, in( 7),  5); \
		ROUND2(D, E, A, B, C, F1,  8, in( 6),  5); \
		ROUND2(C, D, E, A, B, F1, 13, in( 2),  5); \
		ROUND2(B, C, D, E, A, F1,  6, in(13),  5); \
		ROUND2(A, B, C, D, E, F1,  5, in(14),  5); \
		ROUND2(E, A, B, C, D, F1, 15, in( 0),  5); \
		ROUND2(D, E, A, B, C, F1, 13, in( 3),  5); \
		ROUND2(C, D, E, A, B, F1, 11, in( 9),  5); \
		ROUND2(B, C, D, E, A, F1, 11, in(11),  5); \
 \
		tmp = SPH_T32((h)[1] + C1 + D2); \
		(h)[1] = SPH_T32((h)[2] + D1 + E2); \
		(h)[2] = SPH_T32((h)[3] + E1 + A2); \
		(h)[3] = SPH_T32((h)[4] + A1 + B2); \
		(h)[4] = SPH_T32((h)[0] + B1 + C2); \
		(h)[0] = tmp; \
	} while (0)

/*
 * One round of RIPEMD-160. The data must be aligned for 32-bit access.
 */
static void
ripemd160_round(const unsigned char *data, sph_u32 r[5])
{
#if SPH_LITTLE_FAST

#define RIPEMD160_IN(x)   sph_dec32le_aligned(data + (4 * (x)))

#else

	sph_u32 X_var[16];
	int i;

	for (i = 0; i < 16; i ++)
		X_var[i] = sph_dec32le_aligned(data + 4 * i);
#define RIPEMD160_IN(x)   X_var[x]

#endif
	RIPEMD160_ROUND_BODY(RIPEMD160_IN, r);
#undef RIPEMD160_IN
}

/* see sph_ripemd.h */
void
sph_ripemd160_init(void *cc)
{
	sph_ripemd160_context *sc;

	sc = cc;
	memcpy(sc->val, IV, sizeof sc->val);
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = sc->count_low = 0;
#endif
}

#define RFUN   ripemd160_round
#define HASH   ripemd160
#define LE32   1
#include "md_helper.c"
#undef RFUN
#undef HASH
#undef LE32

/* see sph_ripemd.h */
void
sph_ripemd160_close(void *cc, void *dst)
{
	ripemd160_close(cc, dst, 5);
	sph_ripemd160_init(cc);
}

/* see sph_ripemd.h */
void
sph_ripemd160_comp(const sph_u32 msg[16], sph_u32 val[5])
{
#define RIPEMD160_IN(x)   msg[x]
	RIPEMD160_ROUND_BODY(RIPEMD160_IN, val);
#undef RIPEMD160_IN
}

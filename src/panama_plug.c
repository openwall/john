/* $Id: panama.c 216 2010-06-08 09:46:57Z tp $ */
/*
 * PANAMA implementation.
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

#include "sph_panama.h"

#define LVAR17(b)  sph_u32 \
	b ## 0, b ## 1, b ## 2, b ## 3, b ## 4, b ## 5, \
	b ## 6, b ## 7, b ## 8, b ## 9, b ## 10, b ## 11, \
	b ## 12, b ## 13, b ## 14, b ## 15, b ## 16;

#define LVARS   \
	LVAR17(a) \
	LVAR17(g) \
	LVAR17(p) \
	LVAR17(t)

#define M17(macro)   do { \
		macro( 0,  1,  2,  4); \
		macro( 1,  2,  3,  5); \
		macro( 2,  3,  4,  6); \
		macro( 3,  4,  5,  7); \
		macro( 4,  5,  6,  8); \
		macro( 5,  6,  7,  9); \
		macro( 6,  7,  8, 10); \
		macro( 7,  8,  9, 11); \
		macro( 8,  9, 10, 12); \
		macro( 9, 10, 11, 13); \
		macro(10, 11, 12, 14); \
		macro(11, 12, 13, 15); \
		macro(12, 13, 14, 16); \
		macro(13, 14, 15,  0); \
		macro(14, 15, 16,  1); \
		macro(15, 16,  0,  2); \
		macro(16,  0,  1,  3); \
	} while (0)

#define BUPDATE1(n0, n2)   do { \
		sc->buffer[ptr24][n0] ^= sc->buffer[ptr31][n2]; \
		sc->buffer[ptr31][n2] ^= INW1(n2); \
	} while (0)

#define BUPDATE   do { \
		BUPDATE1(0, 2); \
		BUPDATE1(1, 3); \
		BUPDATE1(2, 4); \
		BUPDATE1(3, 5); \
		BUPDATE1(4, 6); \
		BUPDATE1(5, 7); \
		BUPDATE1(6, 0); \
		BUPDATE1(7, 1); \
	} while (0)

#define RSTATE(n0, n1, n2, n4)    (a ## n0 = sc->state[n0])

#define WSTATE(n0, n1, n2, n4)    (sc->state[n0] = a ## n0)

#define GAMMA(n0, n1, n2, n4)   \
	(g ## n0 = a ## n0 ^ (a ## n1 | SPH_T32(~a ## n2)))

#define PI_ALL   do { \
		p0  = g0; \
		p1  = SPH_ROTL32( g7,  1); \
		p2  = SPH_ROTL32(g14,  3); \
		p3  = SPH_ROTL32( g4,  6); \
		p4  = SPH_ROTL32(g11, 10); \
		p5  = SPH_ROTL32( g1, 15); \
		p6  = SPH_ROTL32( g8, 21); \
		p7  = SPH_ROTL32(g15, 28); \
		p8  = SPH_ROTL32( g5,  4); \
		p9  = SPH_ROTL32(g12, 13); \
		p10 = SPH_ROTL32( g2, 23); \
		p11 = SPH_ROTL32( g9,  2); \
		p12 = SPH_ROTL32(g16, 14); \
		p13 = SPH_ROTL32( g6, 27); \
		p14 = SPH_ROTL32(g13,  9); \
		p15 = SPH_ROTL32( g3, 24); \
		p16 = SPH_ROTL32(g10,  8); \
	} while (0)

#define THETA(n0, n1, n2, n4)   \
	(t ## n0 = p ## n0 ^ p ## n1 ^ p ## n4)

#define SIGMA_ALL   do { \
		a0 = t0 ^ 1; \
		a1 = t1 ^ INW2(0); \
		a2 = t2 ^ INW2(1); \
		a3 = t3 ^ INW2(2); \
		a4 = t4 ^ INW2(3); \
		a5 = t5 ^ INW2(4); \
		a6 = t6 ^ INW2(5); \
		a7 = t7 ^ INW2(6); \
		a8 = t8 ^ INW2(7); \
		a9  =  t9 ^ sc->buffer[ptr16][0]; \
		a10 = t10 ^ sc->buffer[ptr16][1]; \
		a11 = t11 ^ sc->buffer[ptr16][2]; \
		a12 = t12 ^ sc->buffer[ptr16][3]; \
		a13 = t13 ^ sc->buffer[ptr16][4]; \
		a14 = t14 ^ sc->buffer[ptr16][5]; \
		a15 = t15 ^ sc->buffer[ptr16][6]; \
		a16 = t16 ^ sc->buffer[ptr16][7]; \
	} while (0)

#define PANAMA_STEP   do { \
		unsigned ptr16, ptr24, ptr31; \
 \
		ptr24 = (ptr0 - 8) & 31; \
		ptr31 = (ptr0 - 1) & 31; \
		BUPDATE; \
		M17(GAMMA); \
		PI_ALL; \
		M17(THETA); \
		ptr16 = ptr0 ^ 16; \
		SIGMA_ALL; \
		ptr0 = ptr31; \
	} while (0)

/*
 * These macros are used to compute
 */
#define INC0     1
#define INC1     2
#define INC2     3
#define INC3     4
#define INC4     5
#define INC5     6
#define INC6     7
#define INC7     8

/*
 * Push data by blocks of 32 bytes. "pbuf" must be 32-bit aligned. Each
 * iteration processes 32 data bytes; "num" contains the number of
 * iterations.
 */
static void
panama_push(sph_panama_context *sc, const unsigned char *pbuf, size_t num)
{
	LVARS
	unsigned ptr0;
#if SPH_LITTLE_FAST
#define INW1(i)   sph_dec32le_aligned(pbuf + 4 * (i))
#else
	sph_u32 X_var[8];
#define INW1(i)   X_var[i]
#endif
#define INW2(i)   INW1(i)

	M17(RSTATE);
	ptr0 = sc->buffer_ptr;
	while (num -- > 0) {
#if !SPH_LITTLE_FAST
		int i;

		for (i = 0; i < 8; i ++)
			X_var[i] = sph_dec32le_aligned(pbuf + 4 * (i));
#endif
		PANAMA_STEP;
		pbuf = (const unsigned char *)pbuf + 32;
	}
	M17(WSTATE);
	sc->buffer_ptr = ptr0;

#undef INW1
#undef INW2
}

/*
 * Perform the "pull" operation repeatedly ("num" times). The hash output
 * will be extracted from the state afterwards.
 */
static void
panama_pull(sph_panama_context *sc, unsigned num)
{
	LVARS
	unsigned ptr0;
#define INW1(i)     INW_H1(INC ## i)
#define INW_H1(i)   INW_H2(i)
#define INW_H2(i)   a ## i
#define INW2(i)     sc->buffer[ptr4][i]

	M17(RSTATE);
	ptr0 = sc->buffer_ptr;
	while (num -- > 0) {
		unsigned ptr4;

		ptr4 = (ptr0 + 4) & 31;
		PANAMA_STEP;
	}
	M17(WSTATE);

#undef INW1
#undef INW_H1
#undef INW_H2
#undef INW2
}

/* see sph_panama.h */
void
sph_panama_init(void *cc)
{
	sph_panama_context *sc;

	sc = cc;
	/*
	 * This is not completely conformant, but "it will work
	 * everywhere". Initial state consists of zeroes everywhere.
	 * Conceptually, the sph_u32 type may have padding bits which
	 * must not be set to 0; but such an architecture remains to
	 * be seen.
	 */
	sc->data_ptr = 0;
	memset(sc->buffer, 0, sizeof sc->buffer);
	sc->buffer_ptr = 0;
	memset(sc->state, 0, sizeof sc->state);
}

#ifdef SPH_UPTR
static void
panama_short(void *cc, const void *data, size_t len)
#else
void
sph_panama(void *cc, const void *data, size_t len)
#endif
{
	sph_panama_context *sc;
	unsigned current;

	sc = cc;
	current = sc->data_ptr;
	while (len > 0) {
		unsigned clen;

		clen = (sizeof sc->data) - current;
		if (clen > len)
			clen = len;
		memcpy(sc->data + current, data, clen);
		data = (const unsigned char *)data + clen;
		len -= clen;
		current += clen;
		if (current == sizeof sc->data) {
			current = 0;
			panama_push(sc, sc->data, 1);
		}
	}
	sc->data_ptr = current;
}

#ifdef SPH_UPTR
/* see sph_panama.h */
void
sph_panama(void *cc, const void *data, size_t len)
{
	sph_panama_context *sc;
	unsigned current;
	size_t rlen;

	if (len < (2 * sizeof sc->data)) {
		panama_short(cc, data, len);
		return;
	}
	sc = cc;
	current = sc->data_ptr;
	if (current > 0) {
		unsigned t;

		t = (sizeof sc->data) - current;
		panama_short(sc, data, t);
		data = (const unsigned char *)data + t;
		len -= t;
	}
#if !SPH_UNALIGNED
	if (((SPH_UPTR)data & 3) != 0) {
		panama_short(sc, data, len);
		return;
	}
#endif
	panama_push(sc, data, len >> 5);
	rlen = len & 31;
	if (rlen > 0)
		memcpy(sc->data,
			(const unsigned char *)data + len - rlen, rlen);
	sc->data_ptr = rlen;
}
#endif

/* see sph_panama.h */
void
sph_panama_close(void *cc, void *dst)
{
	sph_panama_context *sc;
	unsigned current;
	int i;

	sc = cc;
	current = sc->data_ptr;
	sc->data[current ++] = 0x01;
	memset(sc->data + current, 0, (sizeof sc->data) - current);
	panama_push(sc, sc->data, 1);
	panama_pull(sc, 32);
	for (i = 0; i < 8; i ++)
		sph_enc32le((unsigned char *)dst + 4 * i, sc->state[i + 9]);
	sph_panama_init(sc);
}

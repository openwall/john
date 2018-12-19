/* $Id: haval.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * HAVAL implementation.
 *
 * The HAVAL reference paper is of questionable clarity with regards to
 * some details such as endianness of bits within a byte, bytes within
 * a 32-bit word, or the actual ordering of words within a stream of
 * words. This implementation has been made compatible with the reference
 * implementation available on: http://labs.calyptix.com/haval.php
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
#include "arch.h"

#include "sph_haval.h"

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_HAVAL
#define SPH_SMALL_FOOTPRINT_HAVAL   1
#endif

/*
 * Basic definition from the reference paper.
 *
#define F1(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)) ^ ((x0) & (x1)) ^ (x0))
 *
 */

#define F1(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & ((x0) ^ (x4))) ^ ((x2) & (x5)) ^ ((x3) & (x6)) ^ (x0))

/*
 * Basic definition from the reference paper.
 *
#define F2(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x2) & (x3)) ^ ((x2) & (x4) & (x5)) ^ ((x1) & (x2)) \
	^ ((x1) & (x4)) ^ ((x2) & (x6)) ^ ((x3) & (x5)) \
	^ ((x4) & (x5)) ^ ((x0) & (x2)) ^ (x0))
 *
 */

#define F2(x6, x5, x4, x3, x2, x1, x0) \
	(((x2) & (((x1) & ~(x3)) ^ ((x4) & (x5)) ^ (x6) ^ (x0))) \
	^ ((x4) & ((x1) ^ (x5))) ^ ((x3 & (x5)) ^ (x0)))

/*
 * Basic definition from the reference paper.
 *
#define F3(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x2) & (x3)) ^ ((x1) & (x4)) ^ ((x2) & (x5)) \
	^ ((x3) & (x6)) ^ ((x0) & (x3)) ^ (x0))
 *
 */

#define F3(x6, x5, x4, x3, x2, x1, x0) \
	(((x3) & (((x1) & (x2)) ^ (x6) ^ (x0))) \
	^ ((x1) & (x4)) ^ ((x2) & (x5)) ^ (x0))

/*
 * Basic definition from the reference paper.
 *
#define F4(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x2) & (x3)) ^ ((x2) & (x4) & (x5)) ^ ((x3) & (x4) & (x6)) \
	^ ((x1) & (x4)) ^ ((x2) & (x6)) ^ ((x3) & (x4)) ^ ((x3) & (x5)) \
	^ ((x3) & (x6)) ^ ((x4) & (x5)) ^ ((x4) & (x6)) ^ ((x0) & (x4)) ^ (x0))
 *
 */

#define F4(x6, x5, x4, x3, x2, x1, x0) \
	(((x3) & (((x1) & (x2)) ^ ((x4) | (x6)) ^ (x5))) \
	^ ((x4) & ((~(x2) & (x5)) ^ (x1) ^ (x6) ^ (x0))) \
	^ ((x2) & (x6)) ^ (x0))

/*
 * Basic definition from the reference paper.
 *
#define F5(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)) \
	^ ((x0) & (x1) & (x2) & (x3)) ^ ((x0) & (x5)) ^ (x0))
 *
 */

#define F5(x6, x5, x4, x3, x2, x1, x0) \
	(((x0) & ~(((x1) & (x2) & (x3)) ^ (x5))) \
	^ ((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)))

/*
 * The macros below integrate the phi() permutations, depending on the
 * pass and the total number of passes.
 */

#define FP3_1(x6, x5, x4, x3, x2, x1, x0) \
	F1(x1, x0, x3, x5, x6, x2, x4)
#define FP3_2(x6, x5, x4, x3, x2, x1, x0) \
	F2(x4, x2, x1, x0, x5, x3, x6)
#define FP3_3(x6, x5, x4, x3, x2, x1, x0) \
	F3(x6, x1, x2, x3, x4, x5, x0)

#define FP4_1(x6, x5, x4, x3, x2, x1, x0) \
	F1(x2, x6, x1, x4, x5, x3, x0)
#define FP4_2(x6, x5, x4, x3, x2, x1, x0) \
	F2(x3, x5, x2, x0, x1, x6, x4)
#define FP4_3(x6, x5, x4, x3, x2, x1, x0) \
	F3(x1, x4, x3, x6, x0, x2, x5)
#define FP4_4(x6, x5, x4, x3, x2, x1, x0) \
	F4(x6, x4, x0, x5, x2, x1, x3)

#define FP5_1(x6, x5, x4, x3, x2, x1, x0) \
	F1(x3, x4, x1, x0, x5, x2, x6)
#define FP5_2(x6, x5, x4, x3, x2, x1, x0) \
	F2(x6, x2, x1, x0, x3, x4, x5)
#define FP5_3(x6, x5, x4, x3, x2, x1, x0) \
	F3(x2, x6, x0, x4, x3, x1, x5)
#define FP5_4(x6, x5, x4, x3, x2, x1, x0) \
	F4(x1, x5, x3, x2, x0, x4, x6)
#define FP5_5(x6, x5, x4, x3, x2, x1, x0) \
	F5(x2, x5, x0, x6, x4, x3, x1)

/*
 * One step, for "n" passes, pass number "p" (1 <= p <= n), using
 * input word number "w" and step constant "c".
 */
#define STEP(n, p, x7, x6, x5, x4, x3, x2, x1, x0, w, c)  do { \
		sph_u32 t = FP ## n ## _ ## p(x6, x5, x4, x3, x2, x1, x0); \
		(x7) = SPH_T32(SPH_ROTR32(t, 7) + SPH_ROTR32((x7), 11) \
			+ (w) + (c)); \
	} while (0)

/*
 * PASSy(n, in) computes pass number "y", for a total of "n", using the
 * one-argument macro "in" to access input words. Current state is assumed
 * to be held in variables "s0" to "s7".
 */

#if SPH_SMALL_FOOTPRINT_HAVAL

#define PASS1(n, in)   do { \
		unsigned pass_count; \
		for (pass_count = 0; pass_count < 32; pass_count += 8) { \
			STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, \
				in(pass_count + 0), SPH_C32(0x00000000)); \
			STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, \
				in(pass_count + 1), SPH_C32(0x00000000)); \
			STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, \
				in(pass_count + 2), SPH_C32(0x00000000)); \
			STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, \
				in(pass_count + 3), SPH_C32(0x00000000)); \
			STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, \
				in(pass_count + 4), SPH_C32(0x00000000)); \
			STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, \
				in(pass_count + 5), SPH_C32(0x00000000)); \
			STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, \
				in(pass_count + 6), SPH_C32(0x00000000)); \
			STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, \
				in(pass_count + 7), SPH_C32(0x00000000)); \
		} \
	} while (0)

#define PASSG(p, n, in)   do { \
		unsigned pass_count; \
		for (pass_count = 0; pass_count < 32; pass_count += 8) { \
			STEP(n, p, s7, s6, s5, s4, s3, s2, s1, s0, \
				in(MP ## p[pass_count + 0]), \
				RK ## p[pass_count + 0]); \
			STEP(n, p, s6, s5, s4, s3, s2, s1, s0, s7, \
				in(MP ## p[pass_count + 1]), \
				RK ## p[pass_count + 1]); \
			STEP(n, p, s5, s4, s3, s2, s1, s0, s7, s6, \
				in(MP ## p[pass_count + 2]), \
				RK ## p[pass_count + 2]); \
			STEP(n, p, s4, s3, s2, s1, s0, s7, s6, s5, \
				in(MP ## p[pass_count + 3]), \
				RK ## p[pass_count + 3]); \
			STEP(n, p, s3, s2, s1, s0, s7, s6, s5, s4, \
				in(MP ## p[pass_count + 4]), \
				RK ## p[pass_count + 4]); \
			STEP(n, p, s2, s1, s0, s7, s6, s5, s4, s3, \
				in(MP ## p[pass_count + 5]), \
				RK ## p[pass_count + 5]); \
			STEP(n, p, s1, s0, s7, s6, s5, s4, s3, s2, \
				in(MP ## p[pass_count + 6]), \
				RK ## p[pass_count + 6]); \
			STEP(n, p, s0, s7, s6, s5, s4, s3, s2, s1, \
				in(MP ## p[pass_count + 7]), \
				RK ## p[pass_count + 7]); \
		} \
	} while (0)

#define PASS2(n, in)    PASSG(2, n, in)
#define PASS3(n, in)    PASSG(3, n, in)
#define PASS4(n, in)    PASSG(4, n, in)
#define PASS5(n, in)    PASSG(5, n, in)

static const unsigned MP2[32] = {
	 5, 14, 26, 18, 11, 28,  7, 16,
	 0, 23, 20, 22,  1, 10,  4,  8,
	30,  3, 21,  9, 17, 24, 29,  6,
	19, 12, 15, 13,  2, 25, 31, 27
};

static const unsigned MP3[32] = {
	19,  9,  4, 20, 28, 17,  8, 22,
	29, 14, 25, 12, 24, 30, 16, 26,
	31, 15,  7,  3,  1,  0, 18, 27,
	13,  6, 21, 10, 23, 11,  5,  2
};

static const unsigned MP4[32] = {
	24,  4,  0, 14,  2,  7, 28, 23,
	26,  6, 30, 20, 18, 25, 19,  3,
	22, 11, 31, 21,  8, 27, 12,  9,
	 1, 29,  5, 15, 17, 10, 16, 13
};

static const unsigned MP5[32] = {
	27,  3, 21, 26, 17, 11, 20, 29,
	19,  0, 12,  7, 13,  8, 31, 10,
	 5,  9, 14, 30, 18,  6, 28, 24,
	 2, 23, 16, 22,  4,  1, 25, 15
};

static const sph_u32 RK2[32] = {
	SPH_C32(0x452821E6), SPH_C32(0x38D01377),
	SPH_C32(0xBE5466CF), SPH_C32(0x34E90C6C),
	SPH_C32(0xC0AC29B7), SPH_C32(0xC97C50DD),
	SPH_C32(0x3F84D5B5), SPH_C32(0xB5470917),
	SPH_C32(0x9216D5D9), SPH_C32(0x8979FB1B),
	SPH_C32(0xD1310BA6), SPH_C32(0x98DFB5AC),
	SPH_C32(0x2FFD72DB), SPH_C32(0xD01ADFB7),
	SPH_C32(0xB8E1AFED), SPH_C32(0x6A267E96),
	SPH_C32(0xBA7C9045), SPH_C32(0xF12C7F99),
	SPH_C32(0x24A19947), SPH_C32(0xB3916CF7),
	SPH_C32(0x0801F2E2), SPH_C32(0x858EFC16),
	SPH_C32(0x636920D8), SPH_C32(0x71574E69),
	SPH_C32(0xA458FEA3), SPH_C32(0xF4933D7E),
	SPH_C32(0x0D95748F), SPH_C32(0x728EB658),
	SPH_C32(0x718BCD58), SPH_C32(0x82154AEE),
	SPH_C32(0x7B54A41D), SPH_C32(0xC25A59B5)
};

static const sph_u32 RK3[32] = {
	SPH_C32(0x9C30D539), SPH_C32(0x2AF26013),
	SPH_C32(0xC5D1B023), SPH_C32(0x286085F0),
	SPH_C32(0xCA417918), SPH_C32(0xB8DB38EF),
	SPH_C32(0x8E79DCB0), SPH_C32(0x603A180E),
	SPH_C32(0x6C9E0E8B), SPH_C32(0xB01E8A3E),
	SPH_C32(0xD71577C1), SPH_C32(0xBD314B27),
	SPH_C32(0x78AF2FDA), SPH_C32(0x55605C60),
	SPH_C32(0xE65525F3), SPH_C32(0xAA55AB94),
	SPH_C32(0x57489862), SPH_C32(0x63E81440),
	SPH_C32(0x55CA396A), SPH_C32(0x2AAB10B6),
	SPH_C32(0xB4CC5C34), SPH_C32(0x1141E8CE),
	SPH_C32(0xA15486AF), SPH_C32(0x7C72E993),
	SPH_C32(0xB3EE1411), SPH_C32(0x636FBC2A),
	SPH_C32(0x2BA9C55D), SPH_C32(0x741831F6),
	SPH_C32(0xCE5C3E16), SPH_C32(0x9B87931E),
	SPH_C32(0xAFD6BA33), SPH_C32(0x6C24CF5C)
};

static const sph_u32 RK4[32] = {
	SPH_C32(0x7A325381), SPH_C32(0x28958677),
	SPH_C32(0x3B8F4898), SPH_C32(0x6B4BB9AF),
	SPH_C32(0xC4BFE81B), SPH_C32(0x66282193),
	SPH_C32(0x61D809CC), SPH_C32(0xFB21A991),
	SPH_C32(0x487CAC60), SPH_C32(0x5DEC8032),
	SPH_C32(0xEF845D5D), SPH_C32(0xE98575B1),
	SPH_C32(0xDC262302), SPH_C32(0xEB651B88),
	SPH_C32(0x23893E81), SPH_C32(0xD396ACC5),
	SPH_C32(0x0F6D6FF3), SPH_C32(0x83F44239),
	SPH_C32(0x2E0B4482), SPH_C32(0xA4842004),
	SPH_C32(0x69C8F04A), SPH_C32(0x9E1F9B5E),
	SPH_C32(0x21C66842), SPH_C32(0xF6E96C9A),
	SPH_C32(0x670C9C61), SPH_C32(0xABD388F0),
	SPH_C32(0x6A51A0D2), SPH_C32(0xD8542F68),
	SPH_C32(0x960FA728), SPH_C32(0xAB5133A3),
	SPH_C32(0x6EEF0B6C), SPH_C32(0x137A3BE4)
};

static const sph_u32 RK5[32] = {
	SPH_C32(0xBA3BF050), SPH_C32(0x7EFB2A98),
	SPH_C32(0xA1F1651D), SPH_C32(0x39AF0176),
	SPH_C32(0x66CA593E), SPH_C32(0x82430E88),
	SPH_C32(0x8CEE8619), SPH_C32(0x456F9FB4),
	SPH_C32(0x7D84A5C3), SPH_C32(0x3B8B5EBE),
	SPH_C32(0xE06F75D8), SPH_C32(0x85C12073),
	SPH_C32(0x401A449F), SPH_C32(0x56C16AA6),
	SPH_C32(0x4ED3AA62), SPH_C32(0x363F7706),
	SPH_C32(0x1BFEDF72), SPH_C32(0x429B023D),
	SPH_C32(0x37D0D724), SPH_C32(0xD00A1248),
	SPH_C32(0xDB0FEAD3), SPH_C32(0x49F1C09B),
	SPH_C32(0x075372C9), SPH_C32(0x80991B7B),
	SPH_C32(0x25D479D8), SPH_C32(0xF6E8DEF7),
	SPH_C32(0xE3FE501A), SPH_C32(0xB6794C3B),
	SPH_C32(0x976CE0BD), SPH_C32(0x04C006BA),
	SPH_C32(0xC1A94FB6), SPH_C32(0x409F60C4)
};

#else

#define PASS1(n, in)   do { \
   STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, in( 0), SPH_C32(0x00000000)); \
   STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, in( 1), SPH_C32(0x00000000)); \
   STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, in( 2), SPH_C32(0x00000000)); \
   STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, in( 3), SPH_C32(0x00000000)); \
   STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, in( 4), SPH_C32(0x00000000)); \
   STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, in( 5), SPH_C32(0x00000000)); \
   STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, in( 6), SPH_C32(0x00000000)); \
   STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, in( 7), SPH_C32(0x00000000)); \
 \
   STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, in( 8), SPH_C32(0x00000000)); \
   STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, in( 9), SPH_C32(0x00000000)); \
   STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, in(10), SPH_C32(0x00000000)); \
   STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, in(11), SPH_C32(0x00000000)); \
   STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, in(12), SPH_C32(0x00000000)); \
   STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, in(13), SPH_C32(0x00000000)); \
   STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, in(14), SPH_C32(0x00000000)); \
   STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, in(15), SPH_C32(0x00000000)); \
 \
   STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, in(16), SPH_C32(0x00000000)); \
   STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, in(17), SPH_C32(0x00000000)); \
   STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, in(18), SPH_C32(0x00000000)); \
   STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, in(19), SPH_C32(0x00000000)); \
   STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, in(20), SPH_C32(0x00000000)); \
   STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, in(21), SPH_C32(0x00000000)); \
   STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, in(22), SPH_C32(0x00000000)); \
   STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, in(23), SPH_C32(0x00000000)); \
 \
   STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, in(24), SPH_C32(0x00000000)); \
   STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, in(25), SPH_C32(0x00000000)); \
   STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, in(26), SPH_C32(0x00000000)); \
   STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, in(27), SPH_C32(0x00000000)); \
   STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, in(28), SPH_C32(0x00000000)); \
   STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, in(29), SPH_C32(0x00000000)); \
   STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, in(30), SPH_C32(0x00000000)); \
   STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, in(31), SPH_C32(0x00000000)); \
	} while (0)

#define PASS2(n, in)   do { \
   STEP(n, 2, s7, s6, s5, s4, s3, s2, s1, s0, in( 5), SPH_C32(0x452821E6)); \
   STEP(n, 2, s6, s5, s4, s3, s2, s1, s0, s7, in(14), SPH_C32(0x38D01377)); \
   STEP(n, 2, s5, s4, s3, s2, s1, s0, s7, s6, in(26), SPH_C32(0xBE5466CF)); \
   STEP(n, 2, s4, s3, s2, s1, s0, s7, s6, s5, in(18), SPH_C32(0x34E90C6C)); \
   STEP(n, 2, s3, s2, s1, s0, s7, s6, s5, s4, in(11), SPH_C32(0xC0AC29B7)); \
   STEP(n, 2, s2, s1, s0, s7, s6, s5, s4, s3, in(28), SPH_C32(0xC97C50DD)); \
   STEP(n, 2, s1, s0, s7, s6, s5, s4, s3, s2, in( 7), SPH_C32(0x3F84D5B5)); \
   STEP(n, 2, s0, s7, s6, s5, s4, s3, s2, s1, in(16), SPH_C32(0xB5470917)); \
 \
   STEP(n, 2, s7, s6, s5, s4, s3, s2, s1, s0, in( 0), SPH_C32(0x9216D5D9)); \
   STEP(n, 2, s6, s5, s4, s3, s2, s1, s0, s7, in(23), SPH_C32(0x8979FB1B)); \
   STEP(n, 2, s5, s4, s3, s2, s1, s0, s7, s6, in(20), SPH_C32(0xD1310BA6)); \
   STEP(n, 2, s4, s3, s2, s1, s0, s7, s6, s5, in(22), SPH_C32(0x98DFB5AC)); \
   STEP(n, 2, s3, s2, s1, s0, s7, s6, s5, s4, in( 1), SPH_C32(0x2FFD72DB)); \
   STEP(n, 2, s2, s1, s0, s7, s6, s5, s4, s3, in(10), SPH_C32(0xD01ADFB7)); \
   STEP(n, 2, s1, s0, s7, s6, s5, s4, s3, s2, in( 4), SPH_C32(0xB8E1AFED)); \
   STEP(n, 2, s0, s7, s6, s5, s4, s3, s2, s1, in( 8), SPH_C32(0x6A267E96)); \
 \
   STEP(n, 2, s7, s6, s5, s4, s3, s2, s1, s0, in(30), SPH_C32(0xBA7C9045)); \
   STEP(n, 2, s6, s5, s4, s3, s2, s1, s0, s7, in( 3), SPH_C32(0xF12C7F99)); \
   STEP(n, 2, s5, s4, s3, s2, s1, s0, s7, s6, in(21), SPH_C32(0x24A19947)); \
   STEP(n, 2, s4, s3, s2, s1, s0, s7, s6, s5, in( 9), SPH_C32(0xB3916CF7)); \
   STEP(n, 2, s3, s2, s1, s0, s7, s6, s5, s4, in(17), SPH_C32(0x0801F2E2)); \
   STEP(n, 2, s2, s1, s0, s7, s6, s5, s4, s3, in(24), SPH_C32(0x858EFC16)); \
   STEP(n, 2, s1, s0, s7, s6, s5, s4, s3, s2, in(29), SPH_C32(0x636920D8)); \
   STEP(n, 2, s0, s7, s6, s5, s4, s3, s2, s1, in( 6), SPH_C32(0x71574E69)); \
 \
   STEP(n, 2, s7, s6, s5, s4, s3, s2, s1, s0, in(19), SPH_C32(0xA458FEA3)); \
   STEP(n, 2, s6, s5, s4, s3, s2, s1, s0, s7, in(12), SPH_C32(0xF4933D7E)); \
   STEP(n, 2, s5, s4, s3, s2, s1, s0, s7, s6, in(15), SPH_C32(0x0D95748F)); \
   STEP(n, 2, s4, s3, s2, s1, s0, s7, s6, s5, in(13), SPH_C32(0x728EB658)); \
   STEP(n, 2, s3, s2, s1, s0, s7, s6, s5, s4, in( 2), SPH_C32(0x718BCD58)); \
   STEP(n, 2, s2, s1, s0, s7, s6, s5, s4, s3, in(25), SPH_C32(0x82154AEE)); \
   STEP(n, 2, s1, s0, s7, s6, s5, s4, s3, s2, in(31), SPH_C32(0x7B54A41D)); \
   STEP(n, 2, s0, s7, s6, s5, s4, s3, s2, s1, in(27), SPH_C32(0xC25A59B5)); \
	} while (0)

#define PASS3(n, in)   do { \
   STEP(n, 3, s7, s6, s5, s4, s3, s2, s1, s0, in(19), SPH_C32(0x9C30D539)); \
   STEP(n, 3, s6, s5, s4, s3, s2, s1, s0, s7, in( 9), SPH_C32(0x2AF26013)); \
   STEP(n, 3, s5, s4, s3, s2, s1, s0, s7, s6, in( 4), SPH_C32(0xC5D1B023)); \
   STEP(n, 3, s4, s3, s2, s1, s0, s7, s6, s5, in(20), SPH_C32(0x286085F0)); \
   STEP(n, 3, s3, s2, s1, s0, s7, s6, s5, s4, in(28), SPH_C32(0xCA417918)); \
   STEP(n, 3, s2, s1, s0, s7, s6, s5, s4, s3, in(17), SPH_C32(0xB8DB38EF)); \
   STEP(n, 3, s1, s0, s7, s6, s5, s4, s3, s2, in( 8), SPH_C32(0x8E79DCB0)); \
   STEP(n, 3, s0, s7, s6, s5, s4, s3, s2, s1, in(22), SPH_C32(0x603A180E)); \
 \
   STEP(n, 3, s7, s6, s5, s4, s3, s2, s1, s0, in(29), SPH_C32(0x6C9E0E8B)); \
   STEP(n, 3, s6, s5, s4, s3, s2, s1, s0, s7, in(14), SPH_C32(0xB01E8A3E)); \
   STEP(n, 3, s5, s4, s3, s2, s1, s0, s7, s6, in(25), SPH_C32(0xD71577C1)); \
   STEP(n, 3, s4, s3, s2, s1, s0, s7, s6, s5, in(12), SPH_C32(0xBD314B27)); \
   STEP(n, 3, s3, s2, s1, s0, s7, s6, s5, s4, in(24), SPH_C32(0x78AF2FDA)); \
   STEP(n, 3, s2, s1, s0, s7, s6, s5, s4, s3, in(30), SPH_C32(0x55605C60)); \
   STEP(n, 3, s1, s0, s7, s6, s5, s4, s3, s2, in(16), SPH_C32(0xE65525F3)); \
   STEP(n, 3, s0, s7, s6, s5, s4, s3, s2, s1, in(26), SPH_C32(0xAA55AB94)); \
 \
   STEP(n, 3, s7, s6, s5, s4, s3, s2, s1, s0, in(31), SPH_C32(0x57489862)); \
   STEP(n, 3, s6, s5, s4, s3, s2, s1, s0, s7, in(15), SPH_C32(0x63E81440)); \
   STEP(n, 3, s5, s4, s3, s2, s1, s0, s7, s6, in( 7), SPH_C32(0x55CA396A)); \
   STEP(n, 3, s4, s3, s2, s1, s0, s7, s6, s5, in( 3), SPH_C32(0x2AAB10B6)); \
   STEP(n, 3, s3, s2, s1, s0, s7, s6, s5, s4, in( 1), SPH_C32(0xB4CC5C34)); \
   STEP(n, 3, s2, s1, s0, s7, s6, s5, s4, s3, in( 0), SPH_C32(0x1141E8CE)); \
   STEP(n, 3, s1, s0, s7, s6, s5, s4, s3, s2, in(18), SPH_C32(0xA15486AF)); \
   STEP(n, 3, s0, s7, s6, s5, s4, s3, s2, s1, in(27), SPH_C32(0x7C72E993)); \
 \
   STEP(n, 3, s7, s6, s5, s4, s3, s2, s1, s0, in(13), SPH_C32(0xB3EE1411)); \
   STEP(n, 3, s6, s5, s4, s3, s2, s1, s0, s7, in( 6), SPH_C32(0x636FBC2A)); \
   STEP(n, 3, s5, s4, s3, s2, s1, s0, s7, s6, in(21), SPH_C32(0x2BA9C55D)); \
   STEP(n, 3, s4, s3, s2, s1, s0, s7, s6, s5, in(10), SPH_C32(0x741831F6)); \
   STEP(n, 3, s3, s2, s1, s0, s7, s6, s5, s4, in(23), SPH_C32(0xCE5C3E16)); \
   STEP(n, 3, s2, s1, s0, s7, s6, s5, s4, s3, in(11), SPH_C32(0x9B87931E)); \
   STEP(n, 3, s1, s0, s7, s6, s5, s4, s3, s2, in( 5), SPH_C32(0xAFD6BA33)); \
   STEP(n, 3, s0, s7, s6, s5, s4, s3, s2, s1, in( 2), SPH_C32(0x6C24CF5C)); \
	} while (0)

#define PASS4(n, in)   do { \
   STEP(n, 4, s7, s6, s5, s4, s3, s2, s1, s0, in(24), SPH_C32(0x7A325381)); \
   STEP(n, 4, s6, s5, s4, s3, s2, s1, s0, s7, in( 4), SPH_C32(0x28958677)); \
   STEP(n, 4, s5, s4, s3, s2, s1, s0, s7, s6, in( 0), SPH_C32(0x3B8F4898)); \
   STEP(n, 4, s4, s3, s2, s1, s0, s7, s6, s5, in(14), SPH_C32(0x6B4BB9AF)); \
   STEP(n, 4, s3, s2, s1, s0, s7, s6, s5, s4, in( 2), SPH_C32(0xC4BFE81B)); \
   STEP(n, 4, s2, s1, s0, s7, s6, s5, s4, s3, in( 7), SPH_C32(0x66282193)); \
   STEP(n, 4, s1, s0, s7, s6, s5, s4, s3, s2, in(28), SPH_C32(0x61D809CC)); \
   STEP(n, 4, s0, s7, s6, s5, s4, s3, s2, s1, in(23), SPH_C32(0xFB21A991)); \
 \
   STEP(n, 4, s7, s6, s5, s4, s3, s2, s1, s0, in(26), SPH_C32(0x487CAC60)); \
   STEP(n, 4, s6, s5, s4, s3, s2, s1, s0, s7, in( 6), SPH_C32(0x5DEC8032)); \
   STEP(n, 4, s5, s4, s3, s2, s1, s0, s7, s6, in(30), SPH_C32(0xEF845D5D)); \
   STEP(n, 4, s4, s3, s2, s1, s0, s7, s6, s5, in(20), SPH_C32(0xE98575B1)); \
   STEP(n, 4, s3, s2, s1, s0, s7, s6, s5, s4, in(18), SPH_C32(0xDC262302)); \
   STEP(n, 4, s2, s1, s0, s7, s6, s5, s4, s3, in(25), SPH_C32(0xEB651B88)); \
   STEP(n, 4, s1, s0, s7, s6, s5, s4, s3, s2, in(19), SPH_C32(0x23893E81)); \
   STEP(n, 4, s0, s7, s6, s5, s4, s3, s2, s1, in( 3), SPH_C32(0xD396ACC5)); \
 \
   STEP(n, 4, s7, s6, s5, s4, s3, s2, s1, s0, in(22), SPH_C32(0x0F6D6FF3)); \
   STEP(n, 4, s6, s5, s4, s3, s2, s1, s0, s7, in(11), SPH_C32(0x83F44239)); \
   STEP(n, 4, s5, s4, s3, s2, s1, s0, s7, s6, in(31), SPH_C32(0x2E0B4482)); \
   STEP(n, 4, s4, s3, s2, s1, s0, s7, s6, s5, in(21), SPH_C32(0xA4842004)); \
   STEP(n, 4, s3, s2, s1, s0, s7, s6, s5, s4, in( 8), SPH_C32(0x69C8F04A)); \
   STEP(n, 4, s2, s1, s0, s7, s6, s5, s4, s3, in(27), SPH_C32(0x9E1F9B5E)); \
   STEP(n, 4, s1, s0, s7, s6, s5, s4, s3, s2, in(12), SPH_C32(0x21C66842)); \
   STEP(n, 4, s0, s7, s6, s5, s4, s3, s2, s1, in( 9), SPH_C32(0xF6E96C9A)); \
 \
   STEP(n, 4, s7, s6, s5, s4, s3, s2, s1, s0, in( 1), SPH_C32(0x670C9C61)); \
   STEP(n, 4, s6, s5, s4, s3, s2, s1, s0, s7, in(29), SPH_C32(0xABD388F0)); \
   STEP(n, 4, s5, s4, s3, s2, s1, s0, s7, s6, in( 5), SPH_C32(0x6A51A0D2)); \
   STEP(n, 4, s4, s3, s2, s1, s0, s7, s6, s5, in(15), SPH_C32(0xD8542F68)); \
   STEP(n, 4, s3, s2, s1, s0, s7, s6, s5, s4, in(17), SPH_C32(0x960FA728)); \
   STEP(n, 4, s2, s1, s0, s7, s6, s5, s4, s3, in(10), SPH_C32(0xAB5133A3)); \
   STEP(n, 4, s1, s0, s7, s6, s5, s4, s3, s2, in(16), SPH_C32(0x6EEF0B6C)); \
   STEP(n, 4, s0, s7, s6, s5, s4, s3, s2, s1, in(13), SPH_C32(0x137A3BE4)); \
	} while (0)

#define PASS5(n, in)   do { \
   STEP(n, 5, s7, s6, s5, s4, s3, s2, s1, s0, in(27), SPH_C32(0xBA3BF050)); \
   STEP(n, 5, s6, s5, s4, s3, s2, s1, s0, s7, in( 3), SPH_C32(0x7EFB2A98)); \
   STEP(n, 5, s5, s4, s3, s2, s1, s0, s7, s6, in(21), SPH_C32(0xA1F1651D)); \
   STEP(n, 5, s4, s3, s2, s1, s0, s7, s6, s5, in(26), SPH_C32(0x39AF0176)); \
   STEP(n, 5, s3, s2, s1, s0, s7, s6, s5, s4, in(17), SPH_C32(0x66CA593E)); \
   STEP(n, 5, s2, s1, s0, s7, s6, s5, s4, s3, in(11), SPH_C32(0x82430E88)); \
   STEP(n, 5, s1, s0, s7, s6, s5, s4, s3, s2, in(20), SPH_C32(0x8CEE8619)); \
   STEP(n, 5, s0, s7, s6, s5, s4, s3, s2, s1, in(29), SPH_C32(0x456F9FB4)); \
 \
   STEP(n, 5, s7, s6, s5, s4, s3, s2, s1, s0, in(19), SPH_C32(0x7D84A5C3)); \
   STEP(n, 5, s6, s5, s4, s3, s2, s1, s0, s7, in( 0), SPH_C32(0x3B8B5EBE)); \
   STEP(n, 5, s5, s4, s3, s2, s1, s0, s7, s6, in(12), SPH_C32(0xE06F75D8)); \
   STEP(n, 5, s4, s3, s2, s1, s0, s7, s6, s5, in( 7), SPH_C32(0x85C12073)); \
   STEP(n, 5, s3, s2, s1, s0, s7, s6, s5, s4, in(13), SPH_C32(0x401A449F)); \
   STEP(n, 5, s2, s1, s0, s7, s6, s5, s4, s3, in( 8), SPH_C32(0x56C16AA6)); \
   STEP(n, 5, s1, s0, s7, s6, s5, s4, s3, s2, in(31), SPH_C32(0x4ED3AA62)); \
   STEP(n, 5, s0, s7, s6, s5, s4, s3, s2, s1, in(10), SPH_C32(0x363F7706)); \
 \
   STEP(n, 5, s7, s6, s5, s4, s3, s2, s1, s0, in( 5), SPH_C32(0x1BFEDF72)); \
   STEP(n, 5, s6, s5, s4, s3, s2, s1, s0, s7, in( 9), SPH_C32(0x429B023D)); \
   STEP(n, 5, s5, s4, s3, s2, s1, s0, s7, s6, in(14), SPH_C32(0x37D0D724)); \
   STEP(n, 5, s4, s3, s2, s1, s0, s7, s6, s5, in(30), SPH_C32(0xD00A1248)); \
   STEP(n, 5, s3, s2, s1, s0, s7, s6, s5, s4, in(18), SPH_C32(0xDB0FEAD3)); \
   STEP(n, 5, s2, s1, s0, s7, s6, s5, s4, s3, in( 6), SPH_C32(0x49F1C09B)); \
   STEP(n, 5, s1, s0, s7, s6, s5, s4, s3, s2, in(28), SPH_C32(0x075372C9)); \
   STEP(n, 5, s0, s7, s6, s5, s4, s3, s2, s1, in(24), SPH_C32(0x80991B7B)); \
 \
   STEP(n, 5, s7, s6, s5, s4, s3, s2, s1, s0, in( 2), SPH_C32(0x25D479D8)); \
   STEP(n, 5, s6, s5, s4, s3, s2, s1, s0, s7, in(23), SPH_C32(0xF6E8DEF7)); \
   STEP(n, 5, s5, s4, s3, s2, s1, s0, s7, s6, in(16), SPH_C32(0xE3FE501A)); \
   STEP(n, 5, s4, s3, s2, s1, s0, s7, s6, s5, in(22), SPH_C32(0xB6794C3B)); \
   STEP(n, 5, s3, s2, s1, s0, s7, s6, s5, s4, in( 4), SPH_C32(0x976CE0BD)); \
   STEP(n, 5, s2, s1, s0, s7, s6, s5, s4, s3, in( 1), SPH_C32(0x04C006BA)); \
   STEP(n, 5, s1, s0, s7, s6, s5, s4, s3, s2, in(25), SPH_C32(0xC1A94FB6)); \
   STEP(n, 5, s0, s7, s6, s5, s4, s3, s2, s1, in(15), SPH_C32(0x409F60C4)); \
	} while (0)

#endif

#define SAVE_STATE \
	sph_u32 u0, u1, u2, u3, u4, u5, u6, u7; \
	do { \
		u0 = s0; \
		u1 = s1; \
		u2 = s2; \
		u3 = s3; \
		u4 = s4; \
		u5 = s5; \
		u6 = s6; \
		u7 = s7; \
	} while (0)

#define UPDATE_STATE   do { \
		s0 = SPH_T32(s0 + u0); \
		s1 = SPH_T32(s1 + u1); \
		s2 = SPH_T32(s2 + u2); \
		s3 = SPH_T32(s3 + u3); \
		s4 = SPH_T32(s4 + u4); \
		s5 = SPH_T32(s5 + u5); \
		s6 = SPH_T32(s6 + u6); \
		s7 = SPH_T32(s7 + u7); \
	} while (0)

/*
 * COREn(in) performs the core HAVAL computation for "n" passes, using
 * the one-argument macro "in" to access the input words. Running state
 * is held in variable "s0" to "s7".
 */

#define CORE3(in)  do { \
		SAVE_STATE; \
		PASS1(3, in); \
		PASS2(3, in); \
		PASS3(3, in); \
		UPDATE_STATE; \
	} while (0)

#define CORE4(in)  do { \
		SAVE_STATE; \
		PASS1(4, in); \
		PASS2(4, in); \
		PASS3(4, in); \
		PASS4(4, in); \
		UPDATE_STATE; \
	} while (0)

#define CORE5(in)  do { \
		SAVE_STATE; \
		PASS1(5, in); \
		PASS2(5, in); \
		PASS3(5, in); \
		PASS4(5, in); \
		PASS5(5, in); \
		UPDATE_STATE; \
	} while (0)

/*
 * DSTATE declares the state variables "s0" to "s7".
 */
#define DSTATE   sph_u32 s0, s1, s2, s3, s4, s5, s6, s7

/*
 * RSTATE fills the state variables from the context "sc".
 */
#define RSTATE   do { \
		s0 = sc->s0; \
		s1 = sc->s1; \
		s2 = sc->s2; \
		s3 = sc->s3; \
		s4 = sc->s4; \
		s5 = sc->s5; \
		s6 = sc->s6; \
		s7 = sc->s7; \
	} while (0)

/*
 * WSTATE updates the context "sc" from the state variables.
 */
#define WSTATE   do { \
		sc->s0 = s0; \
		sc->s1 = s1; \
		sc->s2 = s2; \
		sc->s3 = s3; \
		sc->s4 = s4; \
		sc->s5 = s5; \
		sc->s6 = s6; \
		sc->s7 = s7; \
	} while (0)

/*
 * Initialize a context. "olen" is the output length, in 32-bit words
 * (between 4 and 8, inclusive). "passes" is the number of passes
 * (3, 4 or 5).
 */
static void
haval_init(sph_haval_context *sc, unsigned olen, unsigned passes)
{
	sc->s0 = SPH_C32(0x243F6A88);
	sc->s1 = SPH_C32(0x85A308D3);
	sc->s2 = SPH_C32(0x13198A2E);
	sc->s3 = SPH_C32(0x03707344);
	sc->s4 = SPH_C32(0xA4093822);
	sc->s5 = SPH_C32(0x299F31D0);
	sc->s6 = SPH_C32(0x082EFA98);
	sc->s7 = SPH_C32(0xEC4E6C89);
	sc->olen = olen;
	sc->passes = passes;
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = 0;
	sc->count_low = 0;
#endif
}

/*
 * IN_PREPARE(data) contains declarations and code to prepare for
 * reading input words pointed to by "data".
 * INW(i) reads the word number "i" (from 0 to 31).
 */
#if SPH_LITTLE_FAST
#define IN_PREPARE(indata)   const unsigned char *const load_ptr = \
                             (const unsigned char *)(indata)
#define INW(i)   sph_dec32le_aligned(load_ptr + 4 * (i))
#else
#define IN_PREPARE(indata) \
	sph_u32 X_var[32]; \
	int load_index; \
 \
	for (load_index = 0; load_index < 32; load_index ++) \
		X_var[load_index] = sph_dec32le_aligned( \
			(const unsigned char *)(indata) + 4 * load_index)
#define INW(i)   X_var[i]
#endif

/*
 * Mixing operation used for 128-bit output tailoring. This function
 * takes the byte 0 from a0, byte 1 from a1, byte 2 from a2 and byte 3
 * from a3, and combines them into a 32-bit word, which is then rotated
 * to the left by n bits.
 */
static SPH_INLINE sph_u32
mix128(sph_u32 a0, sph_u32 a1, sph_u32 a2, sph_u32 a3, int n)
{
	sph_u32 tmp;

	tmp = (a0 & SPH_C32(0x000000FF))
		| (a1 & SPH_C32(0x0000FF00))
		| (a2 & SPH_C32(0x00FF0000))
		| (a3 & SPH_C32(0xFF000000));
	if (n > 0)
		tmp = SPH_ROTL32(tmp, n);
	return tmp;
}

/*
 * Mixing operation used to compute output word 0 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_0(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0x01F80000))
		| (x6 & SPH_C32(0xFE000000))
		| (x7 & SPH_C32(0x0000003F));
	return SPH_ROTL32(tmp, 13);
}

/*
 * Mixing operation used to compute output word 1 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_1(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0xFE000000))
		| (x6 & SPH_C32(0x0000003F))
		| (x7 & SPH_C32(0x00000FC0));
	return SPH_ROTL32(tmp, 7);
}

/*
 * Mixing operation used to compute output word 2 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_2(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0x0000003F))
		| (x6 & SPH_C32(0x00000FC0))
		| (x7 & SPH_C32(0x0007F000));
	return tmp;
}

/*
 * Mixing operation used to compute output word 3 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_3(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0x00000FC0))
		| (x6 & SPH_C32(0x0007F000))
		| (x7 & SPH_C32(0x01F80000));
	return tmp >> 6;
}

/*
 * Mixing operation used to compute output word 4 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_4(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0x0007F000))
		| (x6 & SPH_C32(0x01F80000))
		| (x7 & SPH_C32(0xFE000000));
	return tmp >> 12;
}

/*
 * Mixing operation used to compute output word 0 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_0(sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x6 & SPH_C32(0xFC000000)) | (x7 & SPH_C32(0x0000001F));
	return SPH_ROTL32(tmp, 6);
}

/*
 * Mixing operation used to compute output word 1 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_1(sph_u32 x6, sph_u32 x7)
{
	return (x6 & SPH_C32(0x0000001F)) | (x7 & SPH_C32(0x000003E0));
}

/*
 * Mixing operation used to compute output word 2 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_2(sph_u32 x6, sph_u32 x7)
{
	return ((x6 & SPH_C32(0x000003E0)) | (x7 & SPH_C32(0x0000FC00))) >> 5;
}

/*
 * Mixing operation used to compute output word 3 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_3(sph_u32 x6, sph_u32 x7)
{
	return ((x6 & SPH_C32(0x0000FC00)) | (x7 & SPH_C32(0x001F0000))) >> 10;
}

/*
 * Mixing operation used to compute output word 4 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_4(sph_u32 x6, sph_u32 x7)
{
	return ((x6 & SPH_C32(0x001F0000)) | (x7 & SPH_C32(0x03E00000))) >> 16;
}

/*
 * Mixing operation used to compute output word 5 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_5(sph_u32 x6, sph_u32 x7)
{
	return ((x6 & SPH_C32(0x03E00000)) | (x7 & SPH_C32(0xFC000000))) >> 21;
}

/*
 * Write out HAVAL output. The output length is tailored to the requested
 * length.
 */
static void
haval_out(sph_haval_context *sc, void *dst)
{
	DSTATE;
	unsigned char *buf;

	buf = dst;
	RSTATE;
	switch (sc->olen) {
	case 4:
		sph_enc32le(buf,      SPH_T32(s0 + mix128(s7, s4, s5, s6, 24)));
		sph_enc32le(buf + 4,  SPH_T32(s1 + mix128(s6, s7, s4, s5, 16)));
		sph_enc32le(buf + 8,  SPH_T32(s2 + mix128(s5, s6, s7, s4, 8)));
		sph_enc32le(buf + 12, SPH_T32(s3 + mix128(s4, s5, s6, s7, 0)));
		break;
	case 5:
		sph_enc32le(buf,      SPH_T32(s0 + mix160_0(s5, s6, s7)));
		sph_enc32le(buf + 4,  SPH_T32(s1 + mix160_1(s5, s6, s7)));
		sph_enc32le(buf + 8,  SPH_T32(s2 + mix160_2(s5, s6, s7)));
		sph_enc32le(buf + 12, SPH_T32(s3 + mix160_3(s5, s6, s7)));
		sph_enc32le(buf + 16, SPH_T32(s4 + mix160_4(s5, s6, s7)));
		break;
	case 6:
		sph_enc32le(buf,      SPH_T32(s0 + mix192_0(s6, s7)));
		sph_enc32le(buf + 4,  SPH_T32(s1 + mix192_1(s6, s7)));
		sph_enc32le(buf + 8,  SPH_T32(s2 + mix192_2(s6, s7)));
		sph_enc32le(buf + 12, SPH_T32(s3 + mix192_3(s6, s7)));
		sph_enc32le(buf + 16, SPH_T32(s4 + mix192_4(s6, s7)));
		sph_enc32le(buf + 20, SPH_T32(s5 + mix192_5(s6, s7)));
		break;
	case 7:
		sph_enc32le(buf,      SPH_T32(s0 + ((s7 >> 27) & 0x1F)));
		sph_enc32le(buf + 4,  SPH_T32(s1 + ((s7 >> 22) & 0x1F)));
		sph_enc32le(buf + 8,  SPH_T32(s2 + ((s7 >> 18) & 0x0F)));
		sph_enc32le(buf + 12, SPH_T32(s3 + ((s7 >> 13) & 0x1F)));
		sph_enc32le(buf + 16, SPH_T32(s4 + ((s7 >>  9) & 0x0F)));
		sph_enc32le(buf + 20, SPH_T32(s5 + ((s7 >>  4) & 0x1F)));
		sph_enc32le(buf + 24, SPH_T32(s6 + ((s7      ) & 0x0F)));
		break;
	case 8:
		sph_enc32le(buf,      s0);
		sph_enc32le(buf + 4,  s1);
		sph_enc32le(buf + 8,  s2);
		sph_enc32le(buf + 12, s3);
		sph_enc32le(buf + 16, s4);
		sph_enc32le(buf + 20, s5);
		sph_enc32le(buf + 24, s6);
		sph_enc32le(buf + 28, s7);
		break;
	}
}

/*
 * The main core functions inline the code with the COREx() macros. We
 * use a helper file, included three times, which avoids code copying.
 */

#undef PASSES
#define PASSES   3
#include "haval_helper.c"

#undef PASSES
#define PASSES   4
#include "haval_helper.c"

#undef PASSES
#define PASSES   5
#include "haval_helper.c"

/* ====================================================================== */

#define API(xxx, y) \
void \
sph_haval ## xxx ## _ ## y ## _init(void *cc) \
{ \
	haval_init(cc, xxx >> 5, y); \
} \
 \
void \
sph_haval ## xxx ## _ ## y (void *cc, const void *data, size_t len) \
{ \
	haval ## y(cc, data, len); \
} \
 \
void \
sph_haval ## xxx ## _ ## y ## _close(void *cc, void *dst) \
{ \
	haval ## y ## _close(cc, 0, 0, dst); \
} \
 \
void \
sph_haval ## xxx ## _ ## y ## addbits_and_close( \
	void *cc, unsigned ub, unsigned n, void *dst) \
{ \
	haval ## y ## _close(cc, ub, n, dst); \
}

API(128, 3)
API(128, 4)
API(128, 5)
API(160, 3)
API(160, 4)
API(160, 5)
API(192, 3)
API(192, 4)
API(192, 5)
API(224, 3)
API(224, 4)
API(224, 5)
API(256, 3)
API(256, 4)
API(256, 5)

#define RVAL   do { \
		s0 = val[0]; \
		s1 = val[1]; \
		s2 = val[2]; \
		s3 = val[3]; \
		s4 = val[4]; \
		s5 = val[5]; \
		s6 = val[6]; \
		s7 = val[7]; \
	} while (0)

#define WVAL   do { \
		val[0] = s0; \
		val[1] = s1; \
		val[2] = s2; \
		val[3] = s3; \
		val[4] = s4; \
		val[5] = s5; \
		val[6] = s6; \
		val[7] = s7; \
	} while (0)

#define INMSG(i)   msg[i]

/* see sph_haval.h */
void
sph_haval_3_comp(const sph_u32 msg[32], sph_u32 val[8])
{
	DSTATE;

	RVAL;
	CORE3(INMSG);
	WVAL;
}

/* see sph_haval.h */
void
sph_haval_4_comp(const sph_u32 msg[32], sph_u32 val[8])
{
	DSTATE;

	RVAL;
	CORE4(INMSG);
	WVAL;
}

/* see sph_haval.h */
void
sph_haval_5_comp(const sph_u32 msg[32], sph_u32 val[8])
{
	DSTATE;

	RVAL;
	CORE5(INMSG);
	WVAL;
}


#ifdef TESTING

#include <stdio.h>

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}

int main()
{
	unsigned char out[32];
	sph_haval256_3_context ctx;
	sph_haval256_3_init(&ctx);
	sph_haval256_3(&ctx, "HAVAL", 5);
	sph_haval256_3_close(&ctx, out);
	print_hex(out, 32);

	return 0;
}
#endif

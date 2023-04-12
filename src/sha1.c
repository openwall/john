/* $Id: sha1.c 216 2010-06-08 09:46:57Z tp $ */
/*
 * SHA-1 implementation.
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

#include "sha.h"

#if !HAVE_LIBCRYPTO

#include <stddef.h>
#include <string.h>

#include "sph_sha1.h"

#define F(B, C, D)     ((((C) ^ (D)) & (B)) ^ (D))
#define G(B, C, D)     ((B) ^ (C) ^ (D))
#define H(B, C, D)     (((D) & (C)) | (((D) | (C)) & (B)))
#define I(B, C, D)     G(B, C, D)

#define ROTL    SPH_ROTL32

#define K1     SPH_C32(0x5A827999)
#define K2     SPH_C32(0x6ED9EBA1)
#define K3     SPH_C32(0x8F1BBCDC)
#define K4     SPH_C32(0xCA62C1D6)

static const sph_u32 IV[5] = {
	SPH_C32(0x67452301), SPH_C32(0xEFCDAB89),
	SPH_C32(0x98BADCFE), SPH_C32(0x10325476),
	SPH_C32(0xC3D2E1F0)
};

/*
 * This macro defines the body for a SHA-1 compression function
 * implementation. The "in" parameter should evaluate, when applied to a
 * numerical input parameter from 0 to 15, to an expression which yields
 * the corresponding input block. The "r" parameter should evaluate to
 * an array or pointer expression designating the array of 5 words which
 * contains the input and output of the compression function.
 */

#define SHA1_ROUND_BODY(in, r)   do { \
		sph_u32 A, B, C, D, E; \
		sph_u32 W00, W01, W02, W03, W04, W05, W06, W07; \
		sph_u32 W08, W09, W10, W11, W12, W13, W14, W15; \
 \
		A = (r)[0]; \
		B = (r)[1]; \
		C = (r)[2]; \
		D = (r)[3]; \
		E = (r)[4]; \
 \
		W00 = in(0); \
		E = SPH_T32(ROTL(A, 5) + F(B, C, D) + E + W00 + K1); \
		B = ROTL(B, 30); \
		W01 = in(1); \
		D = SPH_T32(ROTL(E, 5) + F(A, B, C) + D + W01 + K1); \
		A = ROTL(A, 30); \
		W02 = in(2); \
		C = SPH_T32(ROTL(D, 5) + F(E, A, B) + C + W02 + K1); \
		E = ROTL(E, 30); \
		W03 = in(3); \
		B = SPH_T32(ROTL(C, 5) + F(D, E, A) + B + W03 + K1); \
		D = ROTL(D, 30); \
		W04 = in(4); \
		A = SPH_T32(ROTL(B, 5) + F(C, D, E) + A + W04 + K1); \
		C = ROTL(C, 30); \
		W05 = in(5); \
		E = SPH_T32(ROTL(A, 5) + F(B, C, D) + E + W05 + K1); \
		B = ROTL(B, 30); \
		W06 = in(6); \
		D = SPH_T32(ROTL(E, 5) + F(A, B, C) + D + W06 + K1); \
		A = ROTL(A, 30); \
		W07 = in(7); \
		C = SPH_T32(ROTL(D, 5) + F(E, A, B) + C + W07 + K1); \
		E = ROTL(E, 30); \
		W08 = in(8); \
		B = SPH_T32(ROTL(C, 5) + F(D, E, A) + B + W08 + K1); \
		D = ROTL(D, 30); \
		W09 = in(9); \
		A = SPH_T32(ROTL(B, 5) + F(C, D, E) + A + W09 + K1); \
		C = ROTL(C, 30); \
		W10 = in(10); \
		E = SPH_T32(ROTL(A, 5) + F(B, C, D) + E + W10 + K1); \
		B = ROTL(B, 30); \
		W11 = in(11); \
		D = SPH_T32(ROTL(E, 5) + F(A, B, C) + D + W11 + K1); \
		A = ROTL(A, 30); \
		W12 = in(12); \
		C = SPH_T32(ROTL(D, 5) + F(E, A, B) + C + W12 + K1); \
		E = ROTL(E, 30); \
		W13 = in(13); \
		B = SPH_T32(ROTL(C, 5) + F(D, E, A) + B + W13 + K1); \
		D = ROTL(D, 30); \
		W14 = in(14); \
		A = SPH_T32(ROTL(B, 5) + F(C, D, E) + A + W14 + K1); \
		C = ROTL(C, 30); \
		W15 = in(15); \
		E = SPH_T32(ROTL(A, 5) + F(B, C, D) + E + W15 + K1); \
		B = ROTL(B, 30); \
		W00 = ROTL(W13 ^ W08 ^ W02 ^ W00, 1); \
		D = SPH_T32(ROTL(E, 5) + F(A, B, C) + D + W00 + K1); \
		A = ROTL(A, 30); \
		W01 = ROTL(W14 ^ W09 ^ W03 ^ W01, 1); \
		C = SPH_T32(ROTL(D, 5) + F(E, A, B) + C + W01 + K1); \
		E = ROTL(E, 30); \
		W02 = ROTL(W15 ^ W10 ^ W04 ^ W02, 1); \
		B = SPH_T32(ROTL(C, 5) + F(D, E, A) + B + W02 + K1); \
		D = ROTL(D, 30); \
		W03 = ROTL(W00 ^ W11 ^ W05 ^ W03, 1); \
		A = SPH_T32(ROTL(B, 5) + F(C, D, E) + A + W03 + K1); \
		C = ROTL(C, 30); \
		W04 = ROTL(W01 ^ W12 ^ W06 ^ W04, 1); \
		E = SPH_T32(ROTL(A, 5) + G(B, C, D) + E + W04 + K2); \
		B = ROTL(B, 30); \
		W05 = ROTL(W02 ^ W13 ^ W07 ^ W05, 1); \
		D = SPH_T32(ROTL(E, 5) + G(A, B, C) + D + W05 + K2); \
		A = ROTL(A, 30); \
		W06 = ROTL(W03 ^ W14 ^ W08 ^ W06, 1); \
		C = SPH_T32(ROTL(D, 5) + G(E, A, B) + C + W06 + K2); \
		E = ROTL(E, 30); \
		W07 = ROTL(W04 ^ W15 ^ W09 ^ W07, 1); \
		B = SPH_T32(ROTL(C, 5) + G(D, E, A) + B + W07 + K2); \
		D = ROTL(D, 30); \
		W08 = ROTL(W05 ^ W00 ^ W10 ^ W08, 1); \
		A = SPH_T32(ROTL(B, 5) + G(C, D, E) + A + W08 + K2); \
		C = ROTL(C, 30); \
		W09 = ROTL(W06 ^ W01 ^ W11 ^ W09, 1); \
		E = SPH_T32(ROTL(A, 5) + G(B, C, D) + E + W09 + K2); \
		B = ROTL(B, 30); \
		W10 = ROTL(W07 ^ W02 ^ W12 ^ W10, 1); \
		D = SPH_T32(ROTL(E, 5) + G(A, B, C) + D + W10 + K2); \
		A = ROTL(A, 30); \
		W11 = ROTL(W08 ^ W03 ^ W13 ^ W11, 1); \
		C = SPH_T32(ROTL(D, 5) + G(E, A, B) + C + W11 + K2); \
		E = ROTL(E, 30); \
		W12 = ROTL(W09 ^ W04 ^ W14 ^ W12, 1); \
		B = SPH_T32(ROTL(C, 5) + G(D, E, A) + B + W12 + K2); \
		D = ROTL(D, 30); \
		W13 = ROTL(W10 ^ W05 ^ W15 ^ W13, 1); \
		A = SPH_T32(ROTL(B, 5) + G(C, D, E) + A + W13 + K2); \
		C = ROTL(C, 30); \
		W14 = ROTL(W11 ^ W06 ^ W00 ^ W14, 1); \
		E = SPH_T32(ROTL(A, 5) + G(B, C, D) + E + W14 + K2); \
		B = ROTL(B, 30); \
		W15 = ROTL(W12 ^ W07 ^ W01 ^ W15, 1); \
		D = SPH_T32(ROTL(E, 5) + G(A, B, C) + D + W15 + K2); \
		A = ROTL(A, 30); \
		W00 = ROTL(W13 ^ W08 ^ W02 ^ W00, 1); \
		C = SPH_T32(ROTL(D, 5) + G(E, A, B) + C + W00 + K2); \
		E = ROTL(E, 30); \
		W01 = ROTL(W14 ^ W09 ^ W03 ^ W01, 1); \
		B = SPH_T32(ROTL(C, 5) + G(D, E, A) + B + W01 + K2); \
		D = ROTL(D, 30); \
		W02 = ROTL(W15 ^ W10 ^ W04 ^ W02, 1); \
		A = SPH_T32(ROTL(B, 5) + G(C, D, E) + A + W02 + K2); \
		C = ROTL(C, 30); \
		W03 = ROTL(W00 ^ W11 ^ W05 ^ W03, 1); \
		E = SPH_T32(ROTL(A, 5) + G(B, C, D) + E + W03 + K2); \
		B = ROTL(B, 30); \
		W04 = ROTL(W01 ^ W12 ^ W06 ^ W04, 1); \
		D = SPH_T32(ROTL(E, 5) + G(A, B, C) + D + W04 + K2); \
		A = ROTL(A, 30); \
		W05 = ROTL(W02 ^ W13 ^ W07 ^ W05, 1); \
		C = SPH_T32(ROTL(D, 5) + G(E, A, B) + C + W05 + K2); \
		E = ROTL(E, 30); \
		W06 = ROTL(W03 ^ W14 ^ W08 ^ W06, 1); \
		B = SPH_T32(ROTL(C, 5) + G(D, E, A) + B + W06 + K2); \
		D = ROTL(D, 30); \
		W07 = ROTL(W04 ^ W15 ^ W09 ^ W07, 1); \
		A = SPH_T32(ROTL(B, 5) + G(C, D, E) + A + W07 + K2); \
		C = ROTL(C, 30); \
		W08 = ROTL(W05 ^ W00 ^ W10 ^ W08, 1); \
		E = SPH_T32(ROTL(A, 5) + H(B, C, D) + E + W08 + K3); \
		B = ROTL(B, 30); \
		W09 = ROTL(W06 ^ W01 ^ W11 ^ W09, 1); \
		D = SPH_T32(ROTL(E, 5) + H(A, B, C) + D + W09 + K3); \
		A = ROTL(A, 30); \
		W10 = ROTL(W07 ^ W02 ^ W12 ^ W10, 1); \
		C = SPH_T32(ROTL(D, 5) + H(E, A, B) + C + W10 + K3); \
		E = ROTL(E, 30); \
		W11 = ROTL(W08 ^ W03 ^ W13 ^ W11, 1); \
		B = SPH_T32(ROTL(C, 5) + H(D, E, A) + B + W11 + K3); \
		D = ROTL(D, 30); \
		W12 = ROTL(W09 ^ W04 ^ W14 ^ W12, 1); \
		A = SPH_T32(ROTL(B, 5) + H(C, D, E) + A + W12 + K3); \
		C = ROTL(C, 30); \
		W13 = ROTL(W10 ^ W05 ^ W15 ^ W13, 1); \
		E = SPH_T32(ROTL(A, 5) + H(B, C, D) + E + W13 + K3); \
		B = ROTL(B, 30); \
		W14 = ROTL(W11 ^ W06 ^ W00 ^ W14, 1); \
		D = SPH_T32(ROTL(E, 5) + H(A, B, C) + D + W14 + K3); \
		A = ROTL(A, 30); \
		W15 = ROTL(W12 ^ W07 ^ W01 ^ W15, 1); \
		C = SPH_T32(ROTL(D, 5) + H(E, A, B) + C + W15 + K3); \
		E = ROTL(E, 30); \
		W00 = ROTL(W13 ^ W08 ^ W02 ^ W00, 1); \
		B = SPH_T32(ROTL(C, 5) + H(D, E, A) + B + W00 + K3); \
		D = ROTL(D, 30); \
		W01 = ROTL(W14 ^ W09 ^ W03 ^ W01, 1); \
		A = SPH_T32(ROTL(B, 5) + H(C, D, E) + A + W01 + K3); \
		C = ROTL(C, 30); \
		W02 = ROTL(W15 ^ W10 ^ W04 ^ W02, 1); \
		E = SPH_T32(ROTL(A, 5) + H(B, C, D) + E + W02 + K3); \
		B = ROTL(B, 30); \
		W03 = ROTL(W00 ^ W11 ^ W05 ^ W03, 1); \
		D = SPH_T32(ROTL(E, 5) + H(A, B, C) + D + W03 + K3); \
		A = ROTL(A, 30); \
		W04 = ROTL(W01 ^ W12 ^ W06 ^ W04, 1); \
		C = SPH_T32(ROTL(D, 5) + H(E, A, B) + C + W04 + K3); \
		E = ROTL(E, 30); \
		W05 = ROTL(W02 ^ W13 ^ W07 ^ W05, 1); \
		B = SPH_T32(ROTL(C, 5) + H(D, E, A) + B + W05 + K3); \
		D = ROTL(D, 30); \
		W06 = ROTL(W03 ^ W14 ^ W08 ^ W06, 1); \
		A = SPH_T32(ROTL(B, 5) + H(C, D, E) + A + W06 + K3); \
		C = ROTL(C, 30); \
		W07 = ROTL(W04 ^ W15 ^ W09 ^ W07, 1); \
		E = SPH_T32(ROTL(A, 5) + H(B, C, D) + E + W07 + K3); \
		B = ROTL(B, 30); \
		W08 = ROTL(W05 ^ W00 ^ W10 ^ W08, 1); \
		D = SPH_T32(ROTL(E, 5) + H(A, B, C) + D + W08 + K3); \
		A = ROTL(A, 30); \
		W09 = ROTL(W06 ^ W01 ^ W11 ^ W09, 1); \
		C = SPH_T32(ROTL(D, 5) + H(E, A, B) + C + W09 + K3); \
		E = ROTL(E, 30); \
		W10 = ROTL(W07 ^ W02 ^ W12 ^ W10, 1); \
		B = SPH_T32(ROTL(C, 5) + H(D, E, A) + B + W10 + K3); \
		D = ROTL(D, 30); \
		W11 = ROTL(W08 ^ W03 ^ W13 ^ W11, 1); \
		A = SPH_T32(ROTL(B, 5) + H(C, D, E) + A + W11 + K3); \
		C = ROTL(C, 30); \
		W12 = ROTL(W09 ^ W04 ^ W14 ^ W12, 1); \
		E = SPH_T32(ROTL(A, 5) + I(B, C, D) + E + W12 + K4); \
		B = ROTL(B, 30); \
		W13 = ROTL(W10 ^ W05 ^ W15 ^ W13, 1); \
		D = SPH_T32(ROTL(E, 5) + I(A, B, C) + D + W13 + K4); \
		A = ROTL(A, 30); \
		W14 = ROTL(W11 ^ W06 ^ W00 ^ W14, 1); \
		C = SPH_T32(ROTL(D, 5) + I(E, A, B) + C + W14 + K4); \
		E = ROTL(E, 30); \
		W15 = ROTL(W12 ^ W07 ^ W01 ^ W15, 1); \
		B = SPH_T32(ROTL(C, 5) + I(D, E, A) + B + W15 + K4); \
		D = ROTL(D, 30); \
		W00 = ROTL(W13 ^ W08 ^ W02 ^ W00, 1); \
		A = SPH_T32(ROTL(B, 5) + I(C, D, E) + A + W00 + K4); \
		C = ROTL(C, 30); \
		W01 = ROTL(W14 ^ W09 ^ W03 ^ W01, 1); \
		E = SPH_T32(ROTL(A, 5) + I(B, C, D) + E + W01 + K4); \
		B = ROTL(B, 30); \
		W02 = ROTL(W15 ^ W10 ^ W04 ^ W02, 1); \
		D = SPH_T32(ROTL(E, 5) + I(A, B, C) + D + W02 + K4); \
		A = ROTL(A, 30); \
		W03 = ROTL(W00 ^ W11 ^ W05 ^ W03, 1); \
		C = SPH_T32(ROTL(D, 5) + I(E, A, B) + C + W03 + K4); \
		E = ROTL(E, 30); \
		W04 = ROTL(W01 ^ W12 ^ W06 ^ W04, 1); \
		B = SPH_T32(ROTL(C, 5) + I(D, E, A) + B + W04 + K4); \
		D = ROTL(D, 30); \
		W05 = ROTL(W02 ^ W13 ^ W07 ^ W05, 1); \
		A = SPH_T32(ROTL(B, 5) + I(C, D, E) + A + W05 + K4); \
		C = ROTL(C, 30); \
		W06 = ROTL(W03 ^ W14 ^ W08 ^ W06, 1); \
		E = SPH_T32(ROTL(A, 5) + I(B, C, D) + E + W06 + K4); \
		B = ROTL(B, 30); \
		W07 = ROTL(W04 ^ W15 ^ W09 ^ W07, 1); \
		D = SPH_T32(ROTL(E, 5) + I(A, B, C) + D + W07 + K4); \
		A = ROTL(A, 30); \
		W08 = ROTL(W05 ^ W00 ^ W10 ^ W08, 1); \
		C = SPH_T32(ROTL(D, 5) + I(E, A, B) + C + W08 + K4); \
		E = ROTL(E, 30); \
		W09 = ROTL(W06 ^ W01 ^ W11 ^ W09, 1); \
		B = SPH_T32(ROTL(C, 5) + I(D, E, A) + B + W09 + K4); \
		D = ROTL(D, 30); \
		W10 = ROTL(W07 ^ W02 ^ W12 ^ W10, 1); \
		A = SPH_T32(ROTL(B, 5) + I(C, D, E) + A + W10 + K4); \
		C = ROTL(C, 30); \
		W11 = ROTL(W08 ^ W03 ^ W13 ^ W11, 1); \
		E = SPH_T32(ROTL(A, 5) + I(B, C, D) + E + W11 + K4); \
		B = ROTL(B, 30); \
		W12 = ROTL(W09 ^ W04 ^ W14 ^ W12, 1); \
		D = SPH_T32(ROTL(E, 5) + I(A, B, C) + D + W12 + K4); \
		A = ROTL(A, 30); \
		W13 = ROTL(W10 ^ W05 ^ W15 ^ W13, 1); \
		C = SPH_T32(ROTL(D, 5) + I(E, A, B) + C + W13 + K4); \
		E = ROTL(E, 30); \
		W14 = ROTL(W11 ^ W06 ^ W00 ^ W14, 1); \
		B = SPH_T32(ROTL(C, 5) + I(D, E, A) + B + W14 + K4); \
		D = ROTL(D, 30); \
		W15 = ROTL(W12 ^ W07 ^ W01 ^ W15, 1); \
		A = SPH_T32(ROTL(B, 5) + I(C, D, E) + A + W15 + K4); \
		C = ROTL(C, 30); \
 \
		(r)[0] = SPH_T32(r[0] + A); \
		(r)[1] = SPH_T32(r[1] + B); \
		(r)[2] = SPH_T32(r[2] + C); \
		(r)[3] = SPH_T32(r[3] + D); \
		(r)[4] = SPH_T32(r[4] + E); \
	} while (0)

/*
 * One round of SHA-1. The data must be aligned for 32-bit access.
 */
static void
sha1_round(const unsigned char *data, sph_u32 r[5])
{
#define SHA1_IN(x)   sph_dec32be_aligned(data + (4 * (x)))
	SHA1_ROUND_BODY(SHA1_IN, r);
#undef SHA1_IN
}

/* see sph_sha1.h */
void
sph_sha1_init(void *cc)
{
	sph_sha1_context *sc;

	sc = cc;
	memcpy(sc->val, IV, sizeof IV);
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = sc->count_low = 0;
#endif
}

#define RFUN   sha1_round
#define HASH   sha1
#define BE32   1
#include "md_helper.c"

/* see sph_sha1.h */
void
sph_sha1_close(void *cc, void *dst)
{
	sha1_close(cc, dst, 5);
#if 0 /* JtR hack: our PBKDF2 code relies on hash value staying after Final */
	sph_sha1_init(cc);
#endif
}

#if 0 /* JtR hack: this would be dead code */
/* see sph_sha1.h */
void
sph_sha1_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	sha1_addbits_and_close(cc, ub, n, dst, 5);
	sph_sha1_init(cc);
}

/* see sph_sha1.h */
void
sph_sha1_comp(const sph_u32 msg[16], sph_u32 val[5])
{
#define SHA1_IN(x)   msg[x]
	SHA1_ROUND_BODY(SHA1_IN, val);
#undef SHA1_IN
}
#endif /* dead code */

#endif /* HAVE_LIBCRYPTO */

#undef INIT_D
#undef INIT_E
#define INIT_D 0x10325476
#define INIT_E 0xC3D2E1F0

void sha1_reverse(uint32_t *hash)
{
	hash[4] -= INIT_E;
	hash[4]  = (hash[4] << 2) | (hash[4] >> 30);
}

void sha1_unreverse(uint32_t *hash)
{
	hash[4]  = (hash[4] << 30) | (hash[4] >> 2);
	hash[4] += INIT_E;
}

void sha1_reverse3(uint32_t *hash)
{
	hash[3] -= INIT_D;
	hash[3]  = (hash[3] << 2) | (hash[3] >> 30);
}

void sha1_unreverse3(uint32_t *hash)
{
	hash[3]  = (hash[3] << 30) | (hash[3] >> 2);
	hash[3] += INIT_D;
}

/*
 * OpenCL RC4
 *
 * Copyright (c) 2014, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * NOTICE: After changes in headers, you probably need to drop cached
 * kernels to ensure the changes take effect.
 *
 * Some code originally had this copyright notice:
 *
 * Copyright (c) 1996-2000 Whistle Communications, Inc.
 * All rights reserved.
 *
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 *
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#ifndef _OPENCL_RC4_H
#define _OPENCL_RC4_H

#include <opencl_misc.h>

#ifndef RC4_BUFLEN
#error RC4_BUFLEN must be defined prior to including opencl_rc4.h
#endif

// None 2885 626
#define USE_IV32 // 3633 696
#define UNROLLED_RC4_KEY // 3893 817
#define UNROLLED_RC4 // 3932 848
//#define USE_LOCAL // 455 397

#ifdef USE_IV32
__constant uint rc4_iv[64] = { 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                               0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                               0x23222120, 0x27262524, 0x2b2a2928, 0x2f2e2d2c,
                               0x33323130, 0x37363534, 0x3b3a3938, 0x3f3e3d3c,
                               0x43424140, 0x47464544, 0x4b4a4948, 0x4f4e4d4c,
                               0x53525150, 0x57565554, 0x5b5a5958, 0x5f5e5d5c,
                               0x63626160, 0x67666564, 0x6b6a6968, 0x6f6e6d6c,
                               0x73727170, 0x77767574, 0x7b7a7978, 0x7f7e7d7c,
                               0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c,
                               0x93929190, 0x97969594, 0x9b9a9998, 0x9f9e9d9c,
                               0xa3a2a1a0, 0xa7a6a5a4, 0xabaaa9a8, 0xafaeadac,
                               0xb3b2b1b0, 0xb7b6b5b4, 0xbbbab9b8, 0xbfbebdbc,
                               0xc3c2c1c0, 0xc7c6c5c4, 0xcbcac9c8, 0xcfcecdcc,
                               0xd3d2d1d0, 0xd7d6d5d4, 0xdbdad9d8, 0xdfdedddc,
                               0xe3e2e1e0, 0xe7e6e5e4, 0xebeae9e8, 0xefeeedec,
                               0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc };
#endif

#if 0  /* Generic code */
typedef struct {
	uint	perm[256];
	uchar	index1;
	uchar	index2;
} rc4_state_t;

inline void swap_bytes(uint* a, uint* b)
{
	uint tmp = *a;
	*a = *b;
	*b = tmp;
}

inline void rc4_init(rc4_state_t* const state, uint *key, int keylen)
{
	uchar j;
	int i;
	const uchar* keybuf = (const uchar*)key;

	for (i = 0; i < 256; i++)
		state->perm[i] = (uint)i;
	state->index1 = 0;
	state->index2 = 0;
	for (j = i = 0; i < 256; i++) {
		j += state->perm[i] + keybuf[i & (keylen - 1)];
		swap_bytes(&state->perm[i], &state->perm[j]);
	}
}

/* Unrolled to 32-bit xor, buflen must be multiple of 4 */
inline void rc4_crypt(rc4_state_t* const state, const uint* in, uint* out, int buflen)
{
	int i;

	for (i = 0; i < buflen; i++) {
		uchar j;
		uint perm;

		state->index1++;
		state->index2 += state->perm[state->index1];
		swap_bytes(&state->perm[state->index1],
		           &state->perm[state->index2]);
		j = state->perm[state->index1] + state->perm[state->index2];
		perm = state->perm[j];
		i++;

		state->index1++;
		state->index2 += state->perm[state->index1];
		swap_bytes(&state->perm[state->index1],
		           &state->perm[state->index2]);
		j = state->perm[state->index1] + state->perm[state->index2];
		perm += state->perm[j] << 8;
		i++;

		state->index1++;
		state->index2 += state->perm[state->index1];
		swap_bytes(&state->perm[state->index1],
		           &state->perm[state->index2]);
		j = state->perm[state->index1] + state->perm[state->index2];
		perm += state->perm[j] << 16;
		i++;

		state->index1++;
		state->index2 += state->perm[state->index1];
		swap_bytes(&state->perm[state->index1],
		           &state->perm[state->index2]);
		j = state->perm[state->index1] + state->perm[state->index2];
		perm += state->perm[j] << 24;

		*out++ = *in++ ^ perm;
	}
}
#endif /* Generic BSD code */

#ifndef USE_LOCAL
#undef GETCHAR_L
#define GETCHAR_L GETCHAR
#undef PUTCHAR_L
#define PUTCHAR_L PUTCHAR
#endif

#undef swap_byte
#define swap_byte(a, b) {	  \
		uint tmp = GETCHAR_L(state, a); \
		PUTCHAR_L(state, a, GETCHAR_L(state, b)); \
		PUTCHAR_L(state, b, tmp); \
	}
#undef swap_no_inc
#define swap_no_inc(n) {	  \
		index2 = (GETCHAR(key, index1) + GETCHAR_L(state, n) + index2) & 255; \
		swap_byte(n, index2); \
	}
#undef swap_state
#define swap_state(n) {	  \
		swap_no_inc(n); \
		index1 = (index1 + 1) & 15; \
	}
#undef swap_anc_inc
#define swap_and_inc(n) {	  \
		swap_no_inc(n); \
		index1++; n++; \
	}

/*
 * One-shot RC4 with fixed keylen of 16. No byte addressed stores.
 */
inline void rc4(const uint *key,
#ifdef RC4_IN_PLACE
                uint *buf
#else
                MAYBE_CONSTANT uint *in, __global uint *out
#endif
	)
{
	uint x;
	uint y = 0;
	uint index1 = 0;
	uint index2 = 0;
#ifdef USE_LOCAL
	__local uint state_l[64][256/4];
	__local uint *state = state_l[get_local_id(0)];
#else
	uint state[256/4];
#endif

	/* RC4_init() */
#ifdef USE_IV32
	for (x = 0; x < 256/4; x++)
		state[x] = rc4_iv[x];
#else
	for (x = 0; x < 256; x++)
		PUTCHAR_L(state, x, x);
#endif

	/* RC4_set_key() */
#ifdef UNROLLED_RC4_KEY
	/* Unrolled for hard-coded key length 16 */
	for (x = 0; x < 256; x++) {
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_no_inc(x);
		index1 = 0;
	}
#else
	for (x = 0; x < 256; x++)
		swap_state(x);
#endif

	/* RC4() */
#ifdef UNROLLED_RC4
	/* Unrolled to 32-bit xor */
	for (x = 1; x <= RC4_BUFLEN; x++) {
		uint xor_word;

		y = (GETCHAR_L(state, x) + y) & 255;
		swap_byte(x, y);
		xor_word = GETCHAR_L(state, (GETCHAR_L(state, x) + GETCHAR_L(state, y)) & 255);
		x++;

		y = (GETCHAR_L(state, x) + y) & 255;
		swap_byte(x, y);
		xor_word += GETCHAR_L(state, (GETCHAR_L(state, x) + GETCHAR_L(state, y)) & 255) << 8;
		x++;

		y = (GETCHAR_L(state, x) + y) & 255;
		swap_byte(x, y);
		xor_word += GETCHAR_L(state, (GETCHAR_L(state, x) + GETCHAR_L(state, y)) & 255) << 16;
		x++;

		y = (GETCHAR_L(state, x) + y) & 255;
		swap_byte(x, y);
		xor_word += GETCHAR_L(state, (GETCHAR_L(state, x) + GETCHAR_L(state, y)) & 255) << 24;

#ifdef RC4_IN_PLACE
		*buf++ ^= xor_word;
#else
		*out++ = *in++ ^ xor_word;
#endif
	}
#else /* UNROLLED_RC4 */
	for (x = 1; x <= RC4_BUFLEN; x++) {
		y = (GETCHAR_L(state, x) + y) & 255;
		swap_byte(x, y);
#ifdef RC4_IN_PLACE
		XORCHAR(buf, x - 1, GETCHAR_L(state, (GETCHAR_L(state, x) + GETCHAR_L(state, y)) & 255));
#else
		PUTCHAR_G(out, x - 1, GETCHAR_G(in, x - 1) ^ (GETCHAR_L(state, (GETCHAR_L(state, x) + GETCHAR_L(state, y)) & 255)));
#endif
	}
#endif /* UNROLLED_RC4 */
}

#endif /* _OPENCL_RC4_H */

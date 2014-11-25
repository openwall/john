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

#if no_byte_addressable(DEVICE_INFO)
#define RC4_INT uint
#else
#define RC4_INT uchar
#define USE_IV_LUT
#endif

//#define USE_LOCAL

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
                               0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc
};

#if 0  /* Generic code */
typedef struct {
	RC4_INT	perm[256];
	uchar	index1;
	uchar	index2;
} rc4_state_t;

inline void swap_bytes(RC4_INT* a, RC4_INT* b)
{
	RC4_INT tmp = *a;
	*a = *b;
	*b = tmp;
}

inline void rc4_init(rc4_state_t* const state, uint *key, int keylen)
{
	uchar j;
	int i;
	const uchar* keybuf = (const uchar*)key;

#if USE_IV_LUT
	for (i = 0; i < 64; i++)
		((uint*)state->perm)[i] = rc4_iv[i];
#else
	for (i = 0; i < 256; i++)
		state->perm[i] = (RC4_INT)i;
#endif
	state->index1 = 0;
	state->index2 = 0;
	for (j = i = 0; i < 256; i++) {
		j += state->perm[i] + keybuf[i % keylen];
		swap_bytes(&state->perm[i], &state->perm[j]);
	}
}

/* Unrolled to 32-bit writes, buflen must be multiple of 4 */
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
		perm |= state->perm[j] << 8;
		i++;

		state->index1++;
		state->index2 += state->perm[state->index1];
		swap_bytes(&state->perm[state->index1],
		           &state->perm[state->index2]);
		j = state->perm[state->index1] + state->perm[state->index2];
		perm |= state->perm[j] << 16;
		i++;

		state->index1++;
		state->index2 += state->perm[state->index1];
		swap_bytes(&state->perm[state->index1],
		           &state->perm[state->index2]);
		j = state->perm[state->index1] + state->perm[state->index2];
		perm |= state->perm[j] << 24;

		*out++ = *in++ ^ perm;
	}
}
#endif /* Generic BSD code */

#define swap_byte(a, b) {	  \
		RC4_INT tmp = a; \
		a = b; \
		b = tmp; \
	}

#define swap_state(n) {	  \
		index2 = (key[index1] + state[(n)] + index2) & 255; \
		swap_byte(state[(n)], state[index2]); \
		index1 = (index1 + 1) & 15 /* (& 15 == % keylen) */; \
	}

/* One-shot RC4 with fixed keylen and buflen of 16 */
inline void rc4_16_16(const uint *key_w, MAYBE_CONSTANT uint *in,
                __global uint *out)
{
	const uchar *key = (uchar*)key_w;
	uint x;
	uint y = 0;
	RC4_INT index1 = 0;
	RC4_INT index2 = 0;
#ifdef USE_LOCAL
	uint lid = get_local_id(0);
#endif
#ifdef USE_IV_LUT
#ifdef USE_LOCAL
	__local uint state_w[64][64];
	__local uchar *state = (__local uchar*)state_w[lid];
#else
	uint state_w[64];
	uchar *state = (uchar*)state_w;
#endif

	/* RC4_init() */
	for (x = 0; x < 64; x++)
#ifdef USE_LOCAL
		state_w[lid][x] = rc4_iv[x];
#else
		state_w[x] = rc4_iv[x];
#endif
#else
#ifdef USE_LOCAL
	__local uint state_l[64][256];
	__local uint *state = (__local uint*)state_l[lid];
#else
	RC4_INT state[256];
#endif
	/* RC4_init() */
	for (x = 0; x < 256; x++)
		state[x] = x;
#endif

#if 0
	/* RC4_set_key() */
	for (x = 0; x < 256; x++)
		swap_state(x);
#else
	/* RC4_set_key() */
	/* Unrolled for hard-coded key length 16 */
	for (x = 0; x < 256; x++) {
		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1 = 0;
	}
#endif

	/* RC4() */
	/* Unrolled for avoiding byte-addressed stores */
	for (x = 1; x <= 16 /* length */; x++) {
		uint xor_word;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word = state[(state[x++] + state[y]) & 255];

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x++] + state[y]) & 255] << 8;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x++] + state[y]) & 255] << 16;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x] + state[y]) & 255] << 24;

		*out++ = *in++ ^ xor_word;
	}
}

/*
 * One-shot RC4 with fixed keylen of 16 and buflen of 32.
 * Decrypts buffer in-place.
 */
inline void rc4_16_32i(const uint *key_w, uint *buf)
{
	const uchar *key = (uchar*)key_w;
	uint x;
	uint y = 0;
	RC4_INT index1 = 0;
	RC4_INT index2 = 0;
#ifdef USE_LOCAL
	uint lid = get_local_id(0);
#endif
#ifdef USE_IV_LUT
#ifdef USE_LOCAL
	__local uint state_w[64][64];
	__local uchar *state = (__local uchar*)state_w[lid];
#else
	uint state_w[64];
	uchar *state = (uchar*)state_w;
#endif

	/* RC4_init() */
	for (x = 0; x < 64; x++)
#ifdef USE_LOCAL
		state_w[lid][x] = rc4_iv[x];
#else
		state_w[x] = rc4_iv[x];
#endif
#else
#ifdef USE_LOCAL
	__local uint state_l[64][256];
	__local uint *state = (__local uint*)state_l[lid];
#else
	RC4_INT state[256];
#endif
	/* RC4_init() */
	for (x = 0; x < 256; x++)
		state[x] = x;
#endif

#if 0
	/* RC4_set_key() */
	for (x = 0; x < 256; x++)
		swap_state(x);
#else
	/* RC4_set_key() */
	/* Unrolled for hard-coded key length 16 */
	for (x = 0; x < 256; x++) {
		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1 = 0;
	}
#endif

	/* RC4() */
	/* Unrolled for avoiding byte-addressed stores */
	for (x = 1; x <= 32; x++) {
		uint xor_word;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word = state[(state[x++] + state[y]) & 255];

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x++] + state[y]) & 255] << 8;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x++] + state[y]) & 255] << 16;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x] + state[y]) & 255] << 24;

		*buf++ ^= xor_word;
	}
}

#endif

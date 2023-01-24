/*
 * OpenCL RC4
 *
 * Copyright (c) 2014-2023, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * NOTICE: After changes in headers, you probably need to drop cached
 * kernels to ensure the changes take effect.
 *
 * NOTE: These function assume 32-bit aligment - no assertions!
 */

#ifndef _OPENCL_RC4_H
#define _OPENCL_RC4_H

#ifndef RC4_KEY_TYPE
#define RC4_KEY_TYPE
#endif

#ifndef RC4_IN_TYPE
#define RC4_IN_TYPE
#endif

#ifndef RC4_OUT_TYPE
#define RC4_OUT_TYPE
#endif

#include "opencl_misc.h"

#define RC4_IV32

#if !gpu_amd(DEVICE_INFO) || DEV_VER_MAJOR < 1445
/* bug in Catalyst 14.9, besides it is slower */
#define RC4_UNROLLED_KEY
#define RC4_UNROLLED
#endif

#if !defined(__OS_X__) && __GPU__ /* Actually we want discrete GPUs */
#define RC4_USE_LOCAL
#endif

typedef struct {
	uint state[256/4];
	uint x, y;
	uint len;
} RC4_CTX;

#ifdef RC4_IV32
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

#define GETCHAR_KEY(buf, index)	(((RC4_KEY_TYPE uchar*)(buf))[(index)])
#define GETCHAR_IN(buf, index)	(((RC4_IN_TYPE uchar*)(buf))[(index)])

#define PUTCHAR_OUT(buf, index, val)	PUTCHAR((RC4_OUT_TYPE uchar*)(buf), (index), (val))

#ifdef RC4_USE_LOCAL
#define GETSTATE	GETCHAR_L
#define PUTSTATE	PUTCHAR_L
#else
#define GETSTATE	GETCHAR
#define PUTSTATE	PUTCHAR
#endif

#define X8	(x & 255)
#define state	ctx->state

#undef swap_byte
#define swap_byte(a, b) {	  \
		uint tmp = GETSTATE(state, a); \
		PUTSTATE(state, a, GETSTATE(state, b)); \
		PUTSTATE(state, b, tmp); \
	}
#undef swap_no_inc
#define swap_no_inc(n) {	  \
		index2 = (GETCHAR_KEY(key, index1) + GETSTATE(state, n) + index2) & 255; \
		swap_byte(n, index2); \
	}
#undef swap_state
#define swap_state(n) {	  \
		swap_no_inc(n); \
		index1 = (index1 + 1) & 15; /* WARNING: &15 == %keylen */ \
	}
#undef swap_anc_inc
#define swap_and_inc(n) {	  \
		swap_no_inc(n); \
		index1++; n++; \
	}

/*
 * One-shot RC4 with fixed keylen of 16 but unlimited data length (len),
 * expressed in bytes but must be multiple of 4).
 */
inline void rc4_oneshot(
#ifdef RC4_USE_LOCAL
                __local
#endif
	                RC4_CTX *restrict ctx,
                const uint *restrict key,
#ifdef RC4_IN_PLACE
                uint *buf,
#else
                RC4_IN_TYPE const uint *restrict in,
                RC4_OUT_TYPE uint *restrict out,
#endif
                uint len)
{
	uint x;
	uint y = 0;
	uint index1 = 0;
	uint index2 = 0;

	/* RC4_init() */
#ifdef RC4_IV32
	for (x = 0; x < 256/4; x++)
		state[x] = rc4_iv[x];
#else
	for (x = 0; x < 256; x++)
		PUTSTATE(state, x, x);
#endif

	/* RC4_set_key() */
#ifdef RC4_UNROLLED_KEY
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
#ifdef RC4_UNROLLED
	/* Unrolled to 32-bit xor */
	for (x = 1; x <= len; x++) {
		uint xor_word;

		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
		xor_word = GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255);
		x++;

		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
		xor_word += GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255) << 8;
		x++;

		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
		xor_word += GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255) << 16;
		x++;

		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
		xor_word += GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255) << 24;

#ifdef RC4_IN_PLACE
		*buf++ ^= xor_word;
#else
		*out++ = *in++ ^ xor_word;
#endif
	}
#else /* RC4_UNROLLED */
	for (x = 1; x <= len; x++) {
		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
#ifdef RC4_IN_PLACE
		XORCHAR(buf, x - 1, GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255));
#else
		PUTCHAR_OUT(out, x - 1, GETCHAR_IN(in, x - 1) ^
		          (GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255)));
#endif
	}
#endif /* RC4_UNROLLED */
	ctx->x = x;
	ctx->y = y;
	ctx->len = len;
}

/*
 * Fixed keylen of 16.
 */
inline void rc4_set_key(
#ifdef RC4_USE_LOCAL
                __local
#endif
                RC4_CTX *restrict ctx,
                const uint *restrict key)
{
	uint x;
	uint index1 = 0;
	uint index2 = 0;

	/* RC4_init() */
#ifdef RC4_IV32
	for (x = 0; x < 256/4; x++)
		state[x] = rc4_iv[x];
#else
	for (x = 0; x < 256; x++)
		PUTSTATE(state, x, x);
#endif

	/* RC4_set_key() */
#ifdef RC4_UNROLLED_KEY
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

	ctx->x = 1;
	ctx->y = 0;
	ctx->len = 0;
}

/*
 * Used after rc4_set_key() *or* rc4_oneshot() and can be called multiple times for more data.
 * Len is given in bytes but must be multiple of 4.
 */
inline void rc4(
#ifdef RC4_USE_LOCAL
                __local
#endif
	                RC4_CTX *restrict ctx,
#ifdef RC4_IN_PLACE
                uint *buf,
#else
                RC4_IN_TYPE const uint *restrict in,
                RC4_OUT_TYPE uint *restrict out,
#endif
                uint len)
{
	uint x = ctx->x;
	uint y = ctx->y;

	len += ctx->len;

#ifdef RC4_UNROLLED
	/* Unrolled to 32-bit xor */
	for (; x <= len; x++) {
		uint xor_word;

		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
		xor_word = GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255);
		x++;

		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
		xor_word += GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255) << 8;
		x++;

		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
		xor_word += GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255) << 16;
		x++;

		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
		xor_word += GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255) << 24;

#ifdef RC4_IN_PLACE
		*buf++ ^= xor_word;
#else
		*out++ = *in++ ^ xor_word;
#endif
	}
#else /* RC4_UNROLLED */
#ifdef RC4_IN_PLACE
	buf -= x / 4;
#else
	out -= x / 4;
	in -= x / 4;
#endif
	for (; x <= len; x++) {
		y = (GETSTATE(state, X8) + y) & 255;
		swap_byte(X8, y);
#ifdef RC4_IN_PLACE
		XORCHAR(buf, x - 1, GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255));
#else
		PUTCHAR_OUT(out, x - 1, GETCHAR_IN(in, x - 1) ^
		          (GETSTATE(state, (GETSTATE(state, X8) + GETSTATE(state, y)) & 255)));
#endif
	}
#endif /* RC4_UNROLLED */
	ctx->x = x;
	ctx->y = y;
	ctx->len = len;
}

#undef state
#undef X8

#endif /* _OPENCL_RC4_H */

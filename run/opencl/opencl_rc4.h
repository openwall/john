/*
 * OpenCL RC4
 *
 * Copyright (c) 2014-2024, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * These functions assume 32-bit aligment - no assertions!
 *
 * NOTE: After changes, you probably need to drop cached kernels to
 * ensure the changes take effect: "make kernel-cache-clean"
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

#define lid     get_local_id(0)

#if __GPU__
#define RC4_USE_LOCAL
#if gpu_amd(DEVICE_INFO)
#define MAX_LOCAL_RC4	64
#define COALESCE_IDX8(i)  (((i) & 3) + (((i) / 4) * 128) + ((lid & 31) * 4) + ((lid / 32) * 8192))
#define COALESCE_IDX32(i) (((i) * 32) + (lid & 31) + ((lid / 32) * 2048))
#else
#define MAX_LOCAL_RC4	32
#define COALESCE_IDX8(i)  (((i) & 3) + (((i) / 4) * 128) + (lid * 4))
#define COALESCE_IDX32(i) (((i) * 32) + lid)
#endif
#endif

#define GETCHAR_KEY(buf, index)	(((RC4_KEY_TYPE uchar*)(buf))[(index)])
#define GETCHAR_IN(buf, index)	(((RC4_IN_TYPE uchar*)(buf))[(index)])

#ifdef RC4_USE_LOCAL
typedef struct {
	uint state[MAX_LOCAL_RC4 * 256/4];
	uint x[MAX_LOCAL_RC4];
	uint y[MAX_LOCAL_RC4];
	uint len[MAX_LOCAL_RC4];
} RC4_CTX;
#define GETSTATE(i)      GETCHAR_L(ctx->state, COALESCE_IDX8(i))
#define PUTSTATE(i, v)   PUTCHAR_L(ctx->state, COALESCE_IDX8(i), v)
#define PUTSTATE32(i, v) ctx->state[COALESCE_IDX32(i)] = v
#define STATE(var)       ctx->var[lid]

#else
typedef struct {
	uint state[256/4];
	uint x;
	uint y;
	uint len;
} RC4_CTX;
#define GETSTATE(i)      GETCHAR(ctx->state, i)
#define PUTSTATE(i, v)   PUTCHAR(ctx->state, i, v)
#define PUTSTATE32(i, v) ctx->state[i] = v
#define STATE(var)       ctx->var
#endif

#undef swap_byte
#define swap_byte(a, b) {	  \
		uint tmp = GETSTATE(a); \
		PUTSTATE(a, GETSTATE(b)); \
		PUTSTATE(b, tmp); \
	}
#undef swap_no_inc
#define swap_no_inc(n) {	  \
		index2 = (GETCHAR_KEY(key, index1) + GETSTATE(n) + index2) & 255; \
		swap_byte(n, index2); \
	}
#undef swap_state
#define swap_state(n) {	  \
		swap_no_inc(n); \
		if (++index1 == keylen) index1 = 0; \
	}
#undef swap_anc_inc
#define swap_and_inc(n) {	  \
		swap_no_inc(n); \
		index1++; n++; \
	}

/*
 * Set IV.  Clever, compact 32-bit implementation nicked from hashcat, replacing
 * the (also 32-bit) constant array we had.  No difference in speed though.
 */
INLINE void rc4_init(
#ifdef RC4_USE_LOCAL
                __local
#endif
                RC4_CTX *restrict ctx)
{
	uint v = 0x03020100;
	const uint a = 0x04040404;

	for (uint i = 0; i < 256/4; i++, v += a)
		PUTSTATE32(i, v);
}

/*
 * Arbitrary length key
 */
INLINE void rc4_set_key(
#ifdef RC4_USE_LOCAL
                __local
#endif
                RC4_CTX *restrict ctx,
                const uint keylen,
                const uint *restrict key)
{
	rc4_init(ctx);

	uint index1 = 0;
	uint index2 = 0;

	for (uint x = 0; x < 256; x++)
		swap_state(x);

	STATE(x) = 1;
	STATE(y) = 0;
	STATE(len) = 0;
}

/*
 * Unrolled fixed keylen of 5 (40-bit).
 */
INLINE void rc4_40_set_key(
#ifdef RC4_USE_LOCAL
                __local
#endif
                RC4_CTX *restrict ctx,
                const uint *restrict key)
{
	rc4_init(ctx);

	uint index1 = 0;
	uint index2 = 0;

	for (uint x = 0; x < 255; x++) {
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_and_inc(x);
		swap_no_inc(x);
		index1 = 0;
	}
	swap_no_inc(255);

	STATE(x) = 1;
	STATE(y) = 0;
	STATE(len) = 0;
}

/*
 * Unrolled fixed keylen of 16 (128-bit).
 */
INLINE void rc4_128_set_key(
#ifdef RC4_USE_LOCAL
                __local
#endif
                RC4_CTX *restrict ctx,
                const uint *restrict key)
{
	rc4_init(ctx);

	uint index1 = 0;
	uint index2 = 0;

	for (uint x = 0; x < 256; x++) {
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

	STATE(x) = 1;
	STATE(y) = 0;
	STATE(len) = 0;
}

#define X8      (x & 255)

/*
 * Len is given in bytes but must be multiple of 4.
 */
INLINE void rc4(
#ifdef RC4_USE_LOCAL
                __local
#endif
	                RC4_CTX *restrict ctx,
                RC4_IN_TYPE const uint *in,
                RC4_OUT_TYPE uint *out,
                uint len)
{
	uint x = STATE(x);
	uint y = STATE(y);

	len += STATE(len);

	/* Unrolled to 32-bit xor */
	for (; x <= len; x++) {
		uint xor_word;

		y = (GETSTATE(X8) + y) & 255;
		swap_byte(X8, y);
		xor_word = GETSTATE((GETSTATE(X8) + GETSTATE(y)) & 255);
		x++;

		y = (GETSTATE(X8) + y) & 255;
		swap_byte(X8, y);
		xor_word += GETSTATE((GETSTATE(X8) + GETSTATE(y)) & 255) << 8;
		x++;

		y = (GETSTATE(X8) + y) & 255;
		swap_byte(X8, y);
		xor_word += GETSTATE((GETSTATE(X8) + GETSTATE(y)) & 255) << 16;
		x++;

		y = (GETSTATE(X8) + y) & 255;
		swap_byte(X8, y);
		xor_word += GETSTATE((GETSTATE(X8) + GETSTATE(y)) & 255) << 24;

		*out++ = *in++ ^ xor_word;
	}

	STATE(x) = x;
	STATE(y) = y;
	STATE(len) = len;
}

#undef X8

#endif /* _OPENCL_RC4_H */

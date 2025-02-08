/*
 * This software is Copyright 2022 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#define STREEBOG512             1
#include "opencl_streebog.h"

#define SALT_LENGTH                 16
#define BINARY_SIZE					64

typedef struct {
	uint len;
	uchar key[PLAINTEXT_LENGTH];
} inbuf;

typedef struct {
	uint rounds;
	uint len;
	uchar salt[SALT_LENGTH];
} saltstruct;

typedef struct {
	uchar p_bytes[PLAINTEXT_LENGTH];
	uchar s_bytes[SALT_LENGTH];
} statebuf;

__kernel void gost12512init(__global inbuf *in,
                            MAYBE_CONSTANT saltstruct *ssalt,
                            __global statebuf *state,
                            __local localbuf *loc_buf,
                            __global uint512_u *out)
{
	GOST34112012Context ctx;
	GOST34112012Context alt_ctx;
	uint512_u result;
	uint512_u temp_result;
	uint gid = get_global_id(0);
	uint cnt;
	uint len = in[gid].len;
	uint saltlen = ssalt->len;
	uchar *cp;
	uchar p_bytes[PLAINTEXT_LENGTH];
	uchar s_bytes[SALT_LENGTH];
	uchar key[PLAINTEXT_LENGTH];
	uchar salt[SALT_LENGTH];

#if STREEBOG_LOCAL_AX
	uint ls = get_local_size(0);
	uint lid = get_local_id(0);

	for (uint i = lid; i < 256; i += ls) {
#if STREEBOG_LOCAL_C
		if (i < 12)
			loc_buf->C[i].VWORD = C[i].VWORD;
#endif
		for (uint j = 0; j < 8; j++)
			loc_buf->Ax[j][i] = Ax[j][i];
	}
	barrier(CLK_LOCAL_MEM_FENCE);
#endif

	/* Copy to private memory */
	memcpy_gp(key, in[gid].key, len);
	memcpy_mcp(salt, ssalt->salt, saltlen);

	/* Prepare for the real work. */
	GOST34112012Init(&ctx, 512);

	/* Add the key string. */
	GOST34112012Update(&ctx, key, len, loc_buf);

	/* The last part is the salt string.  This must be at most 16
	   characters and it ends at the first `$' character (for
	   compatibility with existing implementations). */
	GOST34112012Update(&ctx, salt, saltlen, loc_buf);


	/* Compute alternate Streebog sum with input KEY, SALT, and KEY.  The
	   final result will be added to the first context. */
	GOST34112012Init(&alt_ctx, 512);

	/* Add key. */
	GOST34112012Update(&alt_ctx, key, len, loc_buf);

	/* Add salt. */
	GOST34112012Update(&alt_ctx, salt, saltlen, loc_buf);

	/* Add key again. */
	GOST34112012Update(&alt_ctx, key, len, loc_buf);

	/* Now get result of this (64 bytes) and add it to the other
	   context. */
	GOST34112012Final(&alt_ctx, &result, loc_buf);

	/* Add for any character in the key one byte of the alternate sum. */
#if PLAINTEXT_LENGTH > BINARY_SIZE
	for (cnt = len; cnt > BINARY_SIZE; cnt -= BINARY_SIZE)
		GOST34112012Update(&ctx, result.BYTES, BINARY_SIZE, loc_buf);
#else
	cnt = len;
#endif
	GOST34112012Update(&ctx, result.BYTES, cnt, loc_buf);

	/* Take the binary representation of the length of the key and for every
	   1 add the alternate sum, for every 0 the key. */
	for (cnt = len; cnt > 0; cnt >>= 1)
		if ((cnt & 1) != 0)
			GOST34112012Update(&ctx, result.BYTES, BINARY_SIZE, loc_buf);
		else
			GOST34112012Update(&ctx, key, len, loc_buf);

	/* Create intermediate result. */
	GOST34112012Final(&ctx, &result, loc_buf);

	/* Start computation of P byte sequence. */
	GOST34112012Init(&alt_ctx, 512);

	/* For every character in the password add the entire password. */
	for (cnt = 0; cnt < len; ++cnt)
		GOST34112012Update(&alt_ctx, key, len, loc_buf);

	/* Finish the digest. */
	GOST34112012Final(&alt_ctx, &temp_result, loc_buf);

	/* Create byte sequence P. */
	cp = p_bytes;
#if PLAINTEXT_LENGTH > BINARY_SIZE
	for (cnt = len; cnt > BINARY_SIZE; cnt -= BINARY_SIZE) {
		memcpy_pp(cp, &temp_result, BINARY_SIZE);
		cp += BINARY_SIZE;
	}
#else
	cnt = len;
#endif
	memcpy_pp(cp, &temp_result, cnt);

	/* Start computation of S byte sequence. */
	GOST34112012Init(&alt_ctx, 512);

	/* repeat the following 16+A[0] times, where A[0] represents the
	   first byte in digest A interpreted as an 8-bit uvalue */
	for (cnt = 0; cnt < 16 + result.BYTES[0]; ++cnt)
		GOST34112012Update(&alt_ctx, salt, saltlen, loc_buf);

	/* Finish the digest. */
	GOST34112012Final(&alt_ctx, &temp_result, loc_buf);

	/* Create byte sequence S. */
	cp = s_bytes;
#if SALT_LENGTH > BINARY_SIZE
	for (cnt = saltlen; cnt > BINARY_SIZE; cnt -= BINARY_SIZE) {
		memcpy_pp(cp, &temp_result, BINARY_SIZE);
		cp += BINARY_SIZE;
	}
#else
	cnt = saltlen;
#endif
	memcpy_pp(cp, &temp_result, cnt);

	/* Here's everything we need for the loop kernel */
	memcpy512(&(out[gid]), &(result));
	memcpy_pg(state[gid].p_bytes, p_bytes, len);
	memcpy_pg(state[gid].s_bytes, s_bytes, saltlen);
}

__kernel void gost12512loop(__global inbuf *in,
                            MAYBE_CONSTANT saltstruct *ssalt,
                            __global statebuf *state,
                            __local localbuf *loc_buf,
                            __global uint512_u *out)
{
	GOST34112012Context ctx;
	uint512_u result;
	uint gid = get_global_id(0);
	uchar p_bytes[PLAINTEXT_LENGTH];
	uchar s_bytes[SALT_LENGTH];

	uint cnt;
	uint saltlen = ssalt->len;
	uint len = in[gid].len;

	memcpy512(&(result), &(out[gid]));
	memcpy_gp(p_bytes, state[gid].p_bytes, len);
	memcpy_gp(s_bytes, state[gid].s_bytes, saltlen);

#if STREEBOG_LOCAL_AX
	uint ls = get_local_size(0);
	uint lid = get_local_id(0);

	for (uint i = lid; i < 256; i += ls) {
#if STREEBOG_LOCAL_C
		if (i < 12)
			loc_buf->C[i].VWORD = C[i].VWORD;
#endif
		for (uint j = 0; j < 8; j++)
			loc_buf->Ax[j][i] = Ax[j][i];
	}
	barrier(CLK_LOCAL_MEM_FENCE);
#endif

	/* Repeatedly run the collected hash value through Streebog to burn CPU cycles.  */
	for (cnt = 0; cnt < HASH_LOOPS; ++cnt) {
		/* New context. */
		GOST34112012Init(&ctx, 512);

		/* Add key or last result. */
		if (cnt & 1)
			GOST34112012Update(&ctx, p_bytes, len, loc_buf);
		else
			GOST34112012Update(&ctx, result.BYTES, BINARY_SIZE, loc_buf);

		/* Add salt for numbers not divisible by 3. */
		if (cnt % 3)
			GOST34112012Update(&ctx, s_bytes, saltlen, loc_buf);

		/* Add key for numbers not divisible by 7. */
		if (cnt % 7)
			GOST34112012Update(&ctx, p_bytes, len, loc_buf);

		/* Add key or last result. */
		if (cnt & 1)
			GOST34112012Update(&ctx, result.BYTES, BINARY_SIZE, loc_buf);
		else
			GOST34112012Update(&ctx, p_bytes, len, loc_buf);

		/* Create intermediate result. */
		GOST34112012Final(&ctx, &result, loc_buf);
	}

	memcpy512(&(out[gid]), &(result));
}

__kernel void gost12512final(__global inbuf *in,
                            MAYBE_CONSTANT saltstruct *ssalt,
                            __global statebuf *state,
                            __local localbuf *loc_buf,
                            __global uint512_u *out)
{
	GOST34112012Context ctx;
	uint512_u result;
	uint gid = get_global_id(0);
	uchar p_bytes[PLAINTEXT_LENGTH];
	uchar s_bytes[SALT_LENGTH];
	uint saltlen, len;
	uint cnt;

	uint rounds = ssalt->rounds % HASH_LOOPS;

	memcpy512(&(result), &(out[gid]));

	if (rounds) {
		saltlen = ssalt->len;
		len = in[gid].len;
		memcpy_gp(p_bytes, state[gid].p_bytes, len);
		memcpy_gp(s_bytes, state[gid].s_bytes, saltlen);

#if STREEBOG_LOCAL_AX
		uint ls = get_local_size(0);
		uint lid = get_local_id(0);

		for (uint i = lid; i < 256; i += ls) {
#if STREEBOG_LOCAL_C
			if (i < 12)
				loc_buf->C[i].VWORD = C[i].VWORD;
#endif
			for (uint j = 0; j < 8; j++)
				loc_buf->Ax[j][i] = Ax[j][i];
		}
		barrier(CLK_LOCAL_MEM_FENCE);
#endif
	}

	/* Repeatedly run the collected hash value through Streebog to burn CPU cycles.  */
	for (cnt = 0; cnt < rounds; ++cnt) {
		/* New context. */
		GOST34112012Init(&ctx, 512);

		/* Add key or last result. */
		if (cnt & 1)
			GOST34112012Update(&ctx, p_bytes, len, loc_buf);
		else
			GOST34112012Update(&ctx, result.BYTES, BINARY_SIZE, loc_buf);

		/* Add salt for numbers not divisible by 3. */
		if (cnt % 3)
			GOST34112012Update(&ctx, s_bytes, saltlen, loc_buf);

		/* Add key for numbers not divisible by 7. */
		if (cnt % 7)
			GOST34112012Update(&ctx, p_bytes, len, loc_buf);

		/* Add key or last result. */
		if (cnt & 1)
			GOST34112012Update(&ctx, result.BYTES, BINARY_SIZE, loc_buf);
		else
			GOST34112012Update(&ctx, p_bytes, len, loc_buf);

		/* Create intermediate result. */
		GOST34112012Final(&ctx, &result, loc_buf);
	}

	memcpy512(&(out[gid]), &(result));
}

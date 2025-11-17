/*
 * This software is Copyright 2025 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#include "opencl_sm3.h"

#define SALT_LENGTH     16
#define BINARY_SIZE     SM3_HASH_LENGTH

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

typedef struct {
	uint v[BINARY_SIZE / sizeof(uint)];
} outbuf;

__kernel void sm3crypt_init(__global inbuf *in,
                            MAYBE_CONSTANT saltstruct *ssalt,
                            __global statebuf *state,
                            __global outbuf *out)
{
	sm3_ctx ctx;
	sm3_ctx alt_ctx;
	uchar result[BINARY_SIZE];
	uchar temp_result[BINARY_SIZE];
	uint gid = get_global_id(0);
	uint cnt;
	uint len = in[gid].len;
	uint saltlen = ssalt->len;
	uchar *cp;
	uchar p_bytes[PLAINTEXT_LENGTH];
	uchar s_bytes[SALT_LENGTH];
	uchar key[PLAINTEXT_LENGTH];
	uchar salt[SALT_LENGTH];

	/* Copy to private memory */
	memcpy_gp(key, in[gid].key, len);
	memcpy_mcp(salt, ssalt->salt, saltlen);

	/* Prepare for the real work. */
	sm3_init(&ctx);

	/* Add the key string. */
	sm3_update(&ctx, key, len);

	/* The last part is the salt string.  This must be at most 16
	   characters and it ends at the first `$' character (for
	   compatibility with existing implementations). */
	sm3_update(&ctx, salt, saltlen);


	/* Compute alternate SM3 sum with input KEY, SALT, and KEY.  The
	   final result will be added to the first context. */
	sm3_init(&alt_ctx);

	/* Add key. */
	sm3_update(&alt_ctx, key, len);

	/* Add salt. */
	sm3_update(&alt_ctx, salt, saltlen);

	/* Add key again. */
	sm3_update(&alt_ctx, key, len);

	/* Now get result of this (32 bytes) and add it to the other
	   context. */
	sm3_final(&alt_ctx, result);

	/* Add for any character in the key one byte of the alternate sum. */
#if PLAINTEXT_LENGTH > BINARY_SIZE
	for (cnt = len; cnt > BINARY_SIZE; cnt -= BINARY_SIZE)
		sm3_update(&ctx, result, BINARY_SIZE);
#else
	cnt = len;
#endif
	sm3_update(&ctx, result, cnt);

	/* Take the binary representation of the length of the key and for every
	   1 add the alternate sum, for every 0 the key. */
	for (cnt = len; cnt > 0; cnt >>= 1)
		if ((cnt & 1) != 0)
			sm3_update(&ctx, result, BINARY_SIZE);
		else
			sm3_update(&ctx, key, len);

	/* Create intermediate result. */
	sm3_final(&ctx, result);

	/* Start computation of P byte sequence. */
	sm3_init(&alt_ctx);

	/* For every character in the password add the entire password. */
	for (cnt = 0; cnt < len; ++cnt)
		sm3_update(&alt_ctx, key, len);

	/* Finish the digest. */
	sm3_final(&alt_ctx, temp_result);

	/* Create byte sequence P. */
	cp = p_bytes;
#if PLAINTEXT_LENGTH > BINARY_SIZE
	for (cnt = len; cnt > BINARY_SIZE; cnt -= BINARY_SIZE) {
		memcpy_pp(cp, temp_result, BINARY_SIZE);
		cp += BINARY_SIZE;
	}
#else
	cnt = len;
#endif
	memcpy_pp(cp, temp_result, cnt);

	/* Start computation of S byte sequence. */
	sm3_init(&alt_ctx);

	/* repeat the following 16+A[0] times, where A[0] represents the
	   first byte in digest A interpreted as an 8-bit uvalue */
	for (cnt = 0; cnt < 16 + result[0]; ++cnt)
		sm3_update(&alt_ctx, salt, saltlen);

	/* Finish the digest. */
	sm3_final(&alt_ctx, temp_result);

	/* Create byte sequence S. */
	cp = s_bytes;
#if SALT_LENGTH > BINARY_SIZE
	for (cnt = saltlen; cnt > BINARY_SIZE; cnt -= BINARY_SIZE) {
		memcpy_pp(cp, temp_result, BINARY_SIZE);
		cp += BINARY_SIZE;
	}
#else
	cnt = saltlen;
#endif
	memcpy_pp(cp, temp_result, cnt);

	/* Here's everything we need for the loop kernel */
	memcpy_pg(out[gid].v, result, sizeof(result));
	memcpy_pg(state[gid].p_bytes, p_bytes, len);
	memcpy_pg(state[gid].s_bytes, s_bytes, saltlen);
}

__kernel void sm3crypt_loop(__global inbuf *in,
                            MAYBE_CONSTANT saltstruct *ssalt,
                            __global statebuf *state,
                            __global outbuf *out)
{
	sm3_ctx ctx;
	uchar result[BINARY_SIZE];
	uint gid = get_global_id(0);
	uchar p_bytes[PLAINTEXT_LENGTH];
	uchar s_bytes[SALT_LENGTH];
	uint cnt;
	uint saltlen = ssalt->len;
	uint len = in[gid].len;

	memcpy_gp(result, out[gid].v, sizeof(result));
	memcpy_gp(p_bytes, state[gid].p_bytes, len);
	memcpy_gp(s_bytes, state[gid].s_bytes, saltlen);

	/* Repeatedly run the collected hash value through SM3 to burn CPU cycles. */
	for (cnt = 0; cnt < HASH_LOOPS; ++cnt) {
		/* New context. */
		sm3_init(&ctx);

		/* Add key or last result. */
		if (cnt & 1)
			sm3_update(&ctx, p_bytes, len);
		else
			sm3_update(&ctx, result, BINARY_SIZE);

		/* Add salt for numbers not divisible by 3. */
		if (cnt % 3)
			sm3_update(&ctx, s_bytes, saltlen);

		/* Add key for numbers not divisible by 7. */
		if (cnt % 7)
			sm3_update(&ctx, p_bytes, len);

		/* Add key or last result. */
		if (cnt & 1)
			sm3_update(&ctx, result, BINARY_SIZE);
		else
			sm3_update(&ctx, p_bytes, len);

		/* Create intermediate result. */
		sm3_final(&ctx, result);
	}

	memcpy_pg(out[gid].v, result, sizeof(result));
}

__kernel void sm3crypt_final(__global inbuf *in,
                            MAYBE_CONSTANT saltstruct *ssalt,
                            __global statebuf *state,
                            __global outbuf *out)
{
	sm3_ctx ctx;
	uchar result[BINARY_SIZE];
	uint gid = get_global_id(0);
	uchar p_bytes[PLAINTEXT_LENGTH];
	uchar s_bytes[SALT_LENGTH];
	uint saltlen, len;
	uint cnt;
	uint rounds = ssalt->rounds % HASH_LOOPS;

	memcpy_gp(result, out[gid].v, sizeof(result));

	if (rounds) {
		saltlen = ssalt->len;
		len = in[gid].len;
		memcpy_gp(p_bytes, state[gid].p_bytes, len);
		memcpy_gp(s_bytes, state[gid].s_bytes, saltlen);
	}

	/* Repeatedly run the collected hash value through SM3 to burn CPU cycles. */
	for (cnt = 0; cnt < rounds; ++cnt) {
		/* New context. */
		sm3_init(&ctx);

		/* Add key or last result. */
		if (cnt & 1)
			sm3_update(&ctx, p_bytes, len);
		else
			sm3_update(&ctx, result, BINARY_SIZE);

		/* Add salt for numbers not divisible by 3. */
		if (cnt % 3)
			sm3_update(&ctx, s_bytes, saltlen);

		/* Add key for numbers not divisible by 7. */
		if (cnt % 7)
			sm3_update(&ctx, p_bytes, len);

		/* Add key or last result. */
		if (cnt & 1)
			sm3_update(&ctx, result, BINARY_SIZE);
		else
			sm3_update(&ctx, p_bytes, len);

		/* Create intermediate result. */
		sm3_final(&ctx, result);
	}

	memcpy_pg(out[gid].v, result, sizeof(result));
}

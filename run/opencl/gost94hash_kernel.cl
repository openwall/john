/*
 * This software is Copyright 2022 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"

#if gpu(DEVICE_INFO)
#define GOST94_USE_LOCAL      1
#endif
#define GOST94_FLAT_INIT      1
#include "opencl_gost94.h"

#define SALT_LENGTH           16
#define BINARY_SIZE           32

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

__kernel void gost94init(__global inbuf *in,
                         MAYBE_CONSTANT saltstruct *ssalt,
                         __global statebuf *state,
                         __local rhash_gost94_sbox *sbox_ptr,
                         __global outbuf *out)
{
	gost94_ctx ctx;
	gost94_ctx alt_ctx;
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
#if !GOST94_USE_LOCAL
	rhash_gost94_sbox sbox_buf;
#define sbox &sbox_buf
#else
#define sbox sbox_ptr
#endif

	gost94_init_table(sbox);

	/* Copy to private memory */
	memcpy_gp(key, in[gid].key, len);
	memcpy_mcp(salt, ssalt->salt, saltlen);

	/* Prepare for the real work. */
	gost94_init(&ctx);

	/* Add the key string. */
	gost94_update(&ctx, key, len, sbox);

	/* The last part is the salt string.  This must be at most 16
	   characters and it ends at the first `$' character (for
	   compatibility with existing implementations). */
	gost94_update(&ctx, salt, saltlen, sbox);


	/* Compute alternate GOST94 sum with input KEY, SALT, and KEY.  The
	   final result will be added to the first context. */
	gost94_init(&alt_ctx);

	/* Add key. */
	gost94_update(&alt_ctx, key, len, sbox);

	/* Add salt. */
	gost94_update(&alt_ctx, salt, saltlen, sbox);

	/* Add key again. */
	gost94_update(&alt_ctx, key, len, sbox);

	/* Now get result of this (32 bytes) and add it to the other
	   context. */
	gost94_final(&alt_ctx, result, sbox);

	/* Add for any character in the key one byte of the alternate sum. */
#if PLAINTEXT_LENGTH > BINARY_SIZE
	for (cnt = len; cnt > BINARY_SIZE; cnt -= BINARY_SIZE)
		gost94_update(&ctx, result, BINARY_SIZE, sbox);
#else
	cnt = len;
#endif
	gost94_update(&ctx, result, cnt, sbox);

	/* Take the binary representation of the length of the key and for every
	   1 add the alternate sum, for every 0 the key. */
	for (cnt = len; cnt > 0; cnt >>= 1)
		if ((cnt & 1) != 0)
			gost94_update(&ctx, result, BINARY_SIZE, sbox);
		else
			gost94_update(&ctx, key, len, sbox);

	/* Create intermediate result. */
	gost94_final(&ctx, result, sbox);

	/* Start computation of P byte sequence. */
	gost94_init(&alt_ctx);

	/* For every character in the password add the entire password. */
	for (cnt = 0; cnt < len; ++cnt)
		gost94_update(&alt_ctx, key, len, sbox);

	/* Finish the digest. */
	gost94_final(&alt_ctx, temp_result, sbox);

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
	gost94_init(&alt_ctx);

	/* repeat the following 16+A[0] times, where A[0] represents the
	   first byte in digest A interpreted as an 8-bit uvalue */
	for (cnt = 0; cnt < 16 + result[0]; ++cnt)
		gost94_update(&alt_ctx, salt, saltlen, sbox);

	/* Finish the digest. */
	gost94_final(&alt_ctx, temp_result, sbox);

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
	memcpy_pg(out[gid].v, result, BINARY_SIZE);
	memcpy_pg(state[gid].p_bytes, p_bytes, len);
	memcpy_pg(state[gid].s_bytes, s_bytes, saltlen);
}

__kernel void gost94loop(__global inbuf *in,
                         MAYBE_CONSTANT saltstruct *ssalt,
                         __global statebuf *state,
                         __local rhash_gost94_sbox *sbox_ptr,
                         __global outbuf *out)
{
	gost94_ctx ctx;
	uchar result[BINARY_SIZE];
	uint gid = get_global_id(0);
	uchar p_bytes[PLAINTEXT_LENGTH];
	uchar s_bytes[SALT_LENGTH];
#if !GOST94_USE_LOCAL
	rhash_gost94_sbox sbox_buf;
#define sbox &sbox_buf
#else
#define sbox sbox_ptr
#endif

	gost94_init_table(sbox);

	uint cnt;
	uint saltlen = ssalt->len;
	uint len = in[gid].len;

	memcpy_gp(result, out[gid].v, BINARY_SIZE);
	memcpy_gp(p_bytes, state[gid].p_bytes, len);
	memcpy_gp(s_bytes, state[gid].s_bytes, saltlen);

	/* Repeatedly run the collected hash value through GOST94 to burn CPU cycles.  */
	for (cnt = 0; cnt < HASH_LOOPS; ++cnt) {
		/* New context. */
		gost94_init(&ctx);

		/* Add key or last result. */
		if (cnt & 1)
			gost94_update(&ctx, p_bytes, len, sbox);
		else
			gost94_update(&ctx, result, BINARY_SIZE, sbox);

		/* Add salt for numbers not divisible by 3. */
		if (cnt % 3)
			gost94_update(&ctx, s_bytes, saltlen, sbox);

		/* Add key for numbers not divisible by 7. */
		if (cnt % 7)
			gost94_update(&ctx, p_bytes, len, sbox);

		/* Add key or last result. */
		if (cnt & 1)
			gost94_update(&ctx, result, BINARY_SIZE, sbox);
		else
			gost94_update(&ctx, p_bytes, len, sbox);

		/* Create intermediate result. */
		gost94_final(&ctx, result, sbox);
	}

	memcpy_pg(out[gid].v, result, BINARY_SIZE);
}

__kernel void gost94final(__global inbuf *in,
                          MAYBE_CONSTANT saltstruct *ssalt,
                          __global statebuf *state,
                          __local rhash_gost94_sbox *sbox_ptr,
                          __global outbuf *out)
{
	gost94_ctx ctx;
	uchar result[BINARY_SIZE];
	uint gid = get_global_id(0);
	uchar p_bytes[PLAINTEXT_LENGTH];
	uchar s_bytes[SALT_LENGTH];
	uint saltlen, len;
	uint cnt;
	uint rounds = ssalt->rounds % HASH_LOOPS;
#if !GOST94_USE_LOCAL
	rhash_gost94_sbox sbox_buf;
#define sbox &sbox_buf
#else
#define sbox sbox_ptr
#endif

	memcpy_gp(result, out[gid].v, BINARY_SIZE);

	if (rounds) {
		gost94_init_table(sbox);
		saltlen = ssalt->len;
		len = in[gid].len;
		memcpy_gp(p_bytes, state[gid].p_bytes, len);
		memcpy_gp(s_bytes, state[gid].s_bytes, saltlen);
	}

	/* Repeatedly run the collected hash value through GOST94 to burn CPU cycles.  */
	for (cnt = 0; cnt < rounds; ++cnt) {
		/* New context. */
		gost94_init(&ctx);

		/* Add key or last result. */
		if (cnt & 1)
			gost94_update(&ctx, p_bytes, len, sbox);
		else
			gost94_update(&ctx, result, BINARY_SIZE, sbox);

		/* Add salt for numbers not divisible by 3. */
		if (cnt % 3)
			gost94_update(&ctx, s_bytes, saltlen, sbox);

		/* Add key for numbers not divisible by 7. */
		if (cnt % 7)
			gost94_update(&ctx, p_bytes, len, sbox);

		/* Add key or last result. */
		if (cnt & 1)
			gost94_update(&ctx, result, BINARY_SIZE, sbox);
		else
			gost94_update(&ctx, p_bytes, len, sbox);

		/* Create intermediate result. */
		gost94_final(&ctx, result, sbox);
	}

	memcpy_pg(out[gid].v, result, BINARY_SIZE);
}

/*
 * This software is
 * Copyright 2012 Dhiru Kholia
 * and Copyright (c) 2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha2.h"

typedef struct {
	uint length;
	ushort v[PLAINTEXT_LENGTH];
} sevenzip_password;

typedef struct {
	uint key[32/4];
} sevenzip_hash;

typedef struct {
	uint length;
	uint iterations;
	uchar salt[16];
} sevenzip_salt;

typedef struct {
	ulong t;
	SHA256_CTX ctx;
	uint len;
	ushort buffer[PLAINTEXT_LENGTH];
} sevenzip_state;

__kernel void sevenzip_init(__global const sevenzip_password *inbuffer,
                            __global const sevenzip_salt *salt,
                            __global sevenzip_state *state)
{
	uint gid = get_global_id(0);
	uint len = inbuffer[gid].length;
	uint i;
	SHA256_CTX ctx;

	/* Copy password to state buffer. We could optimize this away
	   but the format is so slow it would not make a difference */
	for (i = 0; i < len; i++)
		state[gid].buffer[i] = inbuffer[gid].v[i];
	state[gid].len = len;

	/* kdf */
	SHA256_Init(&ctx);

	for (i = 0; i < 2; i++)
		state[gid].ctx.total[i] = ctx.total[i];
	for (i = 0; i < 8; i++)
		state[gid].ctx.state[i] = ctx.state[i];
	for (i = 0; i < 64/4; i++)
		((__global uint*)state[gid].ctx.buffer)[i] =
			((uint*)ctx.buffer)[i];

	state[gid].t = 0;
}

__kernel void sevenzip_crypt(__global sevenzip_state *state,
                             __global const sevenzip_salt *salt,
                             __global sevenzip_hash *outbuffer)
{
	uint gid = get_global_id(0);
	uint len = state[gid].len;
	uint i;
	uint rnds = 1U << salt->iterations;
	ushort buffer[PLAINTEXT_LENGTH];
	ulong t = state[gid].t;
	SHA256_CTX ctx;

	for (i = 0; i < 2; i++)
		ctx.total[i] = state[gid].ctx.total[i];
	for (i = 0; i < 8; i++)
		ctx.state[i] = state[gid].ctx.state[i];
	for (i = 0; i < 64/4; i++)
		((uint*)ctx.buffer)[i] =
			((__global uint*)state[gid].ctx.buffer)[i];
	for (i = 0; i < len; i++)
		buffer[i] = state[gid].buffer[i];
	len *= 2;

	/* kdf */
	for (i = 0; i < HASH_LOOPS && t < rnds; i++) {
		SHA256_Update(&ctx, (uchar*)buffer, len);
		SHA256_Update(&ctx, (uchar*)&t, 8);
		t++;
	}

	if (t < rnds) {
		for (i = 0; i < 2; i++)
			state[gid].ctx.total[i] = ctx.total[i];
		for (i = 0; i < 8; i++)
			state[gid].ctx.state[i] = ctx.state[i];
		for (i = 0; i < 64/4; i++)
			((__global uint*)state[gid].ctx.buffer)[i] =
				((uint*)ctx.buffer)[i];
		state[gid].t = t;
	} else {
		uint lkey[32/4];

		SHA256_Final(&ctx, (uchar*)lkey);

		for (i = 0; i < 32/4; i++)
			outbuffer[gid].key[i] = lkey[i];
	}
}

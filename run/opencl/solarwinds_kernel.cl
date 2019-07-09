/*
 * OpenCL kernel for SolarWinds Orion hashes.
 *
 * This software is  Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2017
 * magnum, and it is hereby released to the general public under the following
 * terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define MAYBE_CONSTANT __global
#include "opencl_sha2_ctx.h"
#include "pbkdf2_hmac_sha1_kernel.cl"

typedef struct {
	union {
		uint w[((OUTLEN + 19) / 20) * 20 / sizeof(uint)];
		uchar c[((OUTLEN + 19) / 20) * 20];
	} key;
} solarwinds_out;

typedef struct {
	uchar hash[12];
} solarwinds_final_out;

typedef struct {
	uint  length;
	uint  outlen;
	uint  iters;
	uchar salt[8];
} solarwinds_salt;

__kernel
void solarwinds_loop(MAYBE_CONSTANT solarwinds_salt *salt,
                  __global solarwinds_out *out,
                  __global pbkdf2_state *state)
{
	uint gid = get_global_id(0);
	uint i;
#if !OUTLEN || OUTLEN > 20
	uint base = state[gid].pass++ * 5;
	uint pass = state[gid].pass;
#else
#define base 0
#define pass 1
#endif
#ifndef OUTLEN
#define OUTLEN salt->outlen
#endif

	// First/next 20 bytes of output
	for (i = 0; i < 5; i++)
		out[gid].key.w[base + i] = SWAP32(state[gid].out[i]);

	/* Was this the last pass? If not, prepare for next one */
	if (4 * base + 20 < OUTLEN) {
		_phsk_hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad,
		                salt->salt, salt->length, 1 + pass);

		for (i = 0; i < 5; i++)
			state[gid].W[i] = state[gid].out[i];

#ifndef ITERATIONS
		state[gid].iter_cnt = salt->iterations - 1;
#endif
	} else {
		union {
			uchar c[8192 / 8];
			uint  w[8192 / 8 / 4];
		} hash;

		unsigned char output[64];

		SHA512_CTX ctx;

		for (i = 0; i < 8192/8/4; i++)
			hash.w[i] = out[gid].key.w[i];

		SHA512_Init(&ctx);
		SHA512_Update(&ctx, hash.c, 1024);
		SHA512_Final(output, &ctx);

		memcpy_macro(out[gid].key.c, output, 64);
	}
}

__kernel
void solarwinds_final(__global solarwinds_out *out,  __global solarwinds_final_out *final_out)
{
	uint gid = get_global_id(0);

	memcpy_macro(final_out[gid].hash, out[gid].key.c, 12);
}

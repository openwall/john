/*
 * OpenCL kernel for cracking NetIQ SSPR hashes.
 *
 * This software is
 * Copyright (c) 2018 Dhiru Kholia <dhiru at openwall.com>
 * Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file is based on the gpg_kernel.cl file.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_md5_ctx.h"
#include "opencl_sha1_ctx.h"
#include "opencl_sha2_ctx.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif
#ifndef SALT_LENGTH
#error SALT_LENGTH must be defined
#endif

#ifndef BINARY_SIZE_MIN
#define BINARY_SIZE_MIN         16
#endif

typedef union out_u {
	uchar b[BINARY_SIZE_MIN];
	uint w[BINARY_SIZE_MIN / sizeof(uint)];
	uint64_t W[BINARY_SIZE_MIN / sizeof(uint64_t)];
} out_t;

typedef union hash_u {
	uchar b[SHA_DIGEST_LENGTH];
	uint w[SHA_DIGEST_LENGTH / sizeof(uint)];
} hash_t;

typedef union hash256_u {
	uchar b[SHA256_DIGEST_LENGTH];
	uint w[SHA256_DIGEST_LENGTH / sizeof(uint)];
} hash256_t;

typedef union hash512_u {
	uchar b[SHA512_DIGEST_LENGTH];
	uint w[SHA512_DIGEST_LENGTH / sizeof(uint)];
	uint64_t W[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
} hash512_t;

typedef struct {
	uint length;
	uchar v[PLAINTEXT_LENGTH];
} sspr_password;

typedef struct {
	out_t hash;
} sspr_hash;

typedef struct {
	uint length;
	uint count;
	uchar salt[SALT_LENGTH];
} sspr_salt;

typedef struct {
	hash512_t hash;
	uint count;
} sspr_state;

__kernel void loop_md5(__global sspr_hash *outbuffer,
                       __global sspr_state *state)
{
	uint gid = get_global_id(0);
	hash_t buf;
	uint i;
	uint count =
		(state[gid].count > HASH_LOOPS) ? HASH_LOOPS : state[gid].count;

	for (i = 0; i < 4; i++)
		buf.w[i] = state[gid].hash.w[i];

	for (i = 0; i < count; i++) {
		uint j, W[16];

		for (j = 0; j < 4; j++)
			W[j] = buf.w[j];
		W[4] = 0x80;
		for (j = 5; j < 14; j++)
			W[j] = 0;
		W[14] = 16 << 3;
		W[15] = 0;
		md5_single(uint, W, buf.w);
	}

	if ((state[gid].count -= count) == 0)
		for (i = 0; i < 4; i++)
			outbuffer[gid].hash.w[i] = buf.w[i];
	else
		for (i = 0; i < 4; i++)
			state[gid].hash.w[i] = buf.w[i];
}

__kernel void sspr_md5(__global const sspr_password *inbuffer,
                        __global sspr_hash *outbuffer,
                        __constant sspr_salt *salt,
                        __global sspr_state *state)
{
	uint gid = get_global_id(0);
	uchar password[PLAINTEXT_LENGTH];
	hash_t buf;
	MD5_CTX ctx;
	uint i;

	memcpy_gp(password, inbuffer[gid].v, inbuffer[gid].length);

	MD5_Init(&ctx);
	MD5_Update(&ctx, password, inbuffer[gid].length);
	MD5_Final(buf.b, &ctx);

	for (i = 0; i < 4; i++)
		state[gid].hash.w[i] = buf.w[i];

	state[gid].count = salt->count - 1;
}

__kernel void loop_sha1(__global sspr_hash *outbuffer,
                        __global sspr_state *state)
{
	uint gid = get_global_id(0);
	hash_t buf;
	uint i;
	uint count =
		(state[gid].count > HASH_LOOPS) ? HASH_LOOPS : state[gid].count;

	for (i = 0; i < 5; i++)
		buf.w[i] = state[gid].hash.w[i];

	for (i = 0; i < count; i++) {
		uint j, W[16];

		for (j = 0; j < 5; j++)
			W[j] = buf.w[j];
		W[5] = 0x80000000;
		W[15] = 20 << 3;
		sha1_single_160Z(uint, W, buf.w);
	}

	if ((state[gid].count -= count) == 0)
		// Only 128 bits of final data
		for (i = 0; i < 4; i++)
			outbuffer[gid].hash.w[i] = SWAP32(buf.w[i]);
	else
		for (i = 0; i < 5; i++)
			state[gid].hash.w[i] = buf.w[i];
}

__kernel void sspr_sha1(__global const sspr_password *inbuffer,
                        __global sspr_hash *outbuffer,
                        __constant sspr_salt *salt,
                        __global sspr_state *state)
{
	uint gid = get_global_id(0);
	uchar password[PLAINTEXT_LENGTH];
	hash_t buf;
	SHA_CTX ctx;
	uint i;

	memcpy_gp(password, inbuffer[gid].v, inbuffer[gid].length);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, password, inbuffer[gid].length);
	SHA1_Final(buf.b, &ctx);

	for (i = 0; i < 5; i++)
		state[gid].hash.w[i] = SWAP32(buf.w[i]);

	state[gid].count = salt->count - 1;
}

__kernel void sspr_salted_sha1(__global const sspr_password *inbuffer,
                               __global sspr_hash *outbuffer,
                               __constant sspr_salt *salt,
                               __global sspr_state *state)
{
	uint gid = get_global_id(0);
	uchar password[PLAINTEXT_LENGTH];
	hash_t buf;
	uchar psalt[32];
	SHA_CTX ctx;
	uint i;

	memcpy_cp(psalt, salt->salt, salt->length);
	memcpy_gp(password, inbuffer[gid].v, inbuffer[gid].length);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, psalt, salt->length);
	SHA1_Update(&ctx, password, inbuffer[gid].length);
	SHA1_Final(buf.b, &ctx);

	for (i = 0; i < 5; i++)
		state[gid].hash.w[i] = SWAP32(buf.w[i]);

	state[gid].count = salt->count - 1;
}

__kernel void loop_sha256(__global sspr_hash *outbuffer,
                          __global sspr_state *state)
{
	uint gid = get_global_id(0);
	hash256_t buf;
	uint i;
	uint count =
		(state[gid].count > HASH_LOOPS) ? HASH_LOOPS : state[gid].count;

	for (i = 0; i < 8; i++)
		buf.w[i] = state[gid].hash.w[i];

	for (i = 0; i < count; i++) {
		uint j, W[16];

		for (j = 0; j < 8; j++)
			W[j] = buf.w[j];
		W[8] = 0x80000000;
		W[15] = 32 << 3;
		sha256_init(buf.w);
		sha256_block_zeros(W, buf.w);
	}

	if ((state[gid].count -= count) == 0)
		// Only 128 bits of final data
		for (i = 0; i < 4; i++)
			outbuffer[gid].hash.w[i] = SWAP32(buf.w[i]);
	else
		for (i = 0; i < 8; i++)
			state[gid].hash.w[i] = buf.w[i];
}

__kernel void sspr_salted_sha256(__global const sspr_password *inbuffer,
                                 __global sspr_hash *outbuffer,
                                 __constant sspr_salt *salt,
                                 __global sspr_state *state)
{
	uint gid = get_global_id(0);
	uchar password[PLAINTEXT_LENGTH];
	hash256_t buf;
	uchar psalt[32];
	SHA256_CTX ctx;
	uint i;

	memcpy_cp(psalt, salt->salt, salt->length);
	memcpy_gp(password, inbuffer[gid].v, inbuffer[gid].length);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, psalt, salt->length);
	SHA256_Update(&ctx, password, inbuffer[gid].length);
	SHA256_Final(buf.b, &ctx);

	for (i = 0; i < 8; i++)
		state[gid].hash.w[i] = SWAP32(buf.w[i]);

	state[gid].count = salt->count - 1;
}

__kernel void loop_sha512(__global sspr_hash *outbuffer,
                          __global sspr_state *state)
{
	uint gid = get_global_id(0);
	hash512_t buf;
	uint i;
	uint count =
		(state[gid].count > HASH_LOOPS) ? HASH_LOOPS : state[gid].count;

	for (i = 0; i < 8; i++)
		buf.W[i] = state[gid].hash.W[i];

	for (i = 0; i < count; i++) {
		uint j;
		ulong W[16];

		for (j = 0; j < 8; j++)
			W[j] = buf.W[j];
		W[8] = 0x8000000000000000UL;
		W[15] = 64 << 3;
		sha512_single_zeros(W, buf.W);
	}

	if ((state[gid].count -= count) == 0)
		// Only 128 bits of final data
		for (i = 0; i < 2; i++)
			outbuffer[gid].hash.W[i] = SWAP64(buf.W[i]);
	else
		for (i = 0; i < 8; i++)
			state[gid].hash.W[i] = buf.W[i];
}

__kernel void sspr_salted_sha512(__global const sspr_password *inbuffer,
                                 __global sspr_hash *outbuffer,
                                 __constant sspr_salt *salt,
                                 __global sspr_state *state)
{
	uint gid = get_global_id(0);
	uchar password[PLAINTEXT_LENGTH];
	hash512_t buf;
	uchar psalt[32];
	SHA512_CTX ctx;
	uint i;

	memcpy_cp(psalt, salt->salt, salt->length);
	memcpy_gp(password, inbuffer[gid].v, inbuffer[gid].length);

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, psalt, salt->length);
	SHA512_Update(&ctx, password, inbuffer[gid].length);
	SHA512_Final(buf.b, &ctx);

	for (i = 0; i < 8; i++)
		state[gid].hash.W[i] = SWAP64(buf.W[i]);

	state[gid].count = salt->count - 1;
}

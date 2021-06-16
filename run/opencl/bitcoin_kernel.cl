/*
 * OpenCL kernel for cracking Bitcoin wallet.dat hashes.
 *
 * This software is
 * Copyright (c) 2021 Solar Designer
 * Copyright (c) 2018 Dhiru Kholia
 * Copyright (c) 2018-2021 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file is loosely based on parts of the sspr_kernel.cl file.
 */

#include "opencl_misc.h"
#include "opencl_sha2_ctx.h"
#define AES_KEY_TYPE __global
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

typedef struct {
	int len;
	char c[PLAINTEXT_LENGTH + 1];
} password_t;

typedef struct custom_salt {
	uchar cry_master[SZ];
	int cry_master_length;
	uchar cry_salt[SZ];
	int cry_salt_length;
	int cry_rounds;
	int final_block_fill;
} salt_t;

typedef union hash512_u {
	uchar b[SHA512_DIGEST_LENGTH];
	uint w[SHA512_DIGEST_LENGTH / sizeof(uint)];
	uint64_t W[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
} hash512_t;

__kernel void bitcoin_init(__global password_t *key, __constant salt_t *salt, __global hash512_t *state)
{
	uint gid = get_global_id(0);
	hash512_t key_iv;
	SHA512_CTX sha_ctx;
	uchar buf[SZ];

	SHA512_Init(&sha_ctx);
	memcpy_gp(buf, key[gid].c, key[gid].len);
	SHA512_Update(&sha_ctx, buf, key[gid].len);
	memcpy_cp(buf, salt->cry_salt, salt->cry_salt_length);
	SHA512_Update(&sha_ctx, buf, salt->cry_salt_length);
	SHA512_Final(key_iv.b, &sha_ctx);

	uint i;
	for (i = 0; i < 8; i++)
		state[gid].W[i] = SWAP64(key_iv.W[i]);
}

__kernel void loop_sha512(__global hash512_t *state, uint count)
{
	uint gid = get_global_id(0);
	hash512_t buf;
	uint i;

	for (i = 0; i < 8; i++)
		buf.W[i] = state[gid].W[i];

	for (i = 0; i < count; i++) {
		uint j;
		ulong W[16];

		for (j = 0; j < 8; j++)
			W[j] = buf.W[j];
		W[8] = 0x8000000000000000UL;
		W[15] = 64 << 3;
		sha512_single_zeros(W, buf.W);
	}

	for (i = 0; i < 8; i++)
		state[gid].W[i] = buf.W[i];
}

__kernel void bitcoin_final(__constant salt_t *salt, __global hash512_t *state, __global uint *cracked)
{
	uint gid = get_global_id(0);
	uchar iv[16];  // updated IV for the final block
	memcpy_cp(iv, salt->cry_master + salt->cry_master_length - 32, 16);

	uint i;
	for (i = 0; i < 8; i++)
		state[gid].W[i] = SWAP64(state[gid].W[i]);

	uchar output[16];
	AES_KEY aes_key;
	AES_set_decrypt_key(state[gid].b, 256, &aes_key);
	AES_cbc_decrypt(salt->cry_master + salt->cry_master_length - 16, output, 16, &aes_key, iv);

	cracked[gid] = (check_pkcs_pad(output, 16, 16) == salt->final_block_fill);
}

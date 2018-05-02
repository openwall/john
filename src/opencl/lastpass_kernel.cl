/*
 * This software is Copyright 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha256_kernel.cl"
#define AES_SRC_TYPE const __constant
#define AES_DST_TYPE __global
#include "opencl_aes.h"

__kernel void lastpass_final(__global crack_t *out,
                             MAYBE_CONSTANT salt_t *salt,
                             __global state_t *state)
{
	uint idx = get_global_id(0);
	uint i;
	uint key[8];
	AES_KEY akey;

	for (i = 0; i < 8; i++)
		key[i] = SWAP32(state[idx].hash[i]);

	AES_set_encrypt_key(key, 256, &akey);
	AES_ecb_encrypt("lastpass rocks\x02\x02", (__global uchar*)out[idx].hash,
	                16, &akey);
}

#define AGENT_VERIFICATION_STRING "`lpass` was written by LastPass."

typedef struct {
	salt_t pbkdf2;
	uchar  iv[16];
} lpcli_salt_t;

__kernel void lastpass_cli_final(__global crack_t *out,
                                 MAYBE_CONSTANT lpcli_salt_t *salt,
                                 __global state_t *state)
{
	uint idx = get_global_id(0);
	uint i;
	uint key[8];
	uchar iv[16];
	AES_KEY akey;

	for (i = 0; i < 8; i++)
		key[i] = SWAP32(state[idx].hash[i]);

	memcpy_mcp(iv, salt->iv, 16);
	AES_set_encrypt_key(key, 256, &akey);
	AES_cbc_encrypt(AGENT_VERIFICATION_STRING, (__global uchar*)out[idx].hash,
	                32, &akey, iv);
}

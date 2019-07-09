/*
 * This software is Copyright 2013 Lukas Odzioba, Copyright 2014 magnum,
 * Copyright 2017 Dhiru Kholia, Copyright 2017 Frederic Heem, and it is hereby
 * released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef PRESALE
#define GLOBAL_SALT_NO_INIT
#endif
#include "pbkdf2_hmac_sha256_kernel.cl"
#ifdef PRESALE
#define AES_KEY_TYPE __global const
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"
#endif
#include "opencl_keccak.h"

// input
typedef struct {
	salt_t pbkdf2;
	uint8_t encseed[1024];
	uint32_t eslen;
} ethereum_salt_t;

// output
typedef struct {
	uint32_t hash[4];
} hash_t;

#ifdef PRESALE
__kernel void ethereum_presale_init(__global const pass_t *inbuffer,
                                    MAYBE_CONSTANT salt_t *salt,
                                    __global state_t *state)
{
	uint i, idx = get_global_id(0);
	uint pass = 0;

	state[idx].rounds = 2000 - 1;

	_phsk_preproc(inbuffer[idx].v, inbuffer[idx].length,
	              state[idx].ipad, 0x36363636);
	_phsk_preproc(inbuffer[idx].v, inbuffer[idx].length,
	              state[idx].opad, 0x5c5c5c5c);

	/* Password is used as salt too! Wierd, and stupid - we exploit it! */
	_phsk_hmac_sha256(state[idx].hash, state[idx].ipad, state[idx].opad,
	                  inbuffer[idx].v, inbuffer[idx].length, pass + 1);

	for (i = 0; i < 8; i++)
		state[idx].W[i] = state[idx].hash[i];

	state[idx].pass = pass;
}

__kernel void ethereum_presale_process(__global crack_t *pbkdf2_out,
                                       MAYBE_CONSTANT ethereum_salt_t *salt,
                                       __global state_t *state,
                                       __global hash_t *out)
{
	uint32_t gid = get_global_id(0);
	AES_KEY akey;
	uchar iv[16];
	int i;
	uchar seed[1024 + 1];
	uint hash[8];
	int padbyte;
	int seed_length;

	/*
	 * We call the PBKDF2 final kernel as a function from here,
	 * instead of another short call from host side
	 */
	pbkdf2_sha256_final(pbkdf2_out, &salt->pbkdf2, state);

	for (i = 0; i < 16; i++)
		iv[i] = salt->encseed[i];

	AES_set_decrypt_key(pbkdf2_out[gid].hash, 128, &akey);
	AES_cbc_decrypt(salt->encseed + 16, seed, salt->eslen - 16, &akey, iv);
	padbyte = seed[salt->eslen - 16 - 1];
	seed_length = salt->eslen - 16 - padbyte;
	if (seed_length < 0)
		seed_length = 0;
	seed[seed_length] = 0x02; // add 0x02 to the buffer
	keccak_256((uint8_t*)hash, 16, seed, seed_length + 1);

	for (i = 0; i < 4; i++)
		out[gid].hash[i] = hash[i];
}

#else

__kernel void ethereum_process(__global crack_t *pbkdf2_out,
                               MAYBE_CONSTANT ethereum_salt_t *salt,
                               __global state_t *state,
                               __global hash_t *out)
{
	uint32_t gid = get_global_id(0);
	uchar hash_in[16 + 256];
	uint hash[8];
	uint i;

	/*
	 * We call the PBKDF2 final kernel as a function from here,
	 * instead of another short call from host side
	 */
	pbkdf2_sha256_final(pbkdf2_out, &salt->pbkdf2, state);

	memcpy_gp(hash_in, &pbkdf2_out[gid].hash[16 / 4], 16);
	memcpy_mcp(hash_in + 16, salt->encseed, salt->eslen);

	keccak_256((uint8_t*)hash, 16, hash_in, 16 + salt->eslen);

	for (i = 0; i < 4; i++)
		out[gid].hash[i] = hash[i];
}

#endif

/*
 * OpenCL kernel for cracking VMware VMX hashes
 *
 * This software is Copyright (c) 2019 magnum, Copyright (c) 2019 Dhiru Kholia
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#include "pbkdf2_hmac_sha1_kernel.cl"
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"

// this is shared between this file and "vmx_common.h" file
#define SALTLEN  16
#define BLOBLEN  116

// output
typedef struct {
	uint cracked;
} vmx_out;

// internal
typedef struct {
	uint key[((OUTLEN + 19) / 20) * 20 / sizeof(uint)];
} vmx_state;

// input
typedef struct {
	uint salt_length;
	uint outlen;
	uint iterations;
	uchar salt[SALTLEN];
	uchar blob[BLOBLEN];
} vmx_salt;

__kernel
void vmx_final(MAYBE_CONSTANT vmx_salt *salt,
		__global vmx_out *out,
		__global pbkdf2_state *state,
		__global vmx_state *vstate)
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
		vstate[gid].key[base + i] = SWAP32(state[gid].out[i]);

	/* Was this the last pass? If not, prepare for next one */
	if (4 * base + 20 < OUTLEN) {
		_phsk_hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad,
		                salt->salt, salt->salt_length, 1 + pass);

		for (i = 0; i < 5; i++)
			state[gid].W[i] = state[gid].out[i];

#ifndef ITERATIONS
		state[gid].iter_cnt = salt->iterations - 1;
#endif
	} else {
		uchar data[16];
		AES_KEY akey;
		int success = 0;
		union {
			uchar c[256 / 8];
			uint  w[256 / 8 / 4];
		} hash;
		union {
			uchar c[16];
			uint  w[16 / 4];
		} iv;

		for (i = 0; i < 256/8/4; i++)
			hash.w[i] = vstate[gid].key[i];

		for (i = 0; i < 16; i++)
			iv.c[i] = salt->blob[i];

		AES_set_decrypt_key(hash.c, 256, &akey);
		AES_cbc_decrypt(salt->blob + 16, data, 16, &akey, iv.c);

		if ((!memcmp_pc(data, "type=key:cipher=", 16))) {
			success = 1;
		}

		out[gid].cracked = success;
	}
}

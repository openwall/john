/*
 * OpenCL kernel for cracking iWork hashes
 *
 * This software is Copyright (c) 2017 magnum, Copyright (c) 2017 Dhiru Kholia
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#undef MAYBE_CONSTANT
#define MAYBE_CONSTANT __global
#include "opencl_sha2.h"
#include "pbkdf2_hmac_sha1_kernel.cl"
#define AES_KEY_TYPE __global
#define OCL_AES_CBC_DECRYPT 1
#include "opencl_aes.h"

// this is shared between this file and "iwork_common.h" file
#define SALTLEN  16
#define IVLEN    16
#define BLOBLEN  64

typedef struct {
	volatile uint cracked;
	uint key[((OUTLEN + 19) / 20) * 20 / sizeof(uint)];
} iwork_out;

typedef struct {
	uint salt_length;
	uint outlen;
	uint iterations;
	uchar salt[SALTLEN];
	uchar iv[IVLEN];
	uchar blob[BLOBLEN];
} iwork_salt;

__kernel
void iwork_final(MAYBE_CONSTANT iwork_salt *salt,
                  __global iwork_out *out,
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

	// First/next 20 bytes of output
	for (i = 0; i < 5; i++)
		out[gid].key[base + i] = SWAP32(state[gid].out[i]);

#ifndef OUTLEN
#define OUTLEN salt->outlen
#endif
	/* Was this the last pass? If not, prepare for next one */
	if (4 * base + 20 < OUTLEN) {
		hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad,
		          salt->salt, salt->salt_length, 1 + pass);

		for (i = 0; i < 5; i++)
			state[gid].W[i] = state[gid].out[i];

#ifndef ITERATIONS
		state[gid].iter_cnt = salt->iterations - 1;
#endif
	} else {
		AES_KEY akey;
		uchar iv[IVLEN];
		uchar plaintext[BLOBLEN];
		uint i;
		int success = 1; // hash was cracked

		if (gid == 0)
			out[0].cracked = 0;

		for (i = 0; i < 16; i++)
			iv[i] = salt->iv[i];

		AES_set_decrypt_key((__global uchar*)(out[gid].key), 128, &akey);
		AES_cbc_decrypt(salt->blob, plaintext, BLOBLEN, &akey, iv);

		union {
			uint w[256 / 8 / 4];
			uchar c[32];
		} hash;

		union {
			uchar c[64];
			uint  w[16];
		} md;

		for (i = 0; i < 16; i++)
			md.w[i] = 0;

		// SHA256(plaintext)
		for (i = 0; i < 32; i++)
			md.c[i ^ 3] = plaintext[i];
		md.c[i ^ 3] = 0x80;
		md.w[15] = i << 3;

		sha256_init(hash.w);
		sha256_block(md.w, hash.w);

		for (i = 0; i < 256/8/4; i++)
			hash.w[i] = SWAP32(hash.w[i]);

		for (i = 0; i < 32; i++) {
			if (hash.c[i] != plaintext[32 + i]) {
				success = 0;
				break;
			}
		}

		out[gid + 1].cracked = success;

		if (success)
			atomic_or(&out[0].cracked, 1);
	}
}

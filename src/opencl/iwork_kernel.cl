/*
 * OpenCL kernel for cracking iWork hashes
 *
 * This software is Copyright (c) 2017 magnum, Copyright (c) 2017 Dhiru Kholia
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#include "opencl_sha2.h"
#include "pbkdf2_hmac_sha1_kernel.cl"
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"

// this is shared between this file and "iwork_common.h" file
#define SALTLEN  16
#define IVLEN    16
#define BLOBLEN  64

typedef struct {
	uint cracked;
} iwork_out;

typedef struct {
	uint salt_length;
	uint outlen;
	uint iterations;
	uchar salt[SALTLEN];
	union {
		uchar c[IVLEN];
		uint  w[IVLEN / 4];
	} iv;
	uchar blob[BLOBLEN];
} iwork_salt;

__kernel
void iwork_final(MAYBE_CONSTANT iwork_salt *salt,
                 __global iwork_out *result,
                 __global pbkdf2_state *state)
{
	uint gid = get_global_id(0);
	uint i;
	AES_KEY akey;
	int success = 1; // hash was cracked
	union {
		uchar c[BLOBLEN];
		uint  w[BLOBLEN / 4];
	} plaintext;
	union {
		uchar c[64];
		uint  w[64 / 4];
	} in;
	union {
		uchar c[256 / 8];
		uint  w[256 / 8 / 4];
	} out;
	union {
		uchar c[16];
		uint  w[16 / 4];
	} iv;

	for (i = 0; i < 128/8/4; i++)
		out.w[i] = SWAP32(state[gid].out[i]);

	for (i = 0; i < 16/4; i++)
		iv.w[i] = salt->iv.w[i];

	AES_set_decrypt_key(out.c, 128, &akey);
	AES_cbc_decrypt(salt->blob, plaintext.c, BLOBLEN, &akey, iv.c);

	// SHA256(plaintext)
	for (i = 0; i < 32/4; i++)
		in.w[i] = SWAP32(plaintext.w[i]);
	in.w[8] = 0x80000000;
	for (i = 9; i < 16; i++)
		in.w[i] = 0;
	in.w[15] = 32 << 3;

	sha256_init(out.w);
	sha256_block(in.w, out.w);

	for (i = 0; i < 256/8/4; i++)
		out.w[i] = SWAP32(out.w[i]);

	for (i = 0; i < 32/4; i++) {
		if (out.w[i] != plaintext.w[32/4 + i]) {
			success = 0;
			break;
		}
	}

	result[gid].cracked = success;
}

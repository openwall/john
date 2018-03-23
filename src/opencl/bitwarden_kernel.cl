/*
 * This software is Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2017 magnum,
 * and Copyright (c) 2017 JimF, and it is hereby released to the general public
 * under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha256_kernel.cl"
#define AES_KEY_TYPE __global const
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"

/*
 * Note that this struct includes the one in opencl_pbkdf2_hmac_sha256.h
 * and custom stuff appended.
 */
typedef struct {
	// PBKDF2 salt
	salt_t pbkdf2;

	// bitwarden extension
	union {
		uint64_t qword[32/8];
		uint8_t chr[32];
	} blob;
} bitwarden_salt_t;

__kernel void bitwarden_decrypt(MAYBE_CONSTANT bitwarden_salt_t *salt,
                                __global crack_t *out,
                                __global uint32_t *cracked)
{
	uint32_t gid = get_global_id(0);
	int32_t i;
	AES_KEY akey;
	union {
		uchar c[32];
		uint  w[32 / 4];
	} plaintext;
	uint8_t iv[16] = { 0 }; // does not matter
	int success = 1; // hash was cracked

	AES_set_decrypt_key(out[gid].hash, 256, &akey);
	AES_cbc_decrypt(salt->blob.chr, plaintext.c, 32, &akey, iv);

	// Check padding
	for (i = 0; i < 4; i++) {
		if (0x10101010 != plaintext.w[4 + i]) {
			success = 0;
			break;
		}
	}

	cracked[gid] = success;
}

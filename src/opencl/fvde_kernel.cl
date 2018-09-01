/*
 * This software is Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * salt length increase. HAS to match pbkdf2_hmac_sha256_kernel.cl code
 *    Dec 2017, JimF.
 */

#include "pbkdf2_hmac_sha256_kernel.cl"
#define AES_KEY_TYPE __global const
#include "opencl_aes.h"

/*
 * Note that this struct includes the one in opencl_pbkdf2_hmac_sha256.h
 * and custom stuff appended.
 */
typedef struct {
	salt_t pbkdf2;
	int32_t type;
	union blob {  // wrapped kek
		uint64_t qword[BLOBLEN/8];
		uint8_t chr[BLOBLEN];
	} blob;
} fvde_salt_t;

__kernel void fvde_decrypt(MAYBE_CONSTANT fvde_salt_t *salt,
                           __global crack_t *out,
                           __global uint32_t *cracked)
{
	uint32_t gid = get_global_id(0);
	MAYBE_CONSTANT uint64_t *C = salt->blob.qword; // len(C) == 3 or 5 (AES-256)
	int32_t n = BLOBLEN / 8 - 1;  // len(C) - 1
	uint64_t R[5]; // n + 1 = 5
	union {
		uint64_t qword[2];
		uint8_t stream[16];
	} todecrypt;
	int32_t i, j;
	AES_KEY akey;
	uint64_t A = C[0];

	if (salt->type == 1) {
		AES_set_decrypt_key(out[gid].hash, 128, &akey);
		n = 2;  // note
	} else {
		AES_set_decrypt_key(out[gid].hash, 256, &akey);
	}

	for (i = 0; i < n + 1; i++)
		R[i] = C[i];

	for (j = 5; j >= 0; j--) { // 5 is fixed!
		for (i = n; i >= 1; i--) { // i = n
			todecrypt.qword[0] = SWAP64(A ^ (n * j + i));
			todecrypt.qword[1] = SWAP64(R[i]);
			AES_decrypt(todecrypt.stream, todecrypt.stream, &akey);
			A = SWAP64(todecrypt.qword[0]);
			R[i] = SWAP64(todecrypt.qword[1]);
		}
	}

	cracked[gid] = (A == 0xa6a6a6a6a6a6a6a6UL);
}

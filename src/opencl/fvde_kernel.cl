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
#define OCL_AES_ECB_DECRYPT 1
#define AES_KEY_TYPE __global
#include "opencl_aes.h"

#define BLOBLEN                 24

/*
 * Note that this struct must match the one in pbkdf2_hmac_sha256_kernel.cl
 * but with some added stuff appended
 */
typedef struct {
	uint32_t rounds;
	uint8_t salt[179];
	uint32_t length;
	union blob {  // wrapped kek
		uint64_t qword[BLOBLEN/8];
		uint8_t chr[BLOBLEN];
	} blob;
} fvde_salt_t;

__kernel void fvde_decrypt(__constant fvde_salt_t *salt,
                           __global crack_t *out,
                           __global uint32_t *cracked)
{
	uint32_t gid = get_global_id(0);
	__constant uint64_t *C = salt->blob.qword; // len(C) == 3
	int32_t n = 2;  // len(C) - 1
	uint64_t R[3]; // n + 1 = 3
	union {
		uint64_t qword[2];
		uint8_t stream[16];
	} todecrypt;
	int32_t i, j;
	AES_KEY akey;
	uint64_t A = C[0];

	AES_set_decrypt_key((__global uchar*)out[gid].hash, 128, &akey);

	for (i = 0; i < n + 1; i++)
		R[i] = C[i];

	for (j = 5; j >= 0; j--) { // 5 is fixed!
		for (i = 2; i >= 1; i--) { // i = n
			todecrypt.qword[0] = SWAP64(A ^ (n * j + i));
			todecrypt.qword[1] = SWAP64(R[i]);
			AES_ecb_decrypt(todecrypt.stream, todecrypt.stream, &akey);
			A = SWAP64(todecrypt.qword[0]);
			R[i] = SWAP64(todecrypt.qword[1]);
		}
	}

	cracked[gid] = (A == 0xa6a6a6a6a6a6a6a6UL);
}

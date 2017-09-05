/*
 * This software is Copyright (c) 2017 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1_ctx.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH 20
#endif

#ifndef _memcpy
#define _memcpy	memcpy_macro
#endif

typedef struct {
	uint length;
	uchar v[PLAINTEXT_LENGTH];
} pgpdisk_password;

typedef struct {
	uchar v[32];
} pgpdisk_hash;

typedef struct {
	uint saltlen;
	uint iterations;
	uint key_len;
	uchar salt[16];
} pgpdisk_salt;

#ifndef __MESA__
inline
#endif
void pgpdisk_kdf(__global const uchar *ipassword, uint password_length,
		__constant const uchar *isalt, uint saltlen, uint iterations,
		__global uchar *okey, uint key_len)
{
	uint32_t bytesNeeded = key_len;
	uint32_t offset = 0;
	unsigned char hash[SHA1_DIGEST_LENGTH];
	int plen;
	SHA_CTX ctx;
	unsigned char key[40];
	unsigned char password[PLAINTEXT_LENGTH];
	unsigned char salt[16];

	_memcpy(salt, isalt, saltlen);
	_memcpy(password, ipassword, password_length);
	plen = password_length;
	while (bytesNeeded > 0) {
		uint32_t bytesThisTime = SHA1_DIGEST_LENGTH < bytesNeeded ? SHA1_DIGEST_LENGTH: bytesNeeded;
		uint8_t j;
		uint16_t i;

		SHA1_Init(&ctx);
		if (offset > 0) {
			SHA1_Update(&ctx, key, SHA1_DIGEST_LENGTH);
		}
		SHA1_Update(&ctx, password, plen);
		SHA1_Final(hash, &ctx);

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, salt, saltlen);

		for (i = 0, j = 0; i < iterations; i++, j++) {
			SHA1_Update(&ctx, hash, bytesThisTime);
			SHA1_Update(&ctx, &j, 1);
		}
		SHA1_Final(key + offset, &ctx);

		bytesNeeded -= bytesThisTime;
		offset += bytesThisTime;
	}

	_memcpy(okey, key, key_len);
}

__kernel void pgpdisk(__global const pgpdisk_password *inbuffer,
                  __global pgpdisk_hash *outbuffer,
                  __constant pgpdisk_salt *salt)
{
	uint idx = get_global_id(0);

	pgpdisk_kdf(inbuffer[idx].v, inbuffer[idx].length, salt->salt,
			salt->saltlen, salt->iterations, outbuffer[idx].v, salt->key_len);
}

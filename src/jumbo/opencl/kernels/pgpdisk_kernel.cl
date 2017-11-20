/*
 * This software is Copyright (c) 2017 Dhiru Kholia <dhiru at openwall.com> and
 * Copyright (c) 2017 magnum, and
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
void pgpdisk_kdf(__global const uchar *ipassword, const uint plen,
                 __constant uchar *isalt, const uint saltlen,
                 const uint iterations, __global uchar *okey, uint bytesNeeded)
{
	uint32_t offset = 0;
	unsigned char password[PLAINTEXT_LENGTH];
	unsigned char salt[16];

	memcpy_cp(salt, isalt, saltlen);
	memcpy_gp(password, ipassword, plen);
	while (bytesNeeded > 0) {
		SHA_CTX ctx;
		unsigned char key[SHA1_DIGEST_LENGTH];
		uint32_t i;
		uint32_t bytesThisTime = bytesNeeded > SHA1_DIGEST_LENGTH?
			SHA1_DIGEST_LENGTH : bytesNeeded;

		SHA1_Init(&ctx);
		if (offset > 0) {
			SHA1_Update(&ctx, key, SHA1_DIGEST_LENGTH);
		}
		SHA1_Update(&ctx, password, plen);
		SHA1_Final(key, &ctx);

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, salt, saltlen);

		for (i = 0; i < iterations; i++) {
			SHA1_Update(&ctx, key, bytesThisTime);
#if __ENDIAN_LITTLE__
			SHA1_Update(&ctx, (uchar*)&i, 1);
#else
			SHA1_Update(&ctx, ((uchar*)&i) + 3, 1);
#endif
		}
		SHA1_Final(key, &ctx);
		memcpy_pg(okey + offset, key, bytesThisTime);

		bytesNeeded -= bytesThisTime;
		offset += bytesThisTime;
	}
}

__kernel void pgpdisk(__global const pgpdisk_password *inbuffer,
                  __global pgpdisk_hash *outbuffer,
                  __constant pgpdisk_salt *salt)
{
	uint idx = get_global_id(0);

	pgpdisk_kdf(inbuffer[idx].v, inbuffer[idx].length, salt->salt,
			salt->saltlen, salt->iterations, outbuffer[idx].v, salt->key_len);
}

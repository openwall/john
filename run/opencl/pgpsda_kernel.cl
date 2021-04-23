/*
 * This software is
 * Copyright (c) 2017 Dhiru Kholia <dhiru at openwall.com>
 * Copyright (c) 2017-2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#include "opencl_sha1_ctx.h"
#include "opencl_cast.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

typedef struct {
	uint length;
	uchar v[PLAINTEXT_LENGTH];
} pgpsda_password;

typedef struct {
	uchar v[8];
} pgpsda_hash;

typedef struct {
	uint iterations;
	uchar salt[8];
} pgpsda_salt;

inline void pgpsda_kdf(__global const uchar *ipassword, const uint plen,
                       __constant uchar *isalt, const uint iterations,
                       uchar *key)
{
	SHA_CTX ctx;
	uint32_t j = 0;
	uchar password[PLAINTEXT_LENGTH];
	uchar salt[8];

	memcpy_cp(salt, isalt, 8);
	memcpy_gp(password, ipassword, plen);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, salt, 8);
	for (j = 0; j < iterations; j++) {
		SHA1_Update(&ctx, password, plen);
#if __ENDIAN_LITTLE__
		SHA1_Update(&ctx, (uchar*)&j, 1);
#else
		SHA1_Update(&ctx, ((uchar*)&j) + 3, 1);
#endif
	}
	SHA1_Final(key, &ctx);
}

__kernel void pgpsda(__global const pgpsda_password *inbuffer,
                     __global pgpsda_hash *outbuffer,
                     __constant pgpsda_salt *salt)
{
	uint idx = get_global_id(0);
	uchar key[SHA1_DIGEST_LENGTH];
	CAST_KEY ck;

	pgpsda_kdf(inbuffer[idx].v, inbuffer[idx].length, salt->salt,
	           salt->iterations, key);

	CAST_set_key(&ck, 16, key);
	CAST_ecb_encrypt(key, key, &ck);

	memcpy_pg(outbuffer[idx].v, key, 8);
}

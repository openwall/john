/*
 * This software is Copyright (c) 2017 Dhiru Kholia <dhiru at openwall.com> and
 * Copyright (c) 2017 magnum, and it is hereby released to the general public
 * under the following terms:
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
} pgpsda_password;

typedef struct {
	uchar v[16];
} pgpsda_hash;

typedef struct {
	uint iterations;
	uchar salt[8];
} pgpsda_salt;

#ifndef __MESA__
inline
#endif
void pgpsda_kdf(__global const uchar *ipassword, const uint plen,
                 __constant uchar *isalt, const uint iterations,
				 __global uchar *okey)
{
	SHA_CTX ctx;
	uint32_t j = 0;
	unsigned char password[PLAINTEXT_LENGTH];
	unsigned char salt[8];
	unsigned char key[SHA1_DIGEST_LENGTH];
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

	memcpy_pg(okey, key, 16);
}

__kernel void pgpsda(__global const pgpsda_password *inbuffer,
                  __global pgpsda_hash *outbuffer,
                  __constant pgpsda_salt *salt)
{
	uint idx = get_global_id(0);

	pgpsda_kdf(inbuffer[idx].v, inbuffer[idx].length, salt->salt,
			salt->iterations, outbuffer[idx].v);
}

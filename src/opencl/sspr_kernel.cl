/*
 * OpenCL kernel for cracking NetIQ SSPR hashes.
 *
 * This software is Copyright (c) 2018 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file is based on the gpg_kernel.cl file.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1_ctx.h"
#include "opencl_sha2_ctx.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif
#ifndef SALT_LENGTH
#error SALT_LENGTH must be defined
#endif

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

typedef struct {
	uint length;
	uchar v[PLAINTEXT_LENGTH];
} sspr_password;

typedef struct {
	uchar v[20];
} sspr_hash;

typedef struct {
	uint length;
	uint count;
	uchar salt[SALT_LENGTH];
} sspr_salt;

#ifndef __MESA__
inline
#endif
void sha1(__global const uchar *ipassword, uint password_length, uint count, __global uchar *okey)
{
	uchar password[PLAINTEXT_LENGTH];
	uchar buf[SHA_DIGEST_LENGTH];
	SHA_CTX ctx;
	uint i;

	memcpy_gp(password, ipassword, password_length);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, password, password_length);
	SHA1_Final(buf, &ctx);

	for (i = 1; i < count; i++) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, buf, 20);
		SHA1_Final(buf, &ctx);
	}

	memcpy_pg(okey, buf, SHA_DIGEST_LENGTH);
}

__kernel void sspr_sha1(__global const sspr_password *inbuffer,
                  __global sspr_hash *outbuffer,
                  __constant sspr_salt *salt)
{
	uint idx = get_global_id(0);

	sha1(inbuffer[idx].v, inbuffer[idx].length, salt->count, outbuffer[idx].v);
}

#ifndef __MESA__
inline
#endif
void salted_sha1(__global const uchar *ipassword, uint password_length, __constant uchar *isalt,
				uint salt_length, uint count, __global uchar *okey)
{
	uchar password[PLAINTEXT_LENGTH];
	uchar buf[SHA_DIGEST_LENGTH];
	uchar salt[32];
	SHA_CTX ctx;
	uint i;

	memcpy_cp(salt, isalt, salt_length);
	memcpy_gp(password, ipassword, password_length);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, salt, salt_length);
	SHA1_Update(&ctx, password, password_length);
	SHA1_Final(buf, &ctx);

	for (i = 1; i < count; i++) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, buf, 20);
		SHA1_Final(buf, &ctx);
	}

	memcpy_pg(okey, buf, SHA_DIGEST_LENGTH);
}

__kernel void sspr_salted_sha1(__global const sspr_password *inbuffer,
                  __global sspr_hash *outbuffer,
                  __constant sspr_salt *salt)
{
	uint idx = get_global_id(0);

	salted_sha1(inbuffer[idx].v, inbuffer[idx].length, salt->salt, salt->length,
				salt->count, outbuffer[idx].v);
}

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#ifndef __MESA__
inline
#endif
void salted_sha256(__global const uchar *ipassword, uint password_length, __constant uchar *isalt,
				uint salt_length, uint count, __global uchar *okey)
{
	uchar password[PLAINTEXT_LENGTH];
	uchar buf[SHA256_DIGEST_LENGTH];
	uchar salt[32];
	SHA256_CTX ctx;
	uint i;

	memcpy_cp(salt, isalt, salt_length);
	memcpy_gp(password, ipassword, password_length);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, salt, salt_length);
	SHA256_Update(&ctx, password, password_length);
	SHA256_Final(buf, &ctx);

	for (i = 1; i < count; i++) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, buf, 32);
		SHA256_Final(buf, &ctx);
	}

	memcpy_pg(okey, buf, SHA_DIGEST_LENGTH); // SHA_DIGEST_LENGTH is OK!
}

__kernel void sspr_salted_sha256(__global const sspr_password *inbuffer,
                  __global sspr_hash *outbuffer,
                  __constant sspr_salt *salt)
{
	uint idx = get_global_id(0);

	salted_sha256(inbuffer[idx].v, inbuffer[idx].length, salt->salt, salt->length,
				salt->count, outbuffer[idx].v);
}

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

#ifndef __MESA__
inline
#endif
void salted_sha512(__global const uchar *ipassword, uint password_length, __constant uchar *isalt,
				uint salt_length, uint count, __global uchar *okey)
{
	uchar password[PLAINTEXT_LENGTH];
	uchar buf[SHA512_DIGEST_LENGTH];
	uchar salt[32];
	SHA512_CTX ctx;
	uint i;

	memcpy_cp(salt, isalt, salt_length);
	memcpy_gp(password, ipassword, password_length);

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, salt, salt_length);
	SHA512_Update(&ctx, password, password_length);
	SHA512_Final(buf, &ctx);

	for (i = 1; i < count; i++) {
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, buf, 64);
		SHA512_Final(buf, &ctx);
	}

	memcpy_pg(okey, buf, SHA_DIGEST_LENGTH); // SHA_DIGEST_LENGTH is OK!
}

__kernel void sspr_salted_sha512(__global const sspr_password *inbuffer,
                  __global sspr_hash *outbuffer,
                  __constant sspr_salt *salt)
{
	uint idx = get_global_id(0);

	salted_sha512(inbuffer[idx].v, inbuffer[idx].length, salt->salt, salt->length,
				salt->count, outbuffer[idx].v);
}

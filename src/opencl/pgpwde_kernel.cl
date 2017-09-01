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
} pgpwde_password;

typedef struct {
	uchar v[32];
} pgpwde_hash;

typedef struct {
	uint saltlen;
	uint bytes;
	uint key_len;
	uchar salt[16];
} pgpwde_salt;

#ifndef __MESA__
inline
#endif
void pgpwde_kdf(__global const uchar *ipassword, uint password_length,
		__constant const uchar *isalt, uint saltlen, uint cbytes,
		__global uchar *okey, uint key_length)
{
	SHA_CTX ctx;
	uint num = (key_length - 1) / SHA1_DIGEST_LENGTH + 1;
	uint i, j;
	uint bytes;
	uint slen;
	const uint b[1] = { 0 };
	uchar password[PLAINTEXT_LENGTH];
	uchar salt[16];
	uchar key[2 * SHA1_DIGEST_LENGTH];

	_memcpy(salt, isalt, saltlen);
	_memcpy(password, ipassword, password_length);
	slen = password_length;
	if (cbytes < slen + 16)
		cbytes = (uint32_t)(slen + 16);

	for (i = 0; i < num; i++) {
		bytes = cbytes;
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, (uchar*)b, 1);
		}

		while (bytes > slen + 16) {
			SHA1_Update(&ctx, salt, 16);
			SHA1_Update(&ctx, password, slen);
			bytes -= slen + 16;
		}
		if (bytes <= 16) {
			SHA1_Update(&ctx, salt, bytes);
		} else {
			SHA1_Update(&ctx, salt, 16);
			SHA1_Update(&ctx, password, bytes - 16);
		}
		SHA1_Final(key + (i * SHA1_DIGEST_LENGTH), &ctx);
	}

	_memcpy(okey, key, key_length);
}

__kernel void pgpwde(__global const pgpwde_password *inbuffer,
                  __global pgpwde_hash *outbuffer,
                  __constant pgpwde_salt *salt)
{
	uint idx = get_global_id(0);

	pgpwde_kdf(inbuffer[idx].v, inbuffer[idx].length, salt->salt,
			salt->saltlen, salt->bytes, outbuffer[idx].v, salt->key_len);
}

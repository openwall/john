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
void pgpwde_kdf(__global const uchar *ipassword, const uint plen,
                __constant uchar *isalt, /*uint saltlen,*/ uint cbytes,
                __global uchar *okey /*, uint key_length*/)
{
	const uint saltlen = 16;
	uint key_length = 32;
	const uint num = (key_length - 1) / SHA1_DIGEST_LENGTH + 1; // Always 2
	uint i;
	uchar password[PLAINTEXT_LENGTH];
	uchar salt[16];

	memcpy_cp(salt, isalt, saltlen);
	memcpy_gp(password, ipassword, plen);
	if (cbytes < plen + 16)
		cbytes = (uint32_t)(plen + 16);

	for (i = 0; i < num; i++) {
		SHA_CTX ctx;
		uint bytes;
		const uint b[1] = { 0 };
		uchar key[SHA1_DIGEST_LENGTH];

		bytes = cbytes;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (uchar*)b, i);

		while (bytes > plen + 16) {
			SHA1_Update(&ctx, salt, 16);
			SHA1_Update(&ctx, password, plen);
			bytes -= plen + 16;
		}
		if (bytes <= 16) {
			SHA1_Update(&ctx, salt, bytes);
		} else {
			SHA1_Update(&ctx, salt, 16);
			SHA1_Update(&ctx, password, bytes - 16);
		}
		SHA1_Final(key, &ctx);
		memcpy_pg(okey + (i * SHA1_DIGEST_LENGTH), key,
		          MIN(key_length, SHA1_DIGEST_LENGTH));
		key_length -= SHA1_DIGEST_LENGTH;
	}
}

__kernel void pgpwde(__global const pgpwde_password *inbuffer,
                  __global pgpwde_hash *outbuffer,
                  __constant pgpwde_salt *salt)
{
	uint idx = get_global_id(0);

	pgpwde_kdf(inbuffer[idx].v, inbuffer[idx].length, salt->salt,
	           /*salt->saltlen,*/ salt->bytes, outbuffer[idx].v
	           /*, salt->key_len*/);
}

/*
 * This software is Copyright (c) 2017 Dhiru Kholia <dhiru at openwall.com> and
 * Copyright (c) 2017-2018 magnum, and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#include "opencl_sha1_ctx.h"
#define AES_NO_BITSLICE
#include "opencl_aes.h"
#include "opencl_twofish.h"
#include "opencl_cast.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

typedef struct {
	uint length;
	uchar v[PLAINTEXT_LENGTH];
} pgpdisk_password;

typedef struct {
	uchar v[BINARY_SIZE];
} pgpdisk_hash;

typedef struct {
	uint saltlen;
	uint iterations;
	uint key_len;
	uint algorithm;
	uchar salt[16];
} pgpdisk_salt;

inline void pgpdisk_kdf(__global const uchar *ipassword, const uint plen,
                        __constant uchar *isalt, const uint saltlen,
                        const uint iterations, uchar *okey, uint bytesNeeded)
{
	uint32_t offset = 0;
	uchar password[PLAINTEXT_LENGTH];
	uchar salt[16];

	memcpy_cp(salt, isalt, saltlen);
	memcpy_gp(password, ipassword, plen);

	while (bytesNeeded) {
		SHA_CTX ctx;
		uchar key[SHA1_DIGEST_LENGTH];
		uint32_t i;
		uint32_t bytesThisTime = MIN(SHA1_DIGEST_LENGTH, bytesNeeded);

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
		memcpy_pp(okey + offset, key, bytesThisTime);

		bytesNeeded -= bytesThisTime;
		offset += bytesThisTime;
	}
}

__kernel void pgpdisk_aes(__global const pgpdisk_password *inbuffer,
                          __global pgpdisk_hash *outbuffer,
                          __constant pgpdisk_salt *salt)
{
	uint idx = get_global_id(0);
	uchar key[32];
	AES_KEY aes_key;

	pgpdisk_kdf(inbuffer[idx].v, inbuffer[idx].length,
	            salt->salt, salt->saltlen, salt->iterations,
	            key, salt->key_len);

	AES_set_encrypt_key(key, 256, &aes_key);
	AES_encrypt(key, key, &aes_key);

	memcpy_pg(outbuffer[idx].v, key, BINARY_SIZE);
}

__kernel void pgpdisk_twofish(__global const pgpdisk_password *inbuffer,
                              __global pgpdisk_hash *outbuffer,
                              __constant pgpdisk_salt *salt)
{
	uint idx = get_global_id(0);
	uchar key[32];
	Twofish_key tkey;

	pgpdisk_kdf(inbuffer[idx].v, inbuffer[idx].length,
	            salt->salt, salt->saltlen, salt->iterations,
	            key, salt->key_len);

	Twofish_prepare_key(key, salt->key_len, &tkey);
	Twofish_encrypt(&tkey, key, key);

	memcpy_pg(outbuffer[idx].v, key, BINARY_SIZE);
}

__kernel void pgpdisk_cast(__global const pgpdisk_password *inbuffer,
                           __global pgpdisk_hash *outbuffer,
                           __constant pgpdisk_salt *salt)
{
	uint idx = get_global_id(0);
	uchar key[32];
	CAST_KEY ck;

	pgpdisk_kdf(inbuffer[idx].v, inbuffer[idx].length,
	            salt->salt, salt->saltlen, salt->iterations,
	            key, salt->key_len);

	CAST_set_key(&ck, 16, key);
	CAST_ecb_encrypt(key, key, &ck);
	memset_p(key + 8, 0, 8);

	memcpy_pg(outbuffer[idx].v, key, BINARY_SIZE);
}

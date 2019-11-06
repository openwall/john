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
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

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
	uint cracked;
} pgpwde_hash;

typedef struct {
	uint saltlen;
	uint bytes;
	uint key_len;
	uchar salt[16];
	uchar esk[128];
} pgpwde_salt;

#ifndef __MESA__
inline
#endif
void pgpwde_kdf(__global const uchar *ipassword, const uint plen,
                __constant uchar *isalt, uint cbytes, uint *okey)
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
		uint key[SHA1_DIGEST_LENGTH / 4];

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
		SHA1_Final((uchar*)key, &ctx);
		memcpy_pp(okey + (i * SHA1_DIGEST_LENGTH / 4), key,
		          MIN(key_length, SHA1_DIGEST_LENGTH));
		key_length -= SHA1_DIGEST_LENGTH;
	}
}

inline int PKCS1oaepMGF1Unpack(uchar *in, uint32_t inlen)
{
	const uint32_t hashlen = SHA1_DIGEST_LENGTH;
	const uchar nullhash[20] = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
	                             0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
	                             0xaf, 0xd8, 0x07, 0x09 };
	uint msg[32];
	uint hash[5];
	uint32_t l;
	uint32_t counter = 0;
	uchar counter_bytes[4] = { 0 };
	uint i, j;
	SHA_CTX ctx;

	SHA1_Init(&ctx);

	memcpy_pp(msg, in + 1, inlen - 1); // remove leading zero

	/* Get original seed */
	SHA1_Update(&ctx, in + 1 + hashlen, inlen - 1 - hashlen);
	SHA1_Update(&ctx, counter_bytes, 4);
	SHA1_Final((uchar*)hash, &ctx); // MGF output is hash(masked_message 00 00 00 00)

	l = hashlen/sizeof(uint32_t);
	for (i = 0; i < l; i++)
		msg[i] ^= hash[i];

	/* Unmask original message */
	i = hashlen / sizeof(uint32_t);
	while (i < inlen/sizeof(uint32_t))  {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (uchar*)msg, hashlen); // hash(seed)
		counter_bytes[3] = (uchar)counter;
		counter_bytes[2] = (uchar)(counter>>8);
		counter_bytes[1] = (uchar)(counter>>16);
		counter_bytes[0] = (uchar)(counter>>24);
		counter++;
		SHA1_Update(&ctx, counter_bytes, 4);
		SHA1_Final((uchar*)hash, &ctx); // hash(seed || counter)

		l = hashlen / sizeof(uint32_t);
		for (j = 0; j < l && i + j < inlen / sizeof(uint32_t); j++)
			msg[i + j] ^= hash[j];
		i += l;
	}

	/* Determine the size of original message.
	 * We have seed || hash(p) || 0...0 || 01 || M */
	for (i = 2 * hashlen; i < inlen - 1; i++)
		if (((uchar*)msg)[i])
			break;

	if (i == inlen - 1 || ((uchar*)msg)[i] != 1)
		return -1; // corrupt data

	// check parameters hash
	return memcmp_pp(nullhash, msg + hashlen / 4, hashlen);
}

inline int pgpwde_decrypt_and_verify(uchar *key, __constant uchar *esk)
{
	AES_KEY aes_key;
	uchar iv[16] = { 8, 0 };
	uchar out[128];

	AES_set_decrypt_key(key, 256, &aes_key);
	AES_cbc_decrypt(esk, out, 16, &aes_key, iv);
	if (out[0]) // Early reject, this should be 0
		return 0;
	AES_cbc_decrypt(esk + 16, out + 16, 128 - 16, &aes_key, iv);

	return !PKCS1oaepMGF1Unpack(out, 128);
}

__kernel void pgpwde(__global const pgpwde_password *inbuffer,
                  __global pgpwde_hash *outbuffer,
                  __constant pgpwde_salt *salt)
{
	uint idx = get_global_id(0);
	uint key[8];

	pgpwde_kdf(inbuffer[idx].v, inbuffer[idx].length, salt->salt,
	           salt->bytes, key);

	outbuffer[idx].cracked = pgpwde_decrypt_and_verify((uchar*)key, salt->esk);
}

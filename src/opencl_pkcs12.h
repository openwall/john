/*
 * This software is Copyright (c) 2017 Dhiru Kholia <kholia at kth dot se>,
 * Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_sha1_ctx.h"
#include "opencl_sha1.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

#define PKCS12_MAX_PWDLEN (PLAINTEXT_LENGTH * 2)

inline void pkcs12_fill_buffer(uint *data, uint data_len,
                               const uint *filler, uint fill_len)
{
	uchar *p = (uchar*)data;

	if ((fill_len & 0x03) == 0) {
		while (data_len > 0) {
			uint i;
			uint use_len = (data_len > fill_len) ? fill_len : data_len;

			for (i = 0; i < (use_len / 4); i++)
				((uint*)p)[i] = filler[i];
			p += use_len;
			data_len -= use_len;
		}
	} else {
		while (data_len > 0) {
			uint i;
			uint use_len = (data_len > fill_len) ? fill_len : data_len;

			for (i = 0; i < use_len; i++)
				p[i] = ((uchar*)filler)[i];
			p += use_len;
			data_len -= use_len;
		}
	}
}

inline void pkcs12_pbe_derive_key(uint iterations, int id,
                                  const uint *pwd, uint pwdlen,
                                  const uint *salt,
                                  uint saltlen, uint *key, uint keylen)
{
	uint i;
	union {
		ushort s[PKCS12_MAX_PWDLEN + 1];
		uint w[1];
	} unipwd;
	uint j, k;
	uint diversifier[64 / 4];
	uint salt_block[64 / 4], pwd_block[128 / 4], hash_block[64 / 4];
	uint hash_output[20 / 4];
	uint *p;
	uchar c;
	uint hlen, use_len, v, v2, datalen;
	SHA_CTX md_ctx;
	const uint idw = id | (id << 8) | (id << 16) | (id << 24);

	for (i = 0; i < pwdlen; i++)
		unipwd.s[i] = ((uchar*)pwd)[i] << 8;
	unipwd.s[i] = 0;

	pwdlen =  pwdlen * 2 + 2;
	pwd = unipwd.w;

	hlen = 20;	// for SHA1
	v = 64;
	v2 = ((pwdlen+64-1)/64)*64;

	// memset(diversifier, (uchar)id, v);
	for (k = 0; k < v / 4; k++)
		diversifier[k] = idw;

	pkcs12_fill_buffer(salt_block, v, salt, saltlen);
	pkcs12_fill_buffer(pwd_block,  v2, pwd,  pwdlen);

	p = key; // data
	datalen = keylen;
	while (datalen > 0) {
		// Calculate hash(diversifier || salt_block || pwd_block)
		SHA1_Init(&md_ctx);
		SHA1_Update(&md_ctx, (uchar*)diversifier, v);
		SHA1_Update(&md_ctx, (uchar*)salt_block, v);
		SHA1_Update(&md_ctx, (uchar*)pwd_block, v2);
		SHA1_Final((uchar*)hash_output, &md_ctx);

		hash_output[0] = SWAP32(hash_output[0]);
		hash_output[1] = SWAP32(hash_output[1]);
		hash_output[2] = SWAP32(hash_output[2]);
		hash_output[3] = SWAP32(hash_output[3]);
		hash_output[4] = SWAP32(hash_output[4]);

		// Perform remaining (iterations - 1) recursive hash calculations
		for (i = 1; i < iterations; i++) {
			uint W[16];

			W[0] = hash_output[0];
			W[1] = hash_output[1];
			W[2] = hash_output[2];
			W[3] = hash_output[3];
			W[4] = hash_output[4];
			W[5] = 0x80000000;
			W[15] = 20 << 3;
			sha1_single_160Z(uint, W, hash_output);
		}
		hash_output[0] = SWAP32(hash_output[0]);
		hash_output[1] = SWAP32(hash_output[1]);
		hash_output[2] = SWAP32(hash_output[2]);
		hash_output[3] = SWAP32(hash_output[3]);
		hash_output[4] = SWAP32(hash_output[4]);

		use_len = (datalen > hlen) ? hlen : datalen;
		for (k = 0; k < use_len / 4; k++)
			p[k] = hash_output[k];

		datalen -= use_len;
		p += use_len / 4;

		if (datalen == 0)
			break;

		// Concatenating copies of hash_output into hash_block (B)
		pkcs12_fill_buffer(hash_block, v, hash_output, hlen);

		// B += 1
		for (i = v; i > 0; i--)
			if (++((uchar*)hash_block)[i - 1] != 0)
				break;

		// salt_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = ((uchar*)salt_block)[i - 1] + ((uchar*)hash_block)[i - 1] + c;
			c = (uchar)(j >> 8);
			((uchar*)salt_block)[i - 1] = j & 0xFF;
		}

		// pwd_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = ((uchar*)pwd_block)[i - 1] + ((uchar*)hash_block)[i - 1] + c;
			c = (uchar)(j >> 8);
			((uchar*)pwd_block)[i - 1] = j & 0xFF;
		}
	}
}

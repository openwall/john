/*
 * This software is Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha1_unsplit_kernel.cl"
#include "opencl_sha1_ctx.h"

#define WINZIP_BINARY_SIZE 10

typedef struct {
	uint32_t iterations;
	uint32_t key_len;
	uint32_t length;
	uint8_t  salt[64];
	uint32_t comp_len;
	uchar    passverify[2];
} zip_salt;

inline void hmac_sha1(__global const uchar *_key, uint key_len,
                      __global const uchar *data, uint data_len,
                      __global uchar *digest, uint digest_len)
{
	union {
		uchar c[64];
		uint w[64/4];
	} buf;
	uchar local_digest[20];
	uint *pW = (uint*)buf.w;
	SHA_CTX ctx;
	uint i;

#if 0
	if (key_len > 64) {
		SHA1_Init(&ctx);
		while (key_len) {
			uchar pbuf[64];
			uint len = MIN(data_len, (uint)sizeof(pbuf));

			memcpy_macro(pbuf, _key, len);
			SHA1_Update(&ctx, pbuf, len);
			data_len -= len;
			_key += len;
		}
		SHA1_Final(buf.c, &ctx);
		pW[0] ^= 0x36363636;
		pW[1] ^= 0x36363636;
		pW[2] ^= 0x36363636;
		pW[3] ^= 0x36363636;
		pW[4] ^= 0x36363636;
		memset_p(&buf.c[20], 0x36, 44);
	} else
#endif
	{
		memcpy_macro(buf.c, _key, key_len);
		memset_p(&buf.c[key_len], 0, 64 - key_len);
		for (i = 0; i < 16; i++)
			pW[i] ^= 0x36363636;
	}
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, buf.c, 64);
	while (data_len) {
		uchar pbuf[64];
		uint len = MIN(data_len, (uint)sizeof(pbuf));

		memcpy_macro(pbuf, data, len);
		SHA1_Update(&ctx, pbuf, len);
		data_len -= len;
		data += len;
	}
	SHA1_Final(local_digest, &ctx);
	for (i = 0; i < 16; i++)
		pW[i] ^= (0x36363636 ^ 0x5c5c5c5c);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, buf.c, 64);
	SHA1_Update(&ctx, local_digest, 20);
	SHA1_Final(local_digest, &ctx);

	memcpy_pg(digest, local_digest, digest_len);
}

__kernel void zip(__global const pbkdf2_password *inbuffer,
                  __global pbkdf2_hash *outbuffer,
                  __constant zip_salt *salt,
                  __global const uchar *saltdata)
{
	uint idx = get_global_id(0);

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
	       salt->salt, salt->length, salt->iterations,
	       outbuffer[idx].v, 2, 2 * salt->key_len);

	if (*(__global ushort*)outbuffer[idx].v ==
	    *(__constant ushort*)salt->passverify) {

		pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
		       salt->salt, salt->length, salt->iterations,
		       outbuffer[idx].v, salt->key_len, salt->key_len);
		hmac_sha1((__global uchar*)outbuffer[idx].v, salt->key_len,
		          saltdata, salt->comp_len,
		          (__global uchar*)outbuffer[idx].v, WINZIP_BINARY_SIZE);
	} else
		memset_g(outbuffer[idx].v, 0, WINZIP_BINARY_SIZE);
}

/*
 * This software is Copyright (c) 2020 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_md5_ctx.h"

#ifdef HMAC_KEY_TYPE
#define USE_KEY_BUF
#else
#define HMAC_KEY_TYPE const
#endif

#ifdef HMAC_MSG_TYPE
#define USE_DATA_BUF
#else
#define HMAC_MSG_TYPE const
#endif

#ifndef HMAC_OUT_TYPE
#define HMAC_OUT_TYPE
#endif

inline void hmac_md5(HMAC_KEY_TYPE void *_key, uint key_len,
                     HMAC_MSG_TYPE void *_data, uint data_len,
                     HMAC_OUT_TYPE void *_digest, uint digest_len)
{
	HMAC_KEY_TYPE uchar *key = _key;
	HMAC_MSG_TYPE uchar *data = _data;
	HMAC_OUT_TYPE uchar *digest = _digest;
	union {
		uint pW[16];
		uchar buf[64];
	} u;
	uchar local_digest[16];
	MD5_CTX ctx;
	uint i;

#if HMAC_KEY_GT_64
	if (key_len > 64) {
		MD5_Init(&ctx);
#ifdef USE_KEY_BUF
		while (key_len) {
			uchar pbuf[64];
			uint len = MIN(key_len, (uint)sizeof(pbuf));

			memcpy_macro(pbuf, key, len);
			MD5_Update(&ctx, pbuf, len);
			key_len -= len;
			key += len;
		}
#else
		MD5_Update(&ctx, key, key_len);
#endif
		MD5_Final(u.buf, &ctx);
		u.pW[0] ^= 0x36363636;
		u.pW[1] ^= 0x36363636;
		u.pW[2] ^= 0x36363636;
		u.pW[3] ^= 0x36363636;
		memset_p(&u.buf[16], 0x36, 64 - 16);
	} else
#endif
	{
		memcpy_macro(u.buf, key, key_len);
		memset_p(&u.buf[key_len], 0, 64 - key_len);
		for (i = 0; i < 16; i++)
			u.pW[i] ^= 0x36363636;
	}
	MD5_Init(&ctx);
	MD5_Update(&ctx, u.buf, 64);
#ifdef USE_DATA_BUF
	HMAC_MSG_TYPE uint *data32 = (HMAC_MSG_TYPE uint*)_data;
	uint blocks = data_len / 64;
	data_len -= 64 * blocks;
	data += 64 * blocks;
	ctx.total += 64 * blocks;
	while (blocks--) {
		uint W[16];

		memcpy_macro(W, data32, 16);
		md5_block(uint, W, ctx.state);
		data32 += 16;
	}
	uchar pbuf[64];
	memcpy_macro(pbuf, data, data_len);
	MD5_Update(&ctx, pbuf, data_len);
#else
	MD5_Update(&ctx, data, data_len);
#endif
	MD5_Final(local_digest, &ctx);
	for (i = 0; i < 16; i++)
		u.pW[i] ^= (0x36363636 ^ 0x5c5c5c5c);
	MD5_Init(&ctx);
	MD5_Update(&ctx, u.buf, 64);
	MD5_Update(&ctx, local_digest, 16);
	MD5_Final(local_digest, &ctx);

	memcpy_macro(digest, local_digest, digest_len);
}

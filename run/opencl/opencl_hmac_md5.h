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
#define HMAC_KEY_TYPE __private
#endif

#ifdef HMAC_MSG_TYPE
#define USE_DATA_BUF
#else
#define HMAC_MSG_TYPE __private const
#endif

#ifndef HMAC_OUT_TYPE
#define HMAC_OUT_TYPE __private
#endif

inline void hmac_md5(HMAC_KEY_TYPE const void *_key, uint key_len,
                     HMAC_MSG_TYPE void *_data, uint data_len,
                     HMAC_OUT_TYPE void *_digest, uint digest_len)
{
	HMAC_KEY_TYPE const uchar *key = _key;
	HMAC_MSG_TYPE uchar *data = _data;
	HMAC_OUT_TYPE uchar *digest = _digest;
	uint pW[16];
	uchar *buf = (uchar*)pW;
	uchar local_digest[16];
	SHA_CTX ctx;
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
			data_len -= len;
			key += len;
		}
#else
		MD5_Update(&ctx, key, key_len);
#endif
		MD5_Final(buf, &ctx);
		pW[0] ^= 0x36363636;
		pW[1] ^= 0x36363636;
		pW[2] ^= 0x36363636;
		pW[3] ^= 0x36363636;
		memset_p(&buf[16], 0x36, 64 - 16);
	} else
#endif
	{
		memcpy_macro(buf, key, key_len);
		memset_p(&buf[key_len], 0, 64 - key_len);
		for (i = 0; i < 16; i++)
			pW[i] ^= 0x36363636;
	}
	MD5_Init(&ctx);
	MD5_Update(&ctx, buf, 64);
#ifdef USE_DATA_BUF
	while (data_len) {
		uchar pbuf[64];
		uint len = MIN(data_len, (uint)sizeof(pbuf));

		memcpy_macro(pbuf, data, len);
		MD5_Update(&ctx, pbuf, len);
		data_len -= len;
		data += len;
	}
#else
	MD5_Update(&ctx, data, data_len);
#endif
	MD5_Final(local_digest, &ctx);
	for (i = 0; i < 16; i++)
		pW[i] ^= (0x36363636 ^ 0x5c5c5c5c);
	MD5_Init(&ctx);
	MD5_Update(&ctx, buf, 64);
	MD5_Update(&ctx, local_digest, 16);
	MD5_Final(local_digest, &ctx);

	memcpy_macro(digest, local_digest, digest_len);
}

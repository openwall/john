/*
 * This software is Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_sha2_ctx.h"

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

inline void hmac_sha256(HMAC_KEY_TYPE void *_key, uint key_len,
                        HMAC_MSG_TYPE void *_data, uint data_len,
                        HMAC_OUT_TYPE void *_digest, uint digest_len)
{
	HMAC_KEY_TYPE uchar *key = _key;
	HMAC_MSG_TYPE uchar *data = _data;
	HMAC_OUT_TYPE uchar *digest = _digest;
	uint pW[16];
	uchar *buf = (uchar*)pW;
	uchar local_digest[32];
	SHA256_CTX ctx;
	uint i;

#if HMAC_KEY_GT_64
	if (key_len > 64) {
		SHA256_Init(&ctx);
#ifdef USE_KEY_BUF
		while (key_len) {
			uchar pbuf[64];
			uint len = MIN(key_len, (uint)sizeof(pbuf));

			memcpy_macro(pbuf, key, len);
			SHA256_Update(&ctx, pbuf, len);
			data_len -= len;
			key += len;
		}
#else
		SHA256_Update(&ctx, key, key_len);
#endif
		SHA256_Final(buf, &ctx);
		pW[0] ^= 0x36363636;
		pW[1] ^= 0x36363636;
		pW[2] ^= 0x36363636;
		pW[3] ^= 0x36363636;
		pW[4] ^= 0x36363636;
		pW[5] ^= 0x36363636;
		pW[6] ^= 0x36363636;
		pW[7] ^= 0x36363636;
		memset_p(&buf[32], 0x36, 32);
	} else
#endif
	{
		memcpy_macro(buf, key, key_len);
		memset_p(&buf[key_len], 0, 64 - key_len);
		for (i = 0; i < 16; i++)
			pW[i] ^= 0x36363636;
	}
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, 64);
#ifdef USE_DATA_BUF
	while (data_len) {
		uchar pbuf[64];
		uint len = MIN(data_len, (uint)sizeof(pbuf));

		memcpy_macro(pbuf, data, len);
		SHA256_Update(&ctx, pbuf, len);
		data_len -= len;
		data += len;
	}
#else
	SHA256_Update(&ctx, data, data_len);
#endif
	SHA256_Final(local_digest, &ctx);
	for (i = 0; i < 16; i++)
		pW[i] ^= (0x36363636 ^ 0x5c5c5c5c);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, 64);
	SHA256_Update(&ctx, local_digest, 32);
	SHA256_Final(local_digest, &ctx);

	memcpy_macro(digest, local_digest, digest_len);
}

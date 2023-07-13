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
	union {
		uint pW[16];
		uchar buf[64];
	} u;
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
			key_len -= len;
			key += len;
		}
#else
		SHA256_Update(&ctx, key, key_len);
#endif
		SHA256_Final(u.buf, &ctx);
		u.pW[0] ^= 0x36363636;
		u.pW[1] ^= 0x36363636;
		u.pW[2] ^= 0x36363636;
		u.pW[3] ^= 0x36363636;
		u.pW[4] ^= 0x36363636;
		u.pW[5] ^= 0x36363636;
		u.pW[6] ^= 0x36363636;
		u.pW[7] ^= 0x36363636;
		memset_p(&u.buf[32], 0x36, 64 - 32);
	} else
#endif
	{
		memcpy_macro(u.buf, key, key_len);
		memset_p(&u.buf[key_len], 0, 64 - key_len);
		for (i = 0; i < 16; i++)
			u.pW[i] ^= 0x36363636;
	}
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, u.buf, 64);
#ifdef USE_DATA_BUF
	HMAC_MSG_TYPE uint *data32 = (HMAC_MSG_TYPE uint*)_data;
	uint blocks = data_len / 64;
	data_len -= 64 * blocks;
	data += 64 * blocks;
	ctx.total += 64 * blocks;
	while (blocks--) {
		uint W[16];
		for (i = 0; i < 16; i++)
			W[i] = SWAP32(data32[i]);
		sha256_block(W, ctx.state);
		data32 += 16;
	}
	uchar pbuf[64];
	memcpy_macro(pbuf, data, data_len);
	SHA256_Update(&ctx, pbuf, data_len);
#else
	SHA256_Update(&ctx, data, data_len);
#endif
	SHA256_Final(local_digest, &ctx);
	for (i = 0; i < 16; i++)
		u.pW[i] ^= (0x36363636 ^ 0x5c5c5c5c);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, u.buf, 64);
	SHA256_Update(&ctx, local_digest, 32);
	SHA256_Final(local_digest, &ctx);

	memcpy_macro(digest, local_digest, digest_len);
}

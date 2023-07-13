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

inline void hmac_sha512(HMAC_KEY_TYPE void *_key, uint key_len,
                        HMAC_MSG_TYPE void *_data, uint data_len,
                        HMAC_OUT_TYPE void *_digest, uint digest_len)
{
	HMAC_KEY_TYPE uchar *key = _key;
	HMAC_MSG_TYPE uchar *data = _data;
	HMAC_OUT_TYPE uchar *digest = _digest;
	union {
		ulong pW[16];
		uchar buf[128];
	} u;
	uchar local_digest[64];
	SHA512_CTX ctx;
	uint i;

#if HMAC_KEY_GT_128
	if (key_len > 128) {
		SHA512_Init(&ctx);
#ifdef USE_KEY_BUF
		while (key_len) {
			uchar pbuf[128];
			uint len = MIN(key_len, (uint)sizeof(pbuf));

			memcpy_macro(pbuf, key, len);
			SHA512_Update(&ctx, pbuf, len);
			data_len -= len;
			key += len;
		}
#else
		SHA512_Update(&ctx, key, key_len);
#endif
		SHA512_Final(u.buf, &ctx);
		u.pW[0] ^= 0x3636363636363636UL;
		u.pW[1] ^= 0x3636363636363636UL;
		u.pW[2] ^= 0x3636363636363636UL;
		u.pW[3] ^= 0x3636363636363636UL;
		u.pW[4] ^= 0x3636363636363636UL;
		u.pW[5] ^= 0x3636363636363636UL;
		u.pW[6] ^= 0x3636363636363636UL;
		u.pW[7] ^= 0x3636363636363636UL;
		memset_p(&u.buf[64], 0x36, 128 - 64);
	} else
#endif
	{
		memcpy_macro(u.buf, key, key_len);
		memset_p(&u.buf[key_len], 0, 128 - key_len);
		for (i = 0; i < 16; i++)
			u.pW[i] ^= 0x3636363636363636UL;
	}
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, u.buf, 128);
#ifdef USE_DATA_BUF
	HMAC_MSG_TYPE ulong *data64 = (HMAC_MSG_TYPE ulong*)_data;
	uint blocks = data_len / 128;
	data_len -= 128 * blocks;
	data += 128 * blocks;
	ctx.total += 128 * blocks;
	while (blocks--) {
		ulong W[16];
		for (i = 0; i < 16; i++)
			W[i] = SWAP64(data64[i]);
		sha512_block(W, ctx.state);
		data64 += 16;
	}
	uchar pbuf[128];
	memcpy_macro(pbuf, data, data_len);
	SHA512_Update(&ctx, pbuf, data_len);
#else
	SHA512_Update(&ctx, data, data_len);
#endif
	SHA512_Final(local_digest, &ctx);
	for (i = 0; i < 16; i++)
		u.pW[i] ^= (0x3636363636363636UL ^ 0x5c5c5c5c5c5c5c5cUL);
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, u.buf, 128);
	SHA512_Update(&ctx, local_digest, 64);
	SHA512_Final(local_digest, &ctx);

	memcpy_macro(digest, local_digest, digest_len);
}

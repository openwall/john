/*
 * free 'simple' hmac_sha1. Public domain, 2015, JimF.
 * Built for John source to replace other code.
 *
 * This software was written by JimF jfoug AT cox dot net
 * in 2015. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2015 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

#include "arch.h"
#include "aligned.h"
#include "sha.h"
#include "common.h"
#include "stdint.h"

#if ARCH_BITS==64
#define HMAC_SHA1_COUNT    8
#define HMAC_SHA1_IPAD_XOR 0x3636363636363636ULL
#define HMAC_SHA1_OPAD_XOR (0x3636363636363636ULL^0x5c5c5c5c5c5c5c5cULL)
#else
#define HMAC_SHA1_COUNT    16
#define HMAC_SHA1_IPAD_XOR 0x36363636
#define HMAC_SHA1_OPAD_XOR (0x36363636^0x5c5c5c5c)
#endif

void JTR_hmac_sha1(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len) {
	JTR_ALIGN(sizeof(ARCH_WORD)) unsigned char buf[64];
	unsigned char int_digest[20];
	ARCH_WORD *pW = (ARCH_WORD *)buf;
	unsigned i;
	SHA_CTX ctx;

	if (key_len > 64) {
		uint32_t *p = (uint32_t*)buf;
		SHA_Init(&ctx);
		SHA1_Update(&ctx, key, key_len);
		SHA1_Final(buf, &ctx);
		p[0] ^= 0x36363636; p[1] ^= 0x36363636; p[2] ^= 0x36363636; p[3] ^= 0x36363636; p[4] ^= 0x36363636;
		memset(&buf[20], 0x36, 44);
	} else {
		memcpy(buf, key, key_len);
		memset(&buf[key_len], 0, 64-key_len);
		for (i = 0; i < HMAC_SHA1_COUNT; ++i)
			pW[i] ^= HMAC_SHA1_IPAD_XOR;
	}
	SHA_Init(&ctx);
	SHA1_Update(&ctx, buf, 64);
	if (data_len)
		SHA1_Update(&ctx, data, data_len);
	SHA1_Final(int_digest, &ctx);
	for (i = 0; i < HMAC_SHA1_COUNT; ++i)
		pW[i] ^= HMAC_SHA1_OPAD_XOR;
	SHA_Init(&ctx);
	SHA1_Update(&ctx, buf, 64);
	SHA1_Update(&ctx, int_digest, 20);
	if (digest_len >= 20)
		SHA1_Final(digest, &ctx);
	else {
		SHA1_Final(int_digest, &ctx);
		memcpy(digest, int_digest, digest_len);
	}
}

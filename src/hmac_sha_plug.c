/*
 * free 'simple' hmac_sha*. Public domain, 2015, JimF.
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

#include <stdint.h>

#include "arch.h"
#include "aligned.h"
#include "sha.h"
#include "sha2.h"
#include "common.h"

#if ARCH_BITS==64
#define HMAC_SHA32_COUNT  8
#define HMAC_SHA64_COUNT  16
#define HMAC_SHA_IPAD_XOR 0x3636363636363636ULL
#define HMAC_SHA_OPAD_XOR (0x3636363636363636ULL^0x5c5c5c5c5c5c5c5cULL)
#else
#define HMAC_SHA32_COUNT  16
#define HMAC_SHA64_COUNT  32
#define HMAC_SHA_IPAD_XOR 0x36363636
#define HMAC_SHA_OPAD_XOR (0x36363636^0x5c5c5c5c)
#endif

void JTR_hmac_sha1(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len) {
	JTR_ALIGN(8) unsigned char buf[64];
	unsigned char local_digest[20];
	ARCH_WORD *pW = (ARCH_WORD *)buf;
	unsigned i;
	SHA_CTX ctx;

	if (key_len > 64) {
		uint32_t *p = (uint32_t*)buf;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, key, key_len);
		SHA1_Final(buf, &ctx);
		p[0] ^= 0x36363636; p[1] ^= 0x36363636; p[2] ^= 0x36363636; p[3] ^= 0x36363636; p[4] ^= 0x36363636;
		memset(&buf[20], 0x36, 44);
	} else {
		memcpy(buf, key, key_len);
		memset(&buf[key_len], 0, 64-key_len);
		for (i = 0; i < HMAC_SHA32_COUNT; ++i)
			pW[i] ^= HMAC_SHA_IPAD_XOR;
	}
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, buf, 64);
	if (data_len)
		SHA1_Update(&ctx, data, data_len);
	SHA1_Final(local_digest, &ctx);
	for (i = 0; i < HMAC_SHA32_COUNT; ++i)
		pW[i] ^= HMAC_SHA_OPAD_XOR;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, buf, 64);
	SHA1_Update(&ctx, local_digest, 20);
	if (digest_len >= 20)
		SHA1_Final(digest, &ctx);
	else {
		SHA1_Final(local_digest, &ctx);
		memcpy(digest, local_digest, digest_len);
	}
}

void JTR_hmac_sha256(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len) {
	JTR_ALIGN(8) unsigned char buf[64];
	unsigned char local_digest[32];
	ARCH_WORD *pW = (ARCH_WORD *)buf;
	unsigned i;
	SHA256_CTX ctx;

	if (key_len > 64) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, key_len);
		SHA256_Final(buf, &ctx);
		for (i = 0; i < HMAC_SHA32_COUNT/2; ++i)
			pW[i] ^= HMAC_SHA_IPAD_XOR;
		for (; i < HMAC_SHA32_COUNT; ++i)
			pW[i] = HMAC_SHA_IPAD_XOR;
	} else {
		memcpy(buf, key, key_len);
		memset(&buf[key_len], 0, 64-key_len);
		for (i = 0; i < HMAC_SHA32_COUNT; ++i)
			pW[i] ^= HMAC_SHA_IPAD_XOR;
	}
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, 64);
	if (data_len)
		SHA256_Update(&ctx, data, data_len);
	SHA256_Final(local_digest, &ctx);
	for (i = 0; i < HMAC_SHA32_COUNT; ++i)
		pW[i] ^= HMAC_SHA_OPAD_XOR;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, 64);
	SHA256_Update(&ctx, local_digest, 32);
	if (digest_len >= 32)
		SHA256_Final(digest, &ctx);
	else {
		SHA256_Final(local_digest, &ctx);
		memcpy(digest, local_digest, digest_len);
	}
}

void JTR_hmac_sha224(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len) {
	JTR_ALIGN(8) unsigned char buf[64];
	unsigned char local_digest[28];
	ARCH_WORD *pW = (ARCH_WORD *)buf;
	unsigned i;
	SHA256_CTX ctx;

	if (key_len > 64) {
		SHA224_Init(&ctx);
		SHA224_Update(&ctx, key, key_len);
		SHA224_Final(buf, &ctx);
		memset(&buf[28], 0, 4);
		for (i = 0; i < HMAC_SHA32_COUNT/2; ++i)
			pW[i] ^= HMAC_SHA_IPAD_XOR;
		for (; i < HMAC_SHA32_COUNT; ++i)
			pW[i] = HMAC_SHA_IPAD_XOR;
	} else {
		memcpy(buf, key, key_len);
		memset(&buf[key_len], 0, 64-key_len);
		for (i = 0; i < HMAC_SHA32_COUNT; ++i)
			pW[i] ^= HMAC_SHA_IPAD_XOR;
	}
	SHA224_Init(&ctx);
	SHA224_Update(&ctx, buf, 64);
	if (data_len)
		SHA224_Update(&ctx, data, data_len);
	SHA224_Final(local_digest, &ctx);
	for (i = 0; i < HMAC_SHA32_COUNT; ++i)
		pW[i] ^= HMAC_SHA_OPAD_XOR;
	SHA224_Init(&ctx);
	SHA224_Update(&ctx, buf, 64);
	SHA224_Update(&ctx, local_digest, 28);
	if (digest_len >= 28)
		SHA224_Final(digest, &ctx);
	else {
		SHA224_Final(local_digest, &ctx);
		memcpy(digest, local_digest, digest_len);
	}
}

void JTR_hmac_sha512(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len) {
	JTR_ALIGN(8) unsigned char buf[128];
	unsigned char local_digest[64];
	ARCH_WORD *pW = (ARCH_WORD *)buf;
	unsigned i;
	SHA512_CTX ctx;

	if (key_len > 128) {
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, key, key_len);
		SHA512_Final(buf, &ctx);
		for (i = 0; i < HMAC_SHA64_COUNT/2; ++i)
			pW[i] ^= HMAC_SHA_IPAD_XOR;
		for (; i < HMAC_SHA64_COUNT; ++i)
			pW[i] = HMAC_SHA_IPAD_XOR;
	} else {
		memcpy(buf, key, key_len);
		memset(&buf[key_len], 0, 128-key_len);
		for (i = 0; i < HMAC_SHA64_COUNT; ++i)
			pW[i] ^= HMAC_SHA_IPAD_XOR;
	}
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, buf, 128);
	if (data_len)
		SHA512_Update(&ctx, data, data_len);
	SHA512_Final(local_digest, &ctx);
	for (i = 0; i < HMAC_SHA64_COUNT; ++i)
		pW[i] ^= HMAC_SHA_OPAD_XOR;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, buf, 128);
	SHA512_Update(&ctx, local_digest, 64);
	if (digest_len >= 64)
		SHA512_Final(digest, &ctx);
	else {
		SHA512_Final(local_digest, &ctx);
		memcpy(digest, local_digest, digest_len);
	}
}

void JTR_hmac_sha384(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len) {
	JTR_ALIGN(8) unsigned char buf[128];
	unsigned char local_digest[48];
	ARCH_WORD *pW = (ARCH_WORD *)buf;
	unsigned i;
	SHA512_CTX ctx;

	if (key_len > 128) {
		SHA384_Init(&ctx);
		SHA384_Update(&ctx, key, key_len);
		SHA384_Final(buf, &ctx);
		memset(&buf[48], 0, 16);
		for (i = 0; i < HMAC_SHA64_COUNT/2; ++i)
			pW[i] ^= HMAC_SHA_IPAD_XOR;
		for (; i < HMAC_SHA64_COUNT; ++i)
			pW[i] = HMAC_SHA_IPAD_XOR;
	} else {
		memcpy(buf, key, key_len);
		memset(&buf[key_len], 0, 128-key_len);
		for (i = 0; i < HMAC_SHA64_COUNT; ++i)
			pW[i] ^= HMAC_SHA_IPAD_XOR;
	}
	SHA384_Init(&ctx);
	SHA384_Update(&ctx, buf, 128);
	if (data_len)
		SHA384_Update(&ctx, data, data_len);
	SHA384_Final(local_digest, &ctx);
	for (i = 0; i < HMAC_SHA64_COUNT; ++i)
		pW[i] ^= HMAC_SHA_OPAD_XOR;
	SHA384_Init(&ctx);
	SHA384_Update(&ctx, buf, 128);
	SHA384_Update(&ctx, local_digest, 48);
	if (digest_len >= 48)
		SHA384_Final(digest, &ctx);
	else {
		SHA384_Final(local_digest, &ctx);
		memcpy(digest, local_digest, digest_len);
	}
}

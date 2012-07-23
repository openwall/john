/*
* This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*
* hccap format was introduced by oclHashcat-plus, and it is described here: http://hashcat.net/wiki/hccap
* Code is based on  Aircrack-ng source
*/
#ifndef _WPAPSK_H
#define _WPAPSK_H

#include "arch.h"
#include "common.h"
#include "johnswap.h"

#include <assert.h>
#include <openssl/hmac.h>

#define HCCAP_SIZE		392
#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		ARCH_WORD_32

#define BINARY_SIZE		sizeof(mic_t)
#define PLAINTEXT_LENGTH	15
#define SALT_SIZE		sizeof(hccap_t)
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

/** if you want to change hccap_t structure is also defined in hccap2john.c **/
typedef struct
{
  char          essid[36];
  unsigned char mac1[6];
  unsigned char mac2[6];
  unsigned char nonce1[32];
  unsigned char nonce2[32];
  unsigned char eapol[256];
  int           eapol_size;
  int           keyver;
  unsigned char keymic[16];
} hccap_t;

typedef struct
{
  unsigned char keymic[16];
} mic_t;

typedef struct {
	uint8_t length;
	uint8_t v[15];
} wpapsk_password;

typedef struct {
	uint32_t v[8];
} wpapsk_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[15];
} wpapsk_salt;



/** Below are common variables used by wpapsk_fmt.c cuda_wpapsk_fmt.c and opencl_wpapsk_fmt.c **/

static hccap_t hccap;			///structure with hccap data
static wpapsk_salt currentsalt;		///structure for essid
static mic_t *mic;			///table for MIC keys
static wpapsk_password *inbuffer;	///table for candidate passwords
static wpapsk_hash *outbuffer;		///table for PMK calculated by GPU
static const char wpapsk_prefix[] = "$WPAPSK$";


/** Below are common functions used by wpapsk_fmt.c cuda_wpapsk_fmt.c and opencl_wpapsk_fmt.c **/

static hccap_t *decode_hccap(char *ciphertext)
{
	static hccap_t hccap;
	char *essid = ciphertext + strlen(wpapsk_prefix);
	char *hash = strrchr(ciphertext, '#');
	char *d = hccap.essid;
	char *cap = hash + 1;
	unsigned char tbuf[sizeof(hccap_t)];
	unsigned char *dst = tbuf;
	int i;

	if (hash == NULL)
		return &hccap;
	while (essid != hash) {	///copy essid to hccap
		*d++ = *essid++;
	}
	*d = '\0';
	assert(*essid == '#');

	for (i = 0; i < 118; i++) {
		dst[0] =
		    (atoi64[ARCH_INDEX(cap[0])] << 2) |
		    (atoi64[ARCH_INDEX(cap[1])] >> 4);
		dst[1] =
		    (atoi64[ARCH_INDEX(cap[1])] << 4) |
		    (atoi64[ARCH_INDEX(cap[2])] >> 2);
		dst[2] =
		    (atoi64[ARCH_INDEX(cap[2])] << 6) |
		    (atoi64[ARCH_INDEX(cap[3])]);
		dst += 3;
		cap += 4;
	}
	dst[0] =
	    (atoi64[ARCH_INDEX(cap[0])] << 2) |
	    (atoi64[ARCH_INDEX(cap[1])] >> 4);
	dst[1] =
	    (atoi64[ARCH_INDEX(cap[1])] << 4) |
	    (atoi64[ARCH_INDEX(cap[2])] >> 2);
	memcpy(&hccap.mac1,tbuf,sizeof(hccap_t)-36);

#if !ARCH_LITTLE_ENDIAN
	hccap.eapol_size = JOHNSWAP(hccap.eapol_size);
	hccap.keyver = JOHNSWAP(hccap.keyver);
#endif

	return &hccap;
}

static void *binary(char *ciphertext)
{
	static unsigned char binary[BINARY_SIZE];
	hccap_t *hccap = decode_hccap(ciphertext);
	memcpy(binary, hccap->keymic, BINARY_SIZE);
	return binary;
}

static void *salt(char *ciphertext)
{
	static hccap_t s;
	memcpy(&s, decode_hccap(ciphertext), SALT_SIZE);
	return &s;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *hash = strrchr(ciphertext, '#') + 1;
	int hashlength = 0;
	hccap_t *hccap;

	if (strncmp(ciphertext, wpapsk_prefix, strlen(wpapsk_prefix)) != 0)
		return 0;
	if (hash == NULL)
		return 0;
	while (hash < ciphertext + strlen(ciphertext)) {
		if (atoi64[ARCH_INDEX(*hash++)] == 0x7f)
			return 0;
		hashlength++;
	}
	if (hashlength != 475)
		return 0;
	hccap = decode_hccap(ciphertext);
#if !ARCH_LITTLE_ENDIAN
	hccap.eapol_size = JOHNSWAP(hccap->eapol_size);
#endif
	if(hccap->eapol_size > 256)
		return 0;
	if(hccap->eapol_size < 0)
		return 0;
	return 1;
}

static MAYBE_INLINE void prf_512(uint32_t * key, uint8_t * data, uint32_t * ret)
{
	unsigned int i;
	char *text = "Pairwise key expansion";
	unsigned char buff[100];

	memcpy(buff, text, 22);
	memcpy(buff + 23, data, 76);
	buff[22] = 0;
	for (i = 0; i < 4; i++) {
		HMAC_CTX ctx;
		buff[76 + 23] = i;
		HMAC_Init(&ctx, key, 32, EVP_sha1());
		HMAC_Update(&ctx, buff, 100);
		HMAC_Final(&ctx, (unsigned char *) ret, NULL);
		HMAC_CTX_cleanup(&ctx);
		ret += 5;
	}
}

static void set_salt(void *salt)
{
	memcpy(&hccap, salt, SALT_SIZE);
	strcpy((char*)currentsalt.salt, hccap.essid);
	currentsalt.length = strlen(hccap.essid);
}

#undef set_key
static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}
static void insert_mac(uint8_t * data)
{
	int k = memcmp(hccap.mac1, hccap.mac2, 6);
	if (k > 0) {
		memcpy(data, hccap.mac2, 6);
		memcpy(data + 6, hccap.mac1, 6);
	} else {
		memcpy(data, hccap.mac1, 6);
		memcpy(data + 6, hccap.mac2, 6);
	}
}

static void insert_nonce(uint8_t * data)
{
	int k = memcmp(hccap.nonce1, hccap.nonce2, 32);
	if (k > 0) {
		memcpy(data, hccap.nonce2, 32);
		memcpy(data + 32, hccap.nonce1, 32);
	} else {
		memcpy(data, hccap.nonce1, 32);
		memcpy(data + 32, hccap.nonce2, 32);
	}
}

static void wpapsk_postprocess(int keys)
{
	int i;
	uint8_t data[64 + 12];
	insert_mac(data);
	insert_nonce(data + 12);

	if (hccap.keyver == 1) {
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(keys, outbuffer, data, hccap, mic)
#endif
		for (i = 0; i < keys; i++) {
			uint32_t prf[20];
			prf_512(outbuffer[i].v, data, prf);
			HMAC(EVP_md5(), prf, 16, hccap.eapol, hccap.eapol_size,
			    mic[i].keymic, NULL);
		}
	} else {
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(keys, outbuffer, data, hccap, mic)
#endif
		for (i = 0; i < keys; i++) {
			uint32_t prf[20];
			unsigned char keymic[20];
			prf_512(outbuffer[i].v, data, prf);
			HMAC(EVP_sha1(), prf, 16, hccap.eapol,
			    hccap.eapol_size, keymic, NULL);
			memcpy(mic[i].keymic, keymic, 16);
		}
	}
}

static int binary_hash_0(void *binary)
{
#ifdef WPAPSK_DEBUG
	puts("binary");
	uint32_t i, *b = binary;

	for (i = 0; i < 4; i++)
		printf("%08x ", b[i]);
	puts("");
#endif
	return ((uint32_t *) binary)[0] & 0xf;
}

static int binary_hash_1(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((uint32_t *) binary)[0] & 0x7ffffff;
}

static int get_hash_0(int index)
{
#ifdef WPAPSK_DEBUG
	int i;
	puts("get_hash");
	uint32_t *b = (uint32_t *)mic[index].keymic;
	for (i = 0; i < 4; i++)
		printf("%08x ", b[i]);
	puts("");
#endif
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & 0xf;
}

static int get_hash_1(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & 0xff;
}

static int get_hash_2(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & 0xfff;
}

static int get_hash_3(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & 0xffff;
}

static int get_hash_4(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & 0xfffff;
}

static int get_hash_5(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & 0xffffff;
}

static int get_hash_6(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i, b = ((uint32_t *) binary)[0];
	for (i = 0; i < count; i++) {
		uint32_t *m = (uint32_t*) mic[i].keymic;
		if (b == m[0])
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	uint8_t i;
	uint32_t *b = (uint32_t*) binary;
	uint32_t *m = (uint32_t*) mic[index].keymic;
	for (i = 0; i < BINARY_SIZE / 4; i++)
		if (b[i] != m[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

#endif

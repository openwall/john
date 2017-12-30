/*
 * This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com>
 * and Copyright (c) 2012-2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * hccap format was introduced by oclHashcat-plus (now renamed to hashcat),
 * and it is described here: http://hashcat.net/wiki/hccap
 * Code is based on  Aircrack-ng source
 */
#ifndef _WPAPMK_H
#define _WPAPMK_H

#include <stdint.h>
#include <assert.h>
#if !AC_BUILT || HAVE_OPENSSL_CMAC_H
#include <openssl/cmac.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "johnswap.h"
#include "hmacmd5.h"
#include "hmac_sha.h"
#include "sha2.h"
#include "base64_convert.h"
#include "hccap.h"

#define BINARY_SIZE         sizeof(mic_t)
#define BINARY_ALIGN        4
#define PLAINTEXT_MIN_LEN   64
#define PLAINTEXT_LENGTH    64
#define SALT_SIZE           (sizeof(hccap_t) - sizeof(mic_t))
#define SALT_ALIGN          MEM_ALIGN_NONE
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define FORMAT_TAG          "$WPAPSK$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)

typedef struct
{
	unsigned char keymic[16];
} mic_t;

typedef struct {
	uint32_t length;
	uint8_t  v[PLAINTEXT_LENGTH + 1];
} wpapsk_password;

typedef struct {
	uint32_t v[8];
} wpapsk_hash;

typedef struct {
	uint32_t length;
#ifdef JOHN_OCL_WPAPMK
	uint8_t  eapol[256 + 64];
	uint32_t eapol_size;
	uint8_t  data[64 + 12];
#endif
	uint8_t  salt[36]; // essid
} wpapsk_salt;

static struct fmt_tests tests[] = {
	{"$WPAPSK$test#..qHuv0A..ZPYJBRzZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsRIfQN2Zar6EXp2BYcRuSkWEJIWjEJJvb4DWZCspbZ51.21.3zy.EY.6........../zZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsQ..................................................................BoK.31m.E2..31m.U2..31m.U2..31m.U................................................................................................................................................................................/X.....E...AkkDQmDg9837LBHG.dGlKA", "cdd79a5acfb070c7e9d1023b870285d639e430b32f31aa37ac825a55b55524ee"},
	{"$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI", "a288fcf0caaacda9a9f58633ff35e8992a01d9c10ba5e02efdf8cb5d730ce7bc"},
#if (!AC_BUILT || HAVE_OPENSSL_CMAC_H) || defined(JOHN_OCL_WPAPMK)
	{"$WPAPSK$Neheb#g9a8Jcre9D0WrPnEN4QXDbA5NwAy5TVpkuoChMdFfL/8Dus4i/X.lTnfwuw04ASqHgvo12wJYJywulb6pWM6C5uqiMPNKNe9pkr6LE61.5I0.Eg.2..........1N4QXDbA5NwAy5TVpkuoChMdFfL/8Dus4i/X.lTnfwuw.................................................................3X.I.E..1uk2.E..1uk2.E..1uk4X...................................................................................................................................................................................../t.....k...0sHl.mVkiHW.ryNchcMd4g", "fb57668cd338374412c26208d79aa5c30ce40a110224f3cfb592a8f2e8bf53e8"},
#endif
	{NULL}
};

/** Below are common variables used by wpapmk_fmt.c and opencl_wpapmk_fmt.c **/

static hccap_t hccap;			///structure with hccap data
static wpapsk_salt currentsalt;		///structure for essid
static mic_t *mic;			///table for MIC keys
#ifndef JOHN_OCL_WPAPMK
static wpapsk_hash *outbuffer;		///table for PMK calculated by GPU
#endif

/** Below are common functions used by wpapmk_fmt.c and opencl_wpapmk_fmt.c **/

static hccap_t *decode_hccap(char *ciphertext)
{
	static hccap_t hccap;
	char *essid = ciphertext + FORMAT_TAG_LEN;
	char *hash = strrchr(ciphertext, '#');
	char *d = hccap.essid;
	char *cap = hash + 1;
	unsigned char tbuf[sizeof(hccap_t)];
	unsigned char *dst = tbuf;
	int i;

	memset(&hccap, 0, sizeof(hccap));
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
	/* This emits warnings on some compilers */
	//memcpy(&hccap.mac1,tbuf,sizeof(hccap_t)-36);
	memcpy(((char*)&hccap) + 36, tbuf, sizeof(hccap_t) - 36);

#if !ARCH_LITTLE_ENDIAN
	hccap.eapol_size = JOHNSWAP(hccap.eapol_size);
	hccap.keyver = JOHNSWAP(hccap.keyver);
#endif

	return &hccap;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} binary;
	hccap_t *hccap = decode_hccap(ciphertext);

	memcpy(binary.c, hccap->keymic, BINARY_SIZE);
	return binary.c;
}

static void *get_salt(char *ciphertext)
{
	static hccap_t s;

	memcpy(&s, decode_hccap(ciphertext), SALT_SIZE);
	return &s;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *hash;
	int hashlength = 0;
	hccap_t *hccap;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	hash = strrchr(ciphertext, '#');
	if (hash == NULL || hash - (ciphertext + FORMAT_TAG_LEN) > 32)
		return 0;
	hash++;
	while (hash < ciphertext + strlen(ciphertext)) {
		if (atoi64[ARCH_INDEX(*hash++)] == 0x7f)
			return 0;
		hashlength++;
	}
	if (hashlength != 475)
		return 0;
	hccap = decode_hccap(ciphertext);

	if (strlen(hccap->essid) > 32) /* real life limit */
		return 0;

	if (hccap->eapol_size > 256)
		return 0;
	if (hccap->keyver < 1)
		return 0;
#if (!AC_BUILT || HAVE_OPENSSL_CMAC_H) || defined(JOHN_OCL_WPAPMK)
	if (hccap->keyver > 3)
		return 0;
#else
	if (hccap->keyver > 2)
		return 0;
#endif
	return 1;
}

#ifndef JOHN_OCL_WPAPMK
static MAYBE_INLINE void prf_512(uint32_t * key, uint8_t * data, uint32_t * ret)
{
	char *text = (char*)"Pairwise key expansion";
	unsigned char buff[100];

	memcpy(buff, text, 22);
	memcpy(buff + 23, data, 76);
	buff[22] = 0;
	buff[76 + 23] = 0;
	hmac_sha1((unsigned char*)key, 32, buff, 100, (unsigned char*)ret, 20);
}
#endif

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

static void set_salt(void *salt)
{
	memcpy(&hccap, salt, SALT_SIZE);
	strncpy((char*)currentsalt.salt, hccap.essid, sizeof(currentsalt.salt));
	currentsalt.length = strlen(hccap.essid);

#ifdef JOHN_OCL_WPAPMK
	currentsalt.eapol_size = hccap.eapol_size;
	memcpy(currentsalt.eapol, hccap.eapol, hccap.eapol_size);
	memset(currentsalt.eapol + hccap.eapol_size, 0x80, 1);
	memset(currentsalt.eapol + hccap.eapol_size + 1, 0, 256 + 64 - hccap.eapol_size - 1);
	if (hccap.keyver == 2)
		alter_endianity(currentsalt.eapol, 256+56);
	((unsigned int*)currentsalt.eapol)[16 * ((hccap.eapol_size + 8) / 64) + ((hccap.keyver == 1) ? 14 : 15)] = (64 + hccap.eapol_size) << 3;
	insert_mac(currentsalt.data);
	insert_nonce(currentsalt.data + 12);
	if (hccap.keyver < 3)
		alter_endianity(currentsalt.data, 64 + 12);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(wpapsk_salt), &currentsalt, 0, NULL, NULL), "Copy setting to gpu");
#endif
	//Debug_hccap();
}

#ifndef JOHN_OCL_WPAPMK

#if !AC_BUILT || HAVE_OPENSSL_CMAC_H

/* Code borrowed from https://w1.fi/wpa_supplicant/ starts */

#define SHA256_MAC_LEN 32
typedef uint16_t u16;
typedef uint8_t u8;

static inline void WPA_PUT_LE16(u8 *a, u16 val)
{
	a[1] = val >> 8;
	a[0] = val & 0xff;
}

static void sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	SHA256_CTX ctx;
	size_t i;

	SHA256_Init(&ctx);
	for (i = 0; i < num_elem; i++) {
		SHA256_Update(&ctx, addr[i], len[i]);
	}

	SHA256_Final(mac, &ctx);
}

static void hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
		const u8 *addr[], const size_t *len, u8 *mac)
{
	unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
	const u8 *_addr[6];
	size_t _len[6], i;

	/* the HMAC_SHA256 transform looks like:
	 *
	 * SHA256(K XOR opad, SHA256(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with ipad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x36;

	/* perform inner SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	sha256_vector(1 + num_elem, _addr, _len, mac);

	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with opad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x5c;

	/* perform outer SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = SHA256_MAC_LEN;
	sha256_vector(2, _addr, _len, mac);
}

static void sha256_prf_bits(const u8 *key, size_t key_len, const char *label,
		const u8 *data, size_t data_len, u8 *buf, size_t buf_len_bits)
{
	u16 counter = 1;
	size_t pos, plen;
	u8 hash[SHA256_MAC_LEN];
	const u8 *addr[4];
	size_t len[4];
	u8 counter_le[2], length_le[2];
	size_t buf_len = (buf_len_bits + 7) / 8;

	addr[0] = counter_le;
	len[0] = 2;
	addr[1] = (u8 *) label;
	len[1] = strlen(label);
	addr[2] = data;
	len[2] = data_len;
	addr[3] = length_le;
	len[3] = sizeof(length_le);

	WPA_PUT_LE16(length_le, buf_len_bits);
	pos = 0;

	while (pos < buf_len) {
		plen = buf_len - pos;
		WPA_PUT_LE16(counter_le, counter);
		if (plen >= SHA256_MAC_LEN) {
			hmac_sha256_vector(key, key_len, 4, addr, len, &buf[pos]);
			pos += SHA256_MAC_LEN;
		} else {
			hmac_sha256_vector(key, key_len, 4, addr, len, hash);
			memcpy(&buf[pos], hash, plen);
			pos += plen;
			break;
		}
		counter++;
	}

	/*
	 * Mask out unused bits in the last octet if it does not use all the
	 * bits.
	 */
	if (buf_len_bits % 8) {
		u8 mask = 0xff << (8 - buf_len_bits % 8);
		buf[pos - 1] &= mask;
	}
}
#endif /* HAVE_OPENSSL_CMAC_H */

/* Code borrowed from https://w1.fi/wpa_supplicant/ ends */

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
			uint32_t prf[20/4];
			HMACMD5Context ctx;

			prf_512(outbuffer[i].v, data, prf); // PTK
			hmac_md5_init_K16((unsigned char*)prf, &ctx);
			hmac_md5_update(hccap.eapol, hccap.eapol_size, &ctx);
			hmac_md5_final(mic[i].keymic, &ctx);
		}
	} else if (hccap.keyver == 2) {
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(keys, outbuffer, data, hccap, mic)
#endif
		for (i = 0; i < keys; i++) {
			uint32_t prf[20/4];

			prf_512(outbuffer[i].v, data, prf); // PTK
			hmac_sha1((unsigned char*)prf, 16, hccap.eapol,
			          hccap.eapol_size, mic[i].keymic, 16);
		}
#if !AC_BUILT || HAVE_OPENSSL_CMAC_H
	} else if (hccap.keyver == 3) { // 802.11w, WPA-PSK-SHA256
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(keys, outbuffer, data, hccap, mic)
#endif
		for (i = 0; i < keys; i++) {
			unsigned char ptk[48];
			unsigned char cmic[16];
			size_t miclen;
			CMAC_CTX *ctx;

			sha256_prf_bits((unsigned char*)outbuffer[i].v, 32, "Pairwise key expansion", data, 76, ptk, 48 * 8); // PTK

			// Compute MIC
			ctx = CMAC_CTX_new();
			CMAC_Init(ctx, ptk, 16, EVP_aes_128_cbc(), 0);
			CMAC_Update(ctx, hccap.eapol, hccap.eapol_size);
			CMAC_Final(ctx, cmic, &miclen);
			memcpy(mic[i].keymic, cmic, 16);
			CMAC_CTX_free(ctx);
		}
#endif /* HAVE_OPENSSL_CMAC_H */
	}
}
#endif /* #ifndef JOHN_OCL_WPAPMK */

static int get_hash_0(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	uint32_t *h = (uint32_t *) mic[index].keymic;
	return h[0] & PH_MASK_6;
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

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int salt_compare(const void *x, const void *y)
{
	int c = strncmp((const char*)x, (const char*)y, 36);
	if (c) return c;
	return memcmp((const char*)x, (const char*)y, SALT_SIZE);
}

/*
 * key version as first tunable cost
 * 1=WPA     (MD5)
 * 2=WPA2    (SHA1)
 * 3=802.11w (SHA256)
 */
static unsigned int get_keyver(void *salt)
{
	hccap_t *my_salt = salt;

	return (unsigned int) my_salt->keyver;
}

#endif

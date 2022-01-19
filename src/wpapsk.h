/*
 * This software is
 * Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com>
 * and Copyright (c) 2012-2019 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * hccap format was introduced by oclHashcat-plus (now renamed to hashcat),
 * and it is described here: http://hashcat.net/wiki/hccap
 */
#ifndef _WPAPSK_H
#define _WPAPSK_H

#if AC_BUILT
#include "autoconfig.h"
#endif

#if !HAVE_LIBCRYPTO
#undef HAVE_OPENSSL_CMAC_H
#elif !AC_BUILT && HAVE_LIBCRYPTO && !defined(HAVE_OPENSSL_CMAC_H)
#define HAVE_OPENSSL_CMAC_H 1
#endif

#include <stdint.h>
#include <assert.h>
#if HAVE_OPENSSL_CMAC_H
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

#define BINARY_SIZE			sizeof(fmt_data)
#define BINARY_ALIGN		sizeof(size_t)
#ifdef WPAPMK
#define PLAINTEXT_MIN_LEN   64
#define PLAINTEXT_LENGTH    64
#define BENCHMARK_LENGTH    64
#define SALT_SIZE           0
#define SALT_ALIGN          MEM_ALIGN_NONE
#else
#define PLAINTEXT_MIN_LEN   8
#define PLAINTEXT_LENGTH    63 /* We can do 64 but spec. says 63 */
#define BENCHMARK_LENGTH    0x108
#define SALT_SIZE		sizeof(wpapsk_salt)
#define SALT_ALIGN		MEM_ALIGN_WORD
#endif
#define BENCHMARK_COMMENT	""
#define FORMAT_TAG           "$WPAPSK$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)

typedef union {
	unsigned char keymic[16];
	uint32_t u32;
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
	uint8_t  essid[36]; // essid
} wpapsk_salt;

#ifdef JOHN_OCL_WPAPSK
typedef struct {
	uint32_t eapol_size;
	uint8_t  eapol[256 + 64];
	uint8_t  data[64 + 12]; /* EAPOL data or PMKID */
} wpapsk_data;
#endif

static struct fmt_tests tests[] = {
#ifdef WPAPMK
	{"$WPAPSK$test#..qHuv0A..ZPYJBRzZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsRIfQN2Zar6EXp2BYcRuSkWEJIWjEJJvb4DWZCspbZ51.21.3zy.EY.6........../zZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsQ..................................................................BoK.31m.E2..31m.U2..31m.U2..31m.U................................................................................................................................................................................/X.....E...AkkDQmDg9837LBHG.dGlKA", "cdd79a5acfb070c7e9d1023b870285d639e430b32f31aa37ac825a55b55524ee"},
	{"$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI", "a288fcf0caaacda9a9f58633ff35e8992a01d9c10ba5e02efdf8cb5d730ce7bc"},
#if HAVE_OPENSSL_CMAC_H || defined(JOHN_OCL_WPAPSK)
	{"$WPAPSK$Neheb#g9a8Jcre9D0WrPnEN4QXDbA5NwAy5TVpkuoChMdFfL/8Dus4i/X.lTnfwuw04ASqHgvo12wJYJywulb6pWM6C5uqiMPNKNe9pkr6LE61.5I0.Eg.2..........1N4QXDbA5NwAy5TVpkuoChMdFfL/8Dus4i/X.lTnfwuw.................................................................3X.I.E..1uk2.E..1uk2.E..1uk4X...................................................................................................................................................................................../t.....k...0sHl.mVkiHW.ryNchcMd4g", "fb57668cd338374412c26208d79aa5c30ce40a110224f3cfb592a8f2e8bf53e8"},
#endif
	/* WPAPSK PMKID */
	{"2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*ed487162465a774bfba60eb603a39f3a", "5b13d4babb3714ccc62c9f71864bc984efd6a55f237c7a87fc2151e1ca658a9d"},
#else
	/* WPA2 testcase from http://wiki.wireshark.org/SampleCaptures */
	{"$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI", "Induction"},
	{"$WPAPSK$Harkonen#./FgTY0../B4zX6AKFO9kuLT4BQSyqEXwo.6XOiS4u8vlMNNs5grN91SVL.WK3GkF2rXfkPFGGi38MHkHDMbH.sm49Vc3pO4HPSUJE21.5I0.Ec.2........../KFO9kuLT4BQSyqEXwo.6XOiS4u8vlMNNs5grN91SVL..................................................................3X.I.E..1uk2.E..1uk2.E..1uk0.E..................................................................................................................................................................................../t.....U...BIpIs8sePU4r8yNnOxKHfM", "12345678"},
	/* WPA (MD5), from aircrack-ng tests */
	{"$WPAPSK$test#..qHuv0A..ZPYJBRzZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsRIfQN2Zar6EXp2BYcRuSkWEJIWjEJJvb4DWZCspbZ51.21.3zy.EY.6........../zZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsQ..................................................................BoK.31m.E2..31m.U2..31m.U2..31m.U................................................................................................................................................................................/X.....E...AkkDQmDg9837LBHG.dGlKA", "biscotte"},
	/* Maximum length, 63 characters */
	{"$WPAPSK$Greased Lighting#kA5.CDNB.07cofsOMXEEUwFTkO/RX2sQUaW9eteI8ynpFMwRgFZC6kk7bGqgvfcXnuF1f7L5fgn4fQMLmDrKjdBNjb6LClRmfLiTYk21.5I0.Ec............7MXEEUwFTkO/RX2sQUaW9eteI8ynpFMwRgFZC6kk7bGo.................................................................3X.I.E..1uk2.E..1uk2.E..1uk00...................................................................................................................................................................................../t.....U...D06LUdWVfGPaP1Oa3AV9Hg", "W*A5z&1?op2_L&Hla-OA$#5i_Lu@F+6d?je?u5!6+6766eluu7-l+jOEkIwLe90"},
	{"$WPAPSK$hello#JUjQmBbOHUY4RTqMpGc9EjqGdCxMZPWNXBNd1ejNDoFuemrLl27juYlDDUDMgZfery1qJTHYVn2Faso/kUDDjr3y8gspK7viz8BCJE21.5I0.Ec............/pGc9EjqGdCxMZPWNXBNd1ejNDoFuemrLl27juYlDDUA.................................................................3X.I.E..1uk2.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...9Py59nqygwiar49oOKA3RY", "12345678"},
#if HAVE_OPENSSL_CMAC_H || defined(JOHN_OCL_WPAPSK)
	/* 802.11w with WPA-PSK-SHA256 */
	{"$WPAPSK$hello#HY6.hTXZv.v27BkPGuhkCnLAKxYHlTWYs.4yuqVSNAip3SeixhErtNMV30LZAA3uaEfy2U2tJQi.VICk4hqn3V5m7W3lNHSJYW5vLE21.5I0.Eg............/GuhkCnLAKxYHlTWYs.4yuqVSNAip3SeixhErtNMV30I.................................................................3X.I.E..1uk2.E..1uk2.E..1uk4....................................................................................................................................................................................../t.....k.../Ms4UxzvlNw5hOM1igIeo6", "password"},
	/* 802.11w with WPA-PSK-SHA256, https://github.com/neheb */
	{"$WPAPSK$Neheb#g9a8Jcre9D0WrPnEN4QXDbA5NwAy5TVpkuoChMdFfL/8Dus4i/X.lTnfwuw04ASqHgvo12wJYJywulb6pWM6C5uqiMPNKNe9pkr6LE61.5I0.Eg.2..........1N4QXDbA5NwAy5TVpkuoChMdFfL/8Dus4i/X.lTnfwuw.................................................................3X.I.E..1uk2.E..1uk2.E..1uk4X...................................................................................................................................................................................../t.....k...0sHl.mVkiHW.ryNchcMd4g", "bo$$password"},
#endif
	/* WPAPSK PMKID */
	{"2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*ed487162465a774bfba60eb603a39f3a", "hashcat!"},
#endif /* WPAPMK */
	{NULL}
};

/** Below are common variables used by wpapsk_fmt.c and opencl_wpapsk_fmt.c **/

#ifndef WPAPMK
static wpapsk_salt *cur_salt;
#endif
static mic_t *mic;			// table for MIC keys
#ifndef JOHN_OCL_WPAPSK
#ifndef WPAPMK
static wpapsk_password *inbuffer;	// table for candidate passwords
#endif
static wpapsk_hash *outbuffer;		// table for calculated PMK
#endif

/** Below are common functions used by wpapsk_fmt.c and opencl_wpapsk_fmt.c **/

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
	while (essid != hash) {	// copy essid to hccap
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

#ifdef WPAPSK_DEBUG
static char *tomac(unsigned char *p) {
	static char buf[48];
	sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
	return buf;
}
static char *hex(unsigned char *p, int len) {
	static char buf[1024];
	char *op=buf;
	int i;
	if (len > 32) {
		do {
			for (i = 0; i < 32; ++i) {
				op += sprintf(op, "%02X", p[i]);
				if (i<31&&i%4==3)
					op += sprintf(op, " ");
				if (i==15)
					op += sprintf(op, ": ");
			}
			len -= 32;
			p += 32;
			op += sprintf(op, "\n          ");
		} while (len > 32);
	}
	for (i = 0; i < len; ++i) {
		op += sprintf(op, "%02X", p[i]);
		if (i<31&&i%4==3)
			op += sprintf(op, " ");
		if (i==15)
			op += sprintf(op, ": ");
	}
	return buf;
}

static void debug_hccap(hccap_t *hccap) {
	printf("essid:    %s\n", hccap->essid);
	printf("mac1:     %s\n", tomac(hccap->mac1));
	printf("mac2:     %s\n", tomac(hccap->mac2));
	printf("nonce1:   %s\n", hex(hccap->nonce1, 32));
	printf("nonce2:   %s\n", hex(hccap->nonce2, 32));
	printf("eapol:    %s\n", hex(hccap->eapol, 256));
	printf("epol_sz:  %d (0x%02X)\n", hccap->eapol_size, hccap->eapol_size);
	printf("keyver:   %d\n", hccap->keyver);
	printf("keymic:   %s\n", hex(hccap->keymic, 16));
}
#endif

static void *get_binary(char *ciphertext)
{
	static fmt_data data;
	hccap_t *s;

	data.flags = FMT_DATA_ALLOC;
	data.size = sizeof(hccap_t);

	s = (data.flags == FMT_DATA_TINY) ?
		mem_alloc_tiny(data.size, sizeof(hccap_t*)) : mem_alloc(data.size);
	data.blob = s;

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		memcpy(s, decode_hccap(ciphertext), sizeof(hccap_t));
	} else {
		memset(s, 0, sizeof(hccap_t));
		s->keyver = 0;
		base64_convert(ciphertext, e_b64_hex, 2 * sizeof(mic_t), s->keymic,
		               e_b64_raw, sizeof(mic_t),
		               flg_Base64_NO_FLAGS, 0);
		ciphertext += 33;
		base64_convert(ciphertext, e_b64_hex, 12, s->mac1,
		               e_b64_raw, 6,
		               flg_Base64_NO_FLAGS, 0);
		ciphertext += 13;
		base64_convert(ciphertext, e_b64_hex, 12, s->mac2,
		               e_b64_raw, 6,
		               flg_Base64_NO_FLAGS, 0);
		ciphertext += 13;
		base64_convert(ciphertext, e_b64_hex, 64, s->essid,
		               e_b64_raw, 33,
		               flg_Base64_NO_FLAGS, 0);
	}

	return &data;
}

#ifndef WPAPMK
static void *get_salt(char *ciphertext)
{
	static wpapsk_salt salt;
	hccap_t s;

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		memcpy(&s, decode_hccap(ciphertext), sizeof(hccap_t));
	} else {
		memset(&s, 0, sizeof(s));
		ciphertext += 33;
		ciphertext += 13;
		ciphertext += 13;
		base64_convert(ciphertext, e_b64_hex, 64, s.essid, e_b64_raw, 32, flg_Base64_NO_FLAGS, 0);
	}

	memcpy(salt.essid, s.essid, sizeof(salt.essid));
	salt.length = strlen(s.essid);

	return &salt;
}
#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *hash;
	int hashlength;
	hccap_t *hccap;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		int extra;

		if (strnlen(ciphertext, 61) < 61)
			return 0;
		if (ciphertext[32] != '*' || hexlenl(ciphertext, NULL) != 32)
			return 0;
		if (ciphertext[45] != '*' || hexlenl(ciphertext + 33, NULL) != 12)
			return 0;
		if (ciphertext[58] != '*' || hexlenl(ciphertext + 46, NULL) != 12)
			return 0;
		hashlength = hexlenl(ciphertext + 59, &extra);
		if (hashlength < 2 || (hashlength & 1) || hashlength > 64 || extra)
			return 0;
		/* This is a PMKID hash */
		return 1;
	}

	hashlength = 0;
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

	if (strlen(hccap->essid) > 32) /* Some routers can do 31 octets, some can do 32. */
		return 0;

	if (hccap->eapol_size > 256)
		return 0;
	if (hccap->keyver < 1)
		return 0;
#if HAVE_OPENSSL_CMAC_H || defined(JOHN_OCL_WPAPSK)
	if (hccap->keyver > 3)
		return 0;
#else
	if (hccap->keyver > 2)
		return 0;
#endif
	return 1;
}

#ifndef JOHN_OCL_WPAPSK
static MAYBE_INLINE void prf_512(uint32_t *key, uint8_t *data, uint32_t *ret)
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

static void insert_mac(hccap_t *hccap, uint8_t *data)
{
	int k = memcmp(hccap->mac1, hccap->mac2, 6);
	if (k > 0) {
		memcpy(data, hccap->mac2, 6);
		memcpy(data + 6, hccap->mac1, 6);
	} else {
		memcpy(data, hccap->mac1, 6);
		memcpy(data + 6, hccap->mac2, 6);
	}
}

static void insert_nonce(hccap_t *hccap, uint8_t *data)
{
	int k = memcmp(hccap->nonce1, hccap->nonce2, 32);
	if (k > 0) {
		memcpy(data, hccap->nonce2, 32);
		memcpy(data + 32, hccap->nonce1, 32);
	} else {
		memcpy(data, hccap->nonce1, 32);
		memcpy(data + 32, hccap->nonce2, 32);
	}
}

#ifndef WPAPMK
static void set_salt(void *salt)
{
	cur_salt = salt;

#ifdef JOHN_OCL_WPAPSK
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(wpapsk_salt), cur_salt, 0, NULL, NULL), "Copy setting to gpu");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
#endif
}
#endif

#ifndef JOHN_OCL_WPAPSK
#ifndef WPAPMK
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
#endif /* WPAPMK */

#if HAVE_OPENSSL_CMAC_H

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

static int cmp_all(void *binary, int count)
{
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;
	int i;
	uint8_t data[64 + 12];

	if (hccap->keyver == 0) {
		uint8_t msg[8 + 6 + 6] = "PMK Name";

		memcpy(msg + 8, hccap->mac1, 6);
		memcpy(msg + 14, hccap->mac2, 6);

#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(count, outbuffer, msg, mic)
#endif
		/* Create "keymic" that is actually PMKID */
		for (i = 0; i < count; i++) {
			hmac_sha1((unsigned char*)outbuffer[i].v, 32,
			          msg, 20, mic[i].keymic, 16);
		}
	} else {
		insert_mac(hccap, data);
		insert_nonce(hccap, data + 12);
	}

	if (hccap->keyver == 1) {
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(count, outbuffer, data, hccap, mic)
#endif
		for (i = 0; i < count; i++) {
			union {
				uint32_t u32[20/4];
				unsigned char uc[20];
				uint64_t dummy; /* alignment for hmac_md5_init_K16() */
			} prf;
			HMACMD5Context ctx;

			prf_512(outbuffer[i].v, data, prf.u32); // PTK
			hmac_md5_init_K16(prf.uc, &ctx);
			hmac_md5_update(hccap->eapol, hccap->eapol_size, &ctx);
			hmac_md5_final(mic[i].keymic, &ctx);
		}
	} else if (hccap->keyver == 2) {
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(count, outbuffer, data, hccap, mic)
#endif
		for (i = 0; i < count; i++) {
			uint32_t prf[20/4];

			prf_512(outbuffer[i].v, data, prf); // PTK
			hmac_sha1((unsigned char*)prf, 16, hccap->eapol,
			          hccap->eapol_size, mic[i].keymic, 16);
		}
#if HAVE_OPENSSL_CMAC_H
	} else if (hccap->keyver == 3) { // 802.11w, WPA-PSK-SHA256
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(count, outbuffer, data, hccap, mic)
#endif
		for (i = 0; i < count; i++) {
			unsigned char ptk[48];
			unsigned char cmic[16];
			size_t miclen;
			CMAC_CTX *ctx;

			sha256_prf_bits((unsigned char*)outbuffer[i].v, 32, "Pairwise key expansion", data, 76, ptk, 48 * 8); // PTK

			// Compute MIC
			ctx = CMAC_CTX_new();
			CMAC_Init(ctx, ptk, 16, EVP_aes_128_cbc(), 0);
			CMAC_Update(ctx, hccap->eapol, hccap->eapol_size);
			CMAC_Final(ctx, cmic, &miclen);
			memcpy(mic[i].keymic, cmic, 16);
			CMAC_CTX_free(ctx);
		}
#endif /* HAVE_OPENSSL_CMAC_H */
	}

	for (i = 0; i < count; i++)
		if (!memcmp(hccap->keymic, mic[i].keymic, 16))
			return 1;
	return 0;
}

#else /* JOHN_OCL_WPAPSK */

#ifdef WPAPMK
#define EVENT(n) multi_profilingEvent[n]
#else
#define EVENT(n) multi_profilingEvent[n + 2]
#endif

static int cmp_all(void *binary, int count)
{
	wpapsk_data cur_data;
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;
	int i;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_KPC_MULTIPLE(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	cur_data.eapol_size = hccap->eapol_size;
	memcpy(cur_data.eapol, hccap->eapol, hccap->eapol_size);
	memset(cur_data.eapol + hccap->eapol_size, 0x80, 1);
	memset(cur_data.eapol + hccap->eapol_size + 1, 0, 256 + 64 - hccap->eapol_size - 1);
	if (hccap->keyver == 2)
		alter_endianity(cur_data.eapol, 256+56);
	((unsigned int*)cur_data.eapol)[16 * ((hccap->eapol_size + 8) / 64) + ((hccap->keyver == 1) ? 14 : 15)] = (64 + hccap->eapol_size) << 3;
	if (hccap->keyver == 0) {
		memcpy(cur_data.data, "PMK Name", 8);
		memcpy(cur_data.data + 8, hccap->mac1, 6);
		memcpy(cur_data.data + 14, hccap->mac2, 6);
		alter_endianity(cur_data.data, 20);
	} else {
		insert_mac(hccap, cur_data.data);
		insert_nonce(hccap, cur_data.data + 12);
		if (hccap->keyver < 3)
			alter_endianity(cur_data.data, 64 + 12);
	}

	// Copy non-hash data blob for this "binary"
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_data, CL_FALSE, 0, sizeof(wpapsk_data), &cur_data, 0, NULL, EVENT(2)), "Copy data to gpu");

	if (hccap->keyver == 0)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_pmkid, 1, NULL, &global_work_size, lws, 0, NULL, EVENT(3)), "Run final kernel (PMKID)");
	else if (hccap->keyver == 1)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_md5, 1, NULL, &global_work_size, lws, 0, NULL, EVENT(3)), "Run final kernel (MD5)");
	else if (hccap->keyver == 2)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_sha1, 1, NULL, &global_work_size, lws, 0, NULL, EVENT(3)), "Run final kernel (SHA1)");
	else
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_sha256, 1, NULL, &global_work_size, lws, 0, NULL, EVENT(3)), "Run final kernel (SHA256)");

	BENCH_CLERROR(clFinish(queue[gpu_id]), "Failed running final kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0, sizeof(mic_t) * scalar_gws, mic, 0, NULL, EVENT(4)), "Copy result back");

#ifndef WPAPMK
	WAIT_INIT(global_work_size)
	BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
	WAIT_SLEEP
#endif
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error transferring keys");
#ifndef WPAPMK
	WAIT_UPDATE
	WAIT_DONE
#endif

	for (i = 0; i < count; i++)
		if (!memcmp(hccap->keymic, mic[i].keymic, 16))
			return 1;
	return 0;
}

#endif /* JOHN_OCL_WPAPSK */

static int cmp_one(void *binary, int index)
{
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;

	return !memcmp(hccap->keymic, mic[index].keymic, 16);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int binary_hash_0(void *binary)
{
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;
	uint8_t *keymic = hccap->keymic;
	uint32_t mic;

	memcpy(&mic, keymic, sizeof(uint32_t));

	return mic & PH_MASK_0;
}

static int binary_hash_1(void *binary)
{
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;
	uint8_t *keymic = hccap->keymic;
	uint32_t mic;

	memcpy(&mic, keymic, sizeof(uint32_t));

	return mic & PH_MASK_1;
}

static int binary_hash_2(void *binary)
{
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;
	uint8_t *keymic = hccap->keymic;
	uint32_t mic;

	memcpy(&mic, keymic, sizeof(uint32_t));

	return mic & PH_MASK_2;
}

static int binary_hash_3(void *binary)
{
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;
	uint8_t *keymic = hccap->keymic;
	uint32_t mic;

	memcpy(&mic, keymic, sizeof(uint32_t));

	return mic & PH_MASK_3;
}

static int binary_hash_4(void *binary)
{
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;
	uint8_t *keymic = hccap->keymic;
	uint32_t mic;

	memcpy(&mic, keymic, sizeof(uint32_t));

	return mic & PH_MASK_4;
}

static int binary_hash_5(void *binary)
{
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;
	uint8_t *keymic = hccap->keymic;
	uint32_t mic;

	memcpy(&mic, keymic, sizeof(uint32_t));

	return mic & PH_MASK_5;
}

static int binary_hash_6(void *binary)
{
	fmt_data *blob = binary;
	hccap_t *hccap = blob->blob;
	uint8_t *keymic = hccap->keymic;
	uint32_t mic;

	memcpy(&mic, keymic, sizeof(uint32_t));

	return mic & PH_MASK_6;
}

#ifndef WPAPMK
/*  Public domain hash function by DJ Bernstein (salt is an ESSID)   */
/* Next after 5381 are 52711, 648391, 9737333, 174440041, 3657500101 */
static int salt_hash(void *salt_s)
{
	wpapsk_salt *salt = salt_s;
	unsigned int len = salt->length;
	unsigned char *c = salt->essid;
	unsigned int hash = 52711;

	while (len--)
		hash = ((hash << 5) + hash) ^ *c++;

	return hash & (SALT_HASH_SIZE - 1);
}

static int salt_compare(const void *x, const void *y)
{
	const wpapsk_salt *s1 = x, *s2 = y;
	return strcmp((const char*)s1->essid, (const char*)s2->essid);
}
#endif /* WPAPMK */

#endif /* _WPAPSK_H */

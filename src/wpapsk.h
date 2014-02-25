/*
 * This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com>
 * and Copyright (c) 2012-2014 magnum
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
#include "stdint.h"

#include <assert.h>
#include <openssl/hmac.h>

#define HCCAP_SIZE		sizeof(hccap_t)

#define BINARY_SIZE		sizeof(mic_t)
#define BINARY_ALIGN		4
#define PLAINTEXT_LENGTH	63 /* We can do 64 but spec. says 63 */
#define SALT_SIZE		sizeof(hccap_t)
#define SALT_ALIGN		MEM_ALIGN_NONE
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
	uint32_t length;
	uint8_t  v[PLAINTEXT_LENGTH + 1];
} wpapsk_password;

typedef struct {
	uint32_t v[8];
} wpapsk_hash;

typedef struct {
	uint32_t length;
#ifdef JOHN_OCL_WPAPSK
	uint8_t  eapol[256 + 64];
	uint32_t eapol_size; // blocks
	uint8_t  data[64 + 12];
#endif
	uint8_t  salt[36]; // essid
} wpapsk_salt;

#ifndef _WPAPSK_CUDA_KERNEL
static struct fmt_tests tests[] = {
	/* WPA2 testcase from http://wiki.wireshark.org/SampleCaptures */
	{"$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI", "Induction"},
	{"$WPAPSK$Harkonen#./FgTY0../B4zX6AKFO9kuLT4BQSyqEXwo.6XOiS4u8vlMNNs5grN91SVL.WK3GkF2rXfkPFGGi38MHkHDMbH.sm49Vc3pO4HPSUJE21.5I0.Ec.2........../KFO9kuLT4BQSyqEXwo.6XOiS4u8vlMNNs5grN91SVL..................................................................3X.I.E..1uk2.E..1uk2.E..1uk0.E..................................................................................................................................................................................../t.....U...BIpIs8sePU4r8yNnOxKHfM", "12345678"},
	/* WPA, from aircrack-ng tests */
	{"$WPAPSK$test#..qHuv0A..ZPYJBRzZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsRIfQN2Zar6EXp2BYcRuSkWEJIWjEJJvb4DWZCspbZ51.21.3zy.EY.6........../zZwAKpEXUJwpza/b69itFaq4.OWoGHfonpc13zCAUsQ..................................................................BoK.31m.E2..31m.U2..31m.U2..31m.U................................................................................................................................................................................/X.....E...AkkDQmDg9837LBHG.dGlKA", "biscotte"},
	/* Maximum length, 63 characters */
	{"$WPAPSK$Greased Lighting#kA5.CDNB.07cofsOMXEEUwFTkO/RX2sQUaW9eteI8ynpFMwRgFZC6kk7bGqgvfcXnuF1f7L5fgn4fQMLmDrKjdBNjb6LClRmfLiTYk21.5I0.Ec............7MXEEUwFTkO/RX2sQUaW9eteI8ynpFMwRgFZC6kk7bGo.................................................................3X.I.E..1uk2.E..1uk2.E..1uk00...................................................................................................................................................................................../t.....U...D06LUdWVfGPaP1Oa3AV9Hg", "W*A5z&1?op2_L&Hla-OA$#5i_Lu@F+6d?je?u5!6+6766eluu7-l+jOEkIwLe90"},
	{NULL}
};
#endif

/** Below are common variables used by wpapsk_fmt.c cuda_wpapsk_fmt.c and opencl_wpapsk_fmt.c **/

static hccap_t hccap;			///structure with hccap data
static wpapsk_salt currentsalt;		///structure for essid
static mic_t *mic;			///table for MIC keys
#ifndef JOHN_OCL_WPAPSK
static wpapsk_password *inbuffer;	///table for candidate passwords
static wpapsk_hash *outbuffer;		///table for PMK calculated by GPU
#endif
static const char wpapsk_prefix[] = "$WPAPSK$";

static int new_keys = 1;
static char last_ssid[sizeof(hccap.essid)];

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
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD_32 dummy;
	} binary;
	hccap_t *hccap = decode_hccap(ciphertext);

	memcpy(binary.c, hccap->keymic, BINARY_SIZE);
	return binary.c;
}

static void *salt(char *ciphertext)
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

	if (strncmp(ciphertext, wpapsk_prefix, strlen(wpapsk_prefix)) != 0)
		return 0;

	hash = strrchr(ciphertext, '#');
	if (hash == NULL || hash - (ciphertext + strlen(wpapsk_prefix)) > 32)
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

	if(hccap->eapol_size > 256)
		return 0;
	if(hccap->eapol_size < 0)
		return 0;
	return 1;
}

#ifndef JOHN_OCL_WPAPSK
static MAYBE_INLINE void prf_512(uint32_t * key, uint8_t * data, uint32_t * ret)
{
	HMAC_CTX ctx;
	char *text = "Pairwise key expansion";
	unsigned char buff[100];

	memcpy(buff, text, 22);
	memcpy(buff + 23, data, 76);
	buff[22] = 0;
	buff[76 + 23] = 0;
	HMAC_Init(&ctx, key, 32, EVP_sha1());
	HMAC_Update(&ctx, buff, 100);
	HMAC_Final(&ctx, (unsigned char *) ret, NULL);
	HMAC_CTX_cleanup(&ctx);
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
				op += sprintf (op, "%02X", p[i]);
				if (i<31&&i%4==3)
					op += sprintf (op, " ");
				if (i==15)
					op += sprintf (op, ": ");
			}
			len -= 32;
			p += 32;
			op += sprintf (op, "\n          ");
		} while (len > 32);
	}
	for (i = 0; i < len; ++i) {
		op += sprintf (op, "%02X", p[i]);
		if (i<31&&i%4==3)
			op += sprintf (op, " ");
		if (i==15)
			op += sprintf (op, ": ");
	}
	return buf;
}

static void Debug_hccap() {
	printf("essid:    %s\n", hccap.essid);
	printf("mac1:     %s\n", tomac(hccap.mac1));
	printf("mac2:     %s\n", tomac(hccap.mac2));
	printf("nonce1:   %s\n", hex(hccap.nonce1, 32));
	printf("nonce2:   %s\n", hex(hccap.nonce2, 32));
	printf("eapol:    %s\n", hex(hccap.eapol, 256));
	printf("epol_sz:  %d (0x%02X)\n", hccap.eapol_size, hccap.eapol_size);
	printf("keyver:   %d\n", hccap.keyver);
	printf("keymic:   %s\n", hex(hccap.keymic, 16));
}
#endif

static void set_salt(void *salt)
{
	memcpy(&hccap, salt, SALT_SIZE);
	strncpy((char*)currentsalt.salt, hccap.essid, sizeof(currentsalt.salt));
	currentsalt.length = strlen(hccap.essid);

#ifdef JOHN_OCL_WPAPSK
	currentsalt.eapol_size = 1 + (hccap.eapol_size + 8) / 64;
	memcpy(currentsalt.eapol, hccap.eapol, hccap.eapol_size);
	memset(currentsalt.eapol + hccap.eapol_size, 0x80, 1);
	memset(currentsalt.eapol + hccap.eapol_size + 1, 0, 256 + 64 - hccap.eapol_size - 1);
	if (hccap.keyver != 1)
		alter_endianity(currentsalt.eapol, 256+56);
	((unsigned int*)currentsalt.eapol)[16 * ((hccap.eapol_size + 8) / 64) + ((hccap.keyver == 1) ? 14 : 15)] = (64 + hccap.eapol_size) << 3;
	insert_mac(currentsalt.data);
	insert_nonce(currentsalt.data + 12);
	alter_endianity(currentsalt.data, 64 + 12);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_salt, CL_FALSE, 0, sizeof(wpapsk_salt), &currentsalt, 0, NULL, NULL), "Copy setting to gpu");
#endif
	//Debug_hccap();
}

#ifndef JOHN_OCL_WPAPSK
static void clear_keys(void) {
	new_keys = 1;
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
			prf_512(outbuffer[i].v, data, prf);
			HMAC(EVP_md5(), prf, 16, hccap.eapol, hccap.eapol_size,
			    mic[i].keymic, NULL);
		}
	} else {
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(keys, outbuffer, data, hccap, mic)
#endif
		for (i = 0; i < keys; i++) {
			uint32_t prf[20/4];
			unsigned char keymic[20];
			prf_512(outbuffer[i].v, data, prf);
			HMAC(EVP_sha1(), prf, 16, hccap.eapol,
			    hccap.eapol_size, keymic, NULL);
			memcpy(mic[i].keymic, keymic, 16);
		}
	}
}
#endif

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

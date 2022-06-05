/*
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Special thanks goes to the loki project for providing the sample pcap files,
 * and for implementing the cryptographic functions involved in RFC 5709
 * clearly.
 *
 * See https://c0decafe.de/svn/codename_loki/ for more information.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ospf;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ospf);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "formats.h"
#include "sha.h"
#include "sha2.h"
#include "hmac_sha.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "ospf"
#define FORMAT_NAME             "OSPF / IS-IS"
#define FORMAT_TAG              "$ospf$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "HMAC-SHA-X 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507 // FIXME: Add cost reporting
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define MAX_SALT_LEN            1500 + 64 // 64 is reserved for appending ospf_apad
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifndef OMP_SCALE
#define OMP_SCALE               128 // MKPC and scale tuned for i7
#endif

static struct fmt_tests tests[] = {
	/* ospf*.pcap from https://c0decafe.de/svn/codename_loki/ */
	{"$ospf$1$02010030ac10001400000000000000020000011454ee4518ffffff00000a120100000028c0a86f14c0a86f0aac10000a$e59ba2c56a2c0429ebe72a194e4b54c250cac1a3", "1234"},
	{"$ospf$2$0201002cac10000a00000000000000020000012054f4c8adffffff00000a120100000028c0a86f0a00000000$508a1abffb5b4554e1aa46eb053bca7105c3e8f6fece4c945f0a0020edb054ec", "1234"},
	{"$ospf$3$0201002cac10000a00000000000000020000013054f4c8e4ffffff00000a120100000028c0a86f0a00000000$9dcf336773034f4ad8b0e19c52546ba72fd91d79d9416c9c1c4854002d3c0b5fc7c80fc1c4994ab9b6c48d9c6ac03587", "1234"},
	{"$ospf$4$0201002cac10000a00000000000000020000014054f4c912ffffff00000a120100000028c0a86f0a00000000$4faa125881137ab3257ee9c8626d0ffa0c387c2e41a832d435afffc41d35881360fbe74442191a8aef201a4aad2689577a0c26a3cc5c681e72f09c297d16ba6a", "1234"},
	/* isis*.pcap from https://c0decafe.de/svn/codename_loki/ */
	{"$ospf$1$831401001101000301192168201101001b004e000104034900018102cc8e8404c0a8ca00f00f0000000003192168201104000000030a17030001$0a33e7acf138d0bfb2b197f331bbd8ae237e0465", "1234"},
	{"$ospf$2$831401001101000301192168201101001b005a000104034900018102cc8e8404c0a8ca00f00f0000000003192168201104000000030a23030002$3082271800f8fab2976d57bb5d1d6e182189b9a2d542f48371da934f854acab9", "1234"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	uint32_t salt_length;
	uint32_t type;
	unsigned char salt[MAX_SALT_LEN]; // fixed len, but should be OK
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1 && value != 2 && value != 3 && value != 4)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) > MAX_SALT_LEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // binary
		goto err;
	value = hexlenl(p, &extra);
	if (value < 20 * 2 || value > 64 * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

// https://tools.ietf.org/rfc/rfc5709.txt and Loki
static const char ospf_apad[] = {
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3
};

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // type
	cs.type = atoi(p);
	p = strtokm(NULL, "$"); // salt
	cs.salt_length = strlen(p) / 2;
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	memcpy(cs.salt + cs.salt_length, ospf_apad, 64);

	MEM_FREE(keeptr);

	return &cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH     20
#endif
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH  32
#endif
#ifndef SHA384_DIGEST_LENGTH
#define SHA384_DIGEST_LENGTH  48
#endif
#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH  64
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		int plen = strlen(saved_key[index]);
		unsigned char key[64];
		unsigned char out[64];

		if (cur_salt->type == 1) {
			SHA_CTX ctx;

			// process password according to rfc5709
			if (plen < SHA_DIGEST_LENGTH) {
				memcpy(key, saved_key[index], plen);
				memset(key + plen, 0, SHA_DIGEST_LENGTH - plen);
			} else if (plen == SHA_DIGEST_LENGTH) {
				memcpy(key, saved_key[index], SHA_DIGEST_LENGTH);
			} else {
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, saved_key[index], plen);
				SHA1_Final(key, &ctx);
			}
			// salt already has ospf_apad appended
			hmac_sha1(key, 20, cur_salt->salt, cur_salt->salt_length + SHA_DIGEST_LENGTH, out, 16);
			memcpy((unsigned char*)crypt_out[index], out, 16);
		} else if (cur_salt->type == 2) {
			SHA256_CTX ctx;

			if (plen < SHA256_DIGEST_LENGTH) {
				memcpy(key, saved_key[index], plen);
				memset(key + plen, 0, SHA256_DIGEST_LENGTH - plen);
			} else if (plen == SHA256_DIGEST_LENGTH) {
				memcpy(key, saved_key[index], SHA256_DIGEST_LENGTH);
			} else {
				SHA256_Init(&ctx);
				SHA256_Update(&ctx, saved_key[index], plen);
				SHA256_Final(key, &ctx);
			}
			hmac_sha256(key, 32, cur_salt->salt, cur_salt->salt_length + SHA256_DIGEST_LENGTH, out, 16);
			memcpy((unsigned char*)crypt_out[index], out, 16);
		} else if (cur_salt->type == 3) {
			SHA512_CTX ctx;

			if (plen < SHA384_DIGEST_LENGTH) {
				memcpy(key, saved_key[index], plen);
				memset(key + plen, 0, SHA384_DIGEST_LENGTH - plen);
			} else if (plen == SHA384_DIGEST_LENGTH) {
				memcpy(key, saved_key[index], SHA384_DIGEST_LENGTH);
			} else {
				SHA384_Init(&ctx);
				SHA384_Update(&ctx, saved_key[index], plen);
				SHA384_Final(key, &ctx);
			}
			hmac_sha384(key, 48, cur_salt->salt, cur_salt->salt_length + SHA384_DIGEST_LENGTH, out, 16);
			memcpy((unsigned char*)crypt_out[index], out, 16);
		} else if (cur_salt->type == 4) {
			SHA512_CTX ctx;

			if (plen < SHA512_DIGEST_LENGTH) {
				memcpy(key, saved_key[index], plen);
				memset(key + plen, 0, SHA512_DIGEST_LENGTH - plen);
			} else if (plen == SHA512_DIGEST_LENGTH) {
				memcpy(key, saved_key[index], SHA512_DIGEST_LENGTH);
			} else {
				SHA512_Init(&ctx);
				SHA512_Update(&ctx, saved_key[index], plen);
				SHA512_Final(key, &ctx);
			}
			hmac_sha512(key, 64, cur_salt->salt, cur_salt->salt_length + SHA512_DIGEST_LENGTH, out, 16);
			memcpy((unsigned char*)crypt_out[index], out, 16);
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void ospf_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_ospf = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		ospf_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

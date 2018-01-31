/*
 * Format for cracking BitShares wallet hashes.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_bitshares;
#elif FMT_REGISTERS_H
john_register_one(&fmt_bitshares);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               32  // MKPC and OMP_SCALE tuned on i5-6500 CPU

#include "formats.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "aes.h"
#include "memdbg.h"

#define FORMAT_LABEL            "bitshares"
#define FORMAT_NAME             "BitShares Wallet"
#define FORMAT_TAG              "$BitShares$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "SHA-512 64/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1000
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint64_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      16

#define MAX_CIPHERTEXT_LENGTH   128

static struct fmt_tests tests[] = {
	// BitShares.Setup.2.0.180115.exe
	{"$BitShares$0*ec415018f26e7182a273655aef7cec47966306c48956604462f5b9e1613b3b70ebaaed4d7600b24a424ddb7d4cd56e55", "openwall"},
	{"$BitShares$0*3bebbec17f0643ee9d3d5e48f04451bf7e38765f3bf2fa6ea12f680d60da121bb04ced9f76681744f3730322082c7ec7", "äbc12345"},
	// Google Chrome -> https://wallet.bitshares.org in January, 2018
	{"$BitShares$0*97452e44d43818099fbd2cc7539588c2c2dbc4e06e1b18831ded86b7e68e51d2da2c2b81054863032248a9da93ea1943", "openwall123"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	uint32_t ctlen;
	unsigned char ct[MAX_CIPHERTEXT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(cracked);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version / type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
		goto err;
	value = hexlenl(p, &extra);
	if (value > MAX_CIPHERTEXT_LENGTH * 2 || value < 32 * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	p = strtokm(NULL, "*");
	cs.ctlen = strlen(p) / 2;
	for (i = 0; i < cs.ctlen; i++)
		cs.ct[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);

	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		SHA512_CTX ctx;
		unsigned char km[64];
		AES_KEY aes_decrypt_key;
		unsigned char out[32];
		unsigned char iv[16] = { 0 }; // does not matter

		SHA512_Init(&ctx);
		SHA512_Update(&ctx, saved_key[index], saved_len[index]);
		SHA512_Final(km, &ctx);

		AES_set_decrypt_key(km, 256, &aes_decrypt_key);
		AES_cbc_encrypt(cur_salt->ct + cur_salt->ctlen - 32, out, 32, &aes_decrypt_key, iv, AES_DECRYPT);

		if (memcmp(out + 16, "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", 16) == 0) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_bitshares = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
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
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
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

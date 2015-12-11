/* How to find the password of attacker's Poison Ivy setup?
 *
 * Based on http://hitcon.org/2013/download/APT1_technical_backstage.pdf
 *
 * - The password is used to encrypt the communication.
 * - The encryption algorithm is Camellia.
 * - The encryption is performed with 16 bytes blocks.
 * - Poison Ivy has an "echo" feature, you send data, it returns the same data
 *   but encrypted ;)
 *
 * So we can,
 * 1. send 100 bytes (with 0x00) to the daemon
 * 2. get the first 16 bytes as result from the daemon
 *
 * Result = Camellia(16*0x00, key)
 *
 * This software is Copyright (c) 2015, Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_camellia;
#elif FMT_REGISTERS_H
john_register_one(&fmt_camellia);
#else

#include <openssl/camellia.h>
#include <string.h>
#include "sha.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "base64.h"
#include "base64_convert.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               2048
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL            "camellia"
#define FORMAT_TAG              "$camellia$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define FORMAT_NAME             "(Poison Ivy)"
#define ALGORITHM_NAME          "Camellia/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        32 /* 256 bits */
#define BINARY_SIZE             16
#define BINARY_ENCODED_SIZE     24
#define BINARY_ALIGN            4
#define SALT_SIZE               0
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests camellia_tests[] = {
	{"$camellia$NeEGbM0Vhz7u+FGJZrcPiw==", "admin" },
	{"$camellia$ItGoyeyQIvPjT/qBoDKQZg==", "pswpsw" },
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;

	p = ciphertext + TAG_LENGTH;
	if (strlen(p) != BINARY_ENCODED_SIZE)
		return 0;

	if (BINARY_ENCODED_SIZE - 2!= base64_valid_length(p, e_b64_mime, flg_Base64_MIME_TRAIL_EQ, 0))
                return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE + 1 + 4];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	p = strrchr(ciphertext, '$') + 1;
	base64_decode((char*)p, BINARY_ENCODED_SIZE, (char*)out);

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		CAMELLIA_KEY st_key;
		unsigned char in[16] = {0};
		unsigned char key[32] = {0};
		strncpy((char*)key, saved_key[index], sizeof(key));
		Camellia_set_key(key, 256, &st_key);
		Camellia_encrypt(in, (unsigned char*)crypt_out[index], &st_key);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
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

static void camellia_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_camellia = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ FORMAT_TAG },
		camellia_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		camellia_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

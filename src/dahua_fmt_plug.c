/*
 * Format for cracking Dahua hashes.
 *
 * http://www.securityfocus.com/archive/1/529799
 * https://github.com/depthsecurity/dahua_dvr_auth_bypass
 *
 * This software is Copyright (c) 2014 Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without#
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_dahua;
#elif FMT_REGISTERS_H
john_register_one(&fmt_dahua);
#else

#include <string.h>
#include <ctype.h>

#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif

#ifdef _OPENMP
#include <omp.h>
#endif // _OPENMP

#include "arch.h"
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "dahua"
#define FORMAT_NAME             "\"MD5 based authentication\" Dahua"
#define FORMAT_TAG              "$dahua$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             8
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               0
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifndef OMP_SCALE
#ifdef __MIC__
#define OMP_SCALE 32
#else
#define OMP_SCALE 16		// MKPC & scale tuned for i7
#endif // __MIC__
#endif // OMP_SCALE

static struct fmt_tests tests[] = {
	{"$dahua$4WzwxXxM", "888888"},  // from hashcat.net
	{"$dahua$HRG6OLE6", "Do You Even Lift?"},
	{"$dahua$sh15yfFM", "666666"},
	{"$dahua$6QNMIQGe", "admin"},
	{"$dahua$g2UpKxOg", "passWOrd"},
	{"$dahua$tlJwpbo6", ""},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext;
	int i;

	if (strncmp(p, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	p = p + TAG_LENGTH;
	if (!p)
		return 0;

	if (strlen(p) != BINARY_SIZE)
		return 0;

	for (i = 0; i < BINARY_SIZE; i++)
		if (!isalnum((int)(unsigned char)p[i]))
			return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	static union {
		char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	char *p;
	char *out = buf.c;

	p = strrchr(ciphertext, '$') + 1;
	strncpy(out, p, BINARY_SIZE);

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

// from hashcat.net (alxchk)
static void compressor(unsigned char *in, unsigned char *out)
{
	int i, j;

	for (i = 0, j = 0; i < 16; i += 2, j++) {
		out[j] = (in[i] + in[i+1]) % 62;

		if (out[j] < 10) {
			out[j] += 48;
		} else if (out[j] < 36) {
			out[j] += 55;
		} else {
			out[j] += 61;
		}
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		// hash is compressor(md5(password))
		MD5_CTX ctx;
		unsigned char *out = (unsigned char*)crypt_out[index];
		unsigned char hash[16];

		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[index], saved_len[index]);
		MD5_Final(hash, &ctx);

		compressor(hash, out);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
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

static void dahua_set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_dahua = {
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT,
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
		dahua_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif

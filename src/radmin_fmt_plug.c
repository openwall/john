/*
 * RAdmin v2.x cracker patch for JtR. Hacked together during
 * May of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format => user:$radmin2$hash
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_radmin;
#elif FMT_REGISTERS_H
john_register_one(&fmt_radmin);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "md5.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "RAdmin"
#define FORMAT_NAME             "v2.x"
#define FORMAT_TAG              "$radmin2$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        99
#define CIPHERTEXT_LENGTH       32
#define BINARY_SIZE             16
#define SALT_SIZE               0
#define BINARY_ALIGN            4
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifndef OMP_SCALE
#define OMP_SCALE               8192 // MKPC and scale tuned for i7
#endif

static struct fmt_tests radmin_tests[] = {
	{"$radmin2$B137F09CF92F465CABCA06AB1B283C1F", "lastwolf"},
	{"$radmin2$14e897b1a9354f875df51047bb1a0765", "podebradka"},
	{"$radmin2$02ba5e187e2589be6f80da0046aa7e3c", "12345678"},
	{"$radmin2$b4e13c7149ebde51e510959f30319ac7", "firebaLL"},
	{"$radmin2$3d2c8cae4621edf8abb081408569482b", "yamaha12345"},
	{"$radmin2$60cb8e411b02c10ecc3c98e29e830de8", "xplicit"},
	{"$radmin2$53b1dc4fd27e58a075b196f99b2ac992", "UPPERCASE"},
	{"$radmin2$6d0bb00954ceb7fbee436bb55a8397a9", ""},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH+1];
static uint32_t (*crypt_out)[8];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
}

static char *split(char *ciphertext, int index, struct fmt_main *self) {
	static char buf[CIPHERTEXT_LENGTH + FORMAT_TAG_LEN + 1];   // $radmin2$ is 9 bytes

	strnzcpylwr(buf, ciphertext, CIPHERTEXT_LENGTH + FORMAT_TAG_LEN + 1);

	return buf;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	p = ciphertext + FORMAT_TAG_LEN;
	if (hexlen(p, &extra) != CIPHERTEXT_LENGTH || extra)
		return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[index], sizeof(saved_key[index]));
		MD5_Final((unsigned char *)crypt_out[index], &ctx);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*(uint32_t *)binary == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *(uint32_t *)binary == crypt_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	void *binary = get_binary(source);
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static void radmin_set_key(char *key, int index)
{
	// This code assures that both saved_key[index] gets null-terminated (without buffer overflow)
	char *cp = &saved_key[index][strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1)+1];
	// and is null padded up to 100 bytes. We simply clean up prior buffer,
	// up to element 99, but that element will never be written to.
	if (cp < &saved_key[index][99])
		while (*cp) *cp++ = 0;
}

static char *get_key(int index)
{
	// Assured NUL teminated string, just return it.
	return saved_key[index];
}

struct fmt_main fmt_radmin = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		radmin_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
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
		radmin_set_key,
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

#endif /* plugin stanza */

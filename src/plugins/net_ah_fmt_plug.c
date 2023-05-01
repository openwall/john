/*
 * Cracker for IPsec Authentication Header (AH) hashes.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_netah;
#elif FMT_REGISTERS_H
john_register_one(&fmt_netah);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               128  // MKPC and OMP_SCALE tuned on Core i5-6500

#include "formats.h"
#include "hmacmd5.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "net-ah"
#define FORMAT_NAME             "IPsec AH HMAC-MD5-96"
#define FORMAT_TAG              "$net-ah$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        8  // Keepalived limit is 8
#define BINARY_SIZE             12
#define BINARY_SIZE_ALLOC       16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      8
#define MAX_SALT_LEN            1500

static struct fmt_tests tests[] = {
	{"$net-ah$0$4500004000150000ff330000c0a87c01e000001270040000c0a87c01000000150000000000000000000000002133650102016c3e0a00018c0000000000000000$ad719a912d50a53935d9ad41", "monkey"},
	{"$net-ah$0$4500004000190000ff330000c0a87c01e000001270040000c0a87c01000000190000000000000000000000002133650102016dc00a00000a0000000000000000$d790123ffdd3ddb2fe1d7205", "openwall"},
	{"$net-ah$0$4500004000170000ff330000c0a87c01e000001270040000c0a87c01000000170000000000000000000000002133650102016dc00a00000a0000000000000000$bb615df255867845496392d8", "12345678"},
	{"$net-ah$0$45000040001e0000ff330000c0a87c01e000001270040000c0a87c010000001e0000000000000000000000002133650102016dc00a00000a0000000000000000$7c6ba14741b4597750ffe6a1", "Müller"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE_ALLOC / sizeof(uint32_t)];

static struct custom_salt {
	uint32_t length;
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
	if ((p = strtokm(ctcopy, "$")) == NULL) // version / type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) > MAX_SALT_LEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // binary
		goto err;
	if (hexlenl(p, &extra) != BINARY_SIZE * 2 || extra)
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
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // version / type
	p = strtokm(NULL, "$"); // salt
	cs.length = strlen(p) / 2;
	for (i = 0; i < cs.length; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		HMACMD5Context ctx;

		hmac_md5_init_rfc2104((const unsigned char*)saved_key[index], strlen(saved_key[index]), &ctx);
		hmac_md5_update(cur_salt->salt, cur_salt->length, &ctx);
		hmac_md5_final((unsigned char*)crypt_out[index], &ctx);
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

static void netah_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_netah = {
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
		FMT_CASE | FMT_TRUNC | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
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
		netah_set_key,
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

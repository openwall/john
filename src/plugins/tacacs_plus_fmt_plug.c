/*
 * Format for cracking TACACS+ hashes.
 *
 * https://insinuator.net/2015/06/tacacs-module-for-loki/
 *
 * This software is Copyright (c) 2015, Daniel Mende <dmende [at] ernw.de> and
 * Copyright (c) 2017, Dhiru Kholia <dhiru [at] openwall.com>, and it is hereby
 * released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_tacacsplus;
#elif FMT_REGISTERS_H
john_register_one(&fmt_tacacsplus);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               8  // tuned on i5-6500 CPU

#include "formats.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "md5.h"

#define FORMAT_LABEL            "tacacs-plus"
#define FORMAT_NAME             "TACACS+"
#define FORMAT_TAG              "$tacacs-plus$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint64_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64  // tuned on i5-6500 CPU

#define MIN_CIPHERTEXT_LENGTH   6
#define MAX_CIPHERTEXT_LENGTH   8 /* It can be longer but we use only 8 */
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH       16
#endif

static struct fmt_tests tests[] = {
	{"$tacacs-plus$0$6d0e1631$db7c01e77499$c006", "1234"},
	{"$tacacs-plus$0$6d0e1631$d623c7692ca7b12f7ecef113bea72845$c004", "1234"},
	{"$tacacs-plus$0$6d0e1631$f7711e4b904fc4a4753e923e9bf3d2cc33e9febd3d2db74b9aa6d20462c2072013c77345d7112400d7b915$c002", "1234"},
	{"$tacacs-plus$0$d0cb2225$f5acae34eb560981b30315cc9b08f00a31566eb5f09351713d0b33067ea1fbdb63ed84062ec24ebc45de63$c002", "testing123"},
	{"$tacacs-plus$0$acf4c30b$c73c409532a4a80e58ba94391111e300$c002", "12345"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	uint32_t ctlen;
	MD5_CTX pctx;
	uint32_t pre_hash_data_len;
	unsigned char pre_hash_data[8];
	uint32_t hash_data_len;
	unsigned char hash_data[2];
	union {
		uint64_t chunk0;
		unsigned char buf[MAX_CIPHERTEXT_LENGTH];
	} ciphertext;
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
	if ((p = strtokm(NULL, "$")) == NULL)   // pre_hash_data
		goto err;
	if (hexlenl(p, &extra) != 4 * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // ciphertext
		goto err;
	if (hexlenl(p, &extra) < MIN_CIPHERTEXT_LENGTH * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // hash_data
		goto err;
	if (hexlenl(p, &extra) != 2 * 2 || extra)
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
	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	cs.pre_hash_data_len = strlen(p) / 2;
	for (i = 0; i < cs.pre_hash_data_len; i++)
		cs.pre_hash_data[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "$");
	cs.ctlen = strlen(p) / 2;
	for (i = 0; i < MIN(MAX_CIPHERTEXT_LENGTH, cs.ctlen); i++)
		cs.ciphertext.buf[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "$");
	cs.hash_data_len = 2;
	for (i = 0; i < 2; i++)
		cs.hash_data[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	MD5_Init(&cs.pctx);
	MD5_Update(&cs.pctx, cs.pre_hash_data, cs.pre_hash_data_len);

	MEM_FREE(keeptr);

	return &cs;
}

static int check_password(int index, struct custom_salt *cs)
{
	MD5_CTX cur;
	union {
		uint64_t u64[MD5_DIGEST_LENGTH / sizeof(uint64_t)];
		unsigned char c[MD5_DIGEST_LENGTH];
	} digest;
	unsigned char status, flags;
	unsigned short server_msg_len, data_len;

	memcpy((void *)&cur, &cur_salt->pctx, sizeof(MD5_CTX));
	MD5_Update(&cur, saved_key[index], saved_len[index]);
	MD5_Update(&cur, cs->hash_data, cs->hash_data_len);
	MD5_Final(digest.c, &cur);

	// XOR the first 8 bytes of "ciphertext" with "digest" to get "cleartext"
	digest.u64[0] ^= cs->ciphertext.chunk0;

	status = digest.c[0];
	flags = digest.c[1];
	server_msg_len = digest.c[3] | (digest.c[2] << 8);
	data_len = digest.c[5] | (digest.c[4] << 8);
	if (((status >= 0x01 && status <= 0x07) || status == 0x21) && (flags == 0x01 || flags == 0x00) &&
		(6U + server_msg_len + data_len == cs->ctlen)) {
		return 1;
	}

	return 0;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
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
		if (check_password(index, cur_salt)) {
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

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_tacacsplus = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
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

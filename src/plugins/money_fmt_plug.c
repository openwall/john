/*
 * JtR format to crack password protected MS Money files.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * All credit goes to Vladimir Berezniker, "Jackcess Encrypt" and Jackcess
 * projects.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_money;
#elif FMT_REGISTERS_H
john_register_one(&fmt_money);
#else

#include <string.h>
#include <ctype.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha.h"
#include "md5.h"
#include "rc4.h"
#include "jumbo.h"
#include "unicode.h"

#define FORMAT_NAME             "Microsoft Money (2002 to Money Plus)"
#define FORMAT_LABEL            "money"
#define FORMAT_TAG              "$money$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5/SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        20
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      256

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
#endif

#define PASSWORD_DIGEST_LENGTH  16
#define PASSWORD_LENGTH         40  // UTF16-LE length

static struct fmt_tests money_tests[] = {
	{"$money$1*fdb51efac3f4e440*bdaa2deb", "openwall"}, // MS Money Plus Sunset Deluxe
	{"$money$1*73cb979632c4e340*d9de64ed", "Test12345"},
	{"$money$1*3dc3fc1cc8f4e440*10f74e1b", "12345678901234567890"}, // Max. password length, original password was 1234567890123456789012345
	// {"$money$1*103c3428c8f4e440*5aa4a678", "Müller"}, // Not yet working, Jackcess does not work either!
	{"$money$1*103c3428c8f4e440*5aa4a678", "M|ller"}, // Same hash but this password is cracked and accepted in MS Money Plus just fine!
	{"$money$1*d68792c7c8f4e440*e1c294bf", "|"}, // Original password is "ü", "|" works fine in official software!
	{"$money$1*353dc5f8c8f4e440*fb840c22", "D"}, // Original password is "ä"
	{"$money$1*e5eee9fec8f4e440*8f7777c9", "V"}, // Original password is "ö"
	{"$money$1*8c83d504c9f4e440*1a1108fa", "#"}, // Original password is "£"
	{"$money$0*9e3eee5bcbf4e440*76a3a059", "openwall"}, // MS Money 2004
	{"$money$0*00b81d0326f5e440*407472c8", "?"}, // Original Я
	{NULL}
};

/* Original password */
static char (*orig_key)[PLAINTEXT_LENGTH + 1];
/* Password encoded in UCS-2 */
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
/* UCS-2 password length, in octets */
static int *saved_len;
static int *cracked, cracked_count;

static struct custom_salt {
	uint32_t type;
	unsigned char salt[8];
	unsigned char encrypted_bytes[4];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	orig_key = mem_calloc(sizeof(*orig_key), self->params.max_keys_per_crypt);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_alloc(self->params.max_keys_per_crypt * sizeof(*saved_len));
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;

	if (options.target_enc == CP1252 || options.target_enc == ISO_8859_1) {
		struct fmt_tests *test = self->params.tests;

		while (test) {
			if (strcmp(test->plaintext, "D"))
				test->plaintext = "\xe4"; // ä
			else if (strcmp(test->plaintext, "|"))
				test->plaintext = "\xfc"; // ü
			else if (strcmp(test->plaintext, "V"))
				test->plaintext = "\xf6"; // ö
			else if (strcmp(test->plaintext, "#"))
				test->plaintext = "\xa3"; // £
			test++;
		}
	}
	else if (options.target_enc == CP1251) {
		struct fmt_tests *test = self->params.tests;

		while (test) {
			if (strcmp(test->plaintext, "?"))
				test->plaintext = "\xdf"; // Я
			test++;
		}
	}
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
	MEM_FREE(orig_key);
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
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0 && value != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // salt
		goto err;
	if (hexlenl(p, &extra) != 8 * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // encrypted_bytes
		goto err;
	if (hexlenl(p, &extra) != 4 * 2 || extra)
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
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 8; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < 4; i++)
		cs.encrypted_bytes[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);
	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0]) * cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char key[24];
		unsigned char out[32];

		if (cur_salt->type == 0) {
			MD5_CTX mctx;

			MD5_Init(&mctx);
			MD5_Update(&mctx, saved_key[index], PASSWORD_LENGTH);
			MD5_Final(key, &mctx);
		} else if (cur_salt->type == 1) {
			SHA_CTX sctx;

			SHA1_Init(&sctx);
			SHA1_Update(&sctx, saved_key[index], PASSWORD_LENGTH);
			SHA1_Final(key, &sctx);
		}

		// combine key[:16] + salt into a key
		memcpy(key + PASSWORD_DIGEST_LENGTH, cur_salt->salt, 8);
		RC4_single(key, 24, cur_salt->encrypted_bytes, 4, out);
		if (memcmp(out, cur_salt->salt, 4) == 0)
			cracked[index] = 1;
		else
			cracked[index] = 0;
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
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
	unsigned char key7[PLAINTEXT_LENGTH + 1];
	unsigned char *s, *d;
	int len;

	/* Store original */
	len = strnzcpyn(orig_key[index], key, sizeof(orig_key[index]));

	/* Upper-case ASCII and strip 8th bit */
	s = (unsigned char*)orig_key[index];
	d = key7;
	do {
		if (*s >= 'a' && *s <= 'z')
			*d++ = *s ^ 0x20;
		else
			*d++ = *s & 0x7f;
	} while (*s++);

	/* convert key to UTF-16LE and fill with nulls */
	memset(saved_key[index], 0, PASSWORD_LENGTH);
	len = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, key7, len);
	if (len < 0)
		len = strlen16(saved_key[index]);
	saved_len[index] = len << 1;
}

static char *get_key(int index)
{
	return orig_key[index];
}

struct fmt_main fmt_money = {
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
		FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ FORMAT_TAG },
		money_tests
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

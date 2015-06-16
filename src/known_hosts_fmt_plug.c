/* Quick-and-dirty cracker for ~/.ssh/known_hosts hashes (HashKnownHosts yes).
 *
 * Based on http://blog.tremily.us/posts/known_hosts/
 *
 * This software is Copyright (c) 2014, Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Significant speedup Dec 2014, JimF.  OMPSCALE was way off, and:
 * NOTE Appears that salt and password are reversed??  With this info, salt was
 * redone, to compute the first half of the HMAC, and double the speed.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_known_hosts;
#elif FMT_REGISTERS_H
john_register_one(&fmt_known_hosts);
#else

#include "sha.h"
#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "base64.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               2048
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL            "known_hosts"
#define FORMAT_TAG              "$known_hosts$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define FORMAT_NAME             "HashKnownHosts HMAC-SHA1"
#define ALGORITHM_NAME          "SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             20
#define BINARY_ENCODED_SIZE     28
#define PAD_SIZE                64
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests known_hosts_tests[] = {
	{"$known_hosts$|1|yivSFSAv9mhGu/GPc14KpaPMSjE=|I9L3FH6RGefWIFb0Po74BVN3Fto=", "213.100.98.219"},
	{"$known_hosts$|1|pgjIzNM77FYsBHLfKvvG9aWpKAA=|XbHqTCXG1JAV6fb2h2HT8MT7kGU=", "192.30.252.130"},
	{"$known_hosts$|1|vAQX51f9EfXY33/j3upxFIlI1ds=|q+CzSLaa1EaSsAQzP/XRM/gaFQ4=", "192.30.252.128"},
	{"$known_hosts$|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg=", "192.168.1.61"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	SHA_CTX ipad_ctx;
	SHA_CTX opad_ctx;
} *cur_salt;

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
	char *p, *q;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;

	p = q = ciphertext + TAG_LENGTH;
	if (p[0] != '|' || p[2] != '|')
		return 0;
	p += 3;
	q = strchr(p, '|');
	if (q -p != BINARY_ENCODED_SIZE)
		return 0;

	p = strrchr(ciphertext, '|') + 1;
	if (strlen(p) != BINARY_ENCODED_SIZE)
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	char *p, *q;
	unsigned char ipad[20], opad[20], salt[20 + 4 + 1];
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	p = ciphertext +  TAG_LENGTH + 3;

	q = strchr(p, '|');
	base64_decode(p, q - p, (char*)salt);

	for (i = 0; i < 20; ++i) {
		ipad[i] = salt[i] ^ 0x36;
		opad[i] = salt[i] ^ 0x5C;
	}
	SHA1_Init(&cs.ipad_ctx);
	SHA1_Update(&cs.ipad_ctx, ipad, 20);
	SHA1_Update(&cs.ipad_ctx, "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36", 44);
	SHA1_Init(&cs.opad_ctx);
	SHA1_Update(&cs.opad_ctx, opad, 20);
	SHA1_Update(&cs.opad_ctx, "\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C", 44);

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE + 1 + 4];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	p = strrchr(ciphertext, '|') + 1;
	base64_decode((char*)p, BINARY_ENCODED_SIZE, (char*)out);

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		SHA_CTX ctx;
		memcpy(&ctx, &cur_salt->ipad_ctx, sizeof(ctx));
		SHA1_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA1_Final((unsigned char*) crypt_out[index], &ctx);

		memcpy(&ctx, &cur_salt->opad_ctx, sizeof(ctx));
		SHA1_Update(&ctx, crypt_out[index], BINARY_SIZE);
		SHA1_Final((unsigned char*) crypt_out[index], &ctx);
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

static void known_hosts_set_key(char *key, int index)
{
	int len = strlen(key);

	memcpy(saved_key[index], key, len);
	saved_key[index][len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_known_hosts = {
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		known_hosts_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
		set_salt,
		known_hosts_set_key,
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

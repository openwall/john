/* Siemens S7 authentication protocol cracker. Written  by Narendra Kangralkar
 * <narendrakangralkar at gmail.com> and Dhiru Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Narendra Kangralkar <narendrakangralkar at gmail.com>  and it is hereby
 * released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_s7;
#elif FMT_REGISTERS_H
john_register_one(&fmt_s7);
#else

#include "sha.h"
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               2048
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"Siemens-S7"
#define FORMAT_NAME		""
#define ALGORITHM_NAME		"HMAC-SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0
#define PLAINTEXT_LENGTH	125
#define CIPHERTEXT_LENGTH	(1 + 10 + 1 + 1 + 1 + 40 + 1 + 40)
#define BINARY_SIZE		20
#define SALT_SIZE		20
#define BINARY_ALIGN	sizeof(ARCH_WORD_32)
#define SALT_ALIGN		1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	8

static struct fmt_tests s7_tests[] = {
	{"$siemens-s7$1$599fe00cdb61f76cc6e949162f22c95943468acb$002e45951f62602b2f5d15df217f49da2f5379cb", "123"},
	{"$siemens-s7$0$387c1fe4ce97e0e71f5a93b4a9557a947cd40d6c$d7789feee651559a09e2f2d92b57306d2835e209", "321"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static int new_keys;
static SHA_CTX *ipad_ctx;
static SHA_CTX *opad_ctx;

unsigned char *challenge;

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
	ipad_ctx  = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*ipad_ctx));
	opad_ctx  = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_ctx));
}

static void done(void)
{
	MEM_FREE(opad_ctx);
	MEM_FREE(ipad_ctx);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	char *ctcopy;
	char *keeptr;
	if (strncmp(ciphertext, "$siemens-s7$", 12) != 0)
		return 0;
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 12;		/* skip over "$siemens-s7$" */
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* outcome, currently unused */
		goto bail;
	if (strlen(p) != 1 || (*p != '1' && *p != '0')) /* outcome must be '1' or '0' */
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL)	/* challenge */
		goto bail;
	if (strlen(p) != 40 || !ishexlc(p))     /* must be hex string and lower cases*/
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL)	/* Fix bug: #1090 */
		goto bail;
	if (strlen(p) != 40 || !ishexlc(p))
		goto bail;
	MEM_FREE(keeptr);
	return 1;
bail:
	MEM_FREE(keeptr);
	return 0;
}

/*
 * Hash versions '0' and '1' were exactly the same.
 * Version '0' is still supported for backwards compatibility,
 * but version '1' is used as the canonical hash representation
 */
static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH+1];

	strnzcpy(out, ciphertext, CIPHERTEXT_LENGTH+1);
	if( out[12] == '0')
		out[12] = '1';
	return out;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static unsigned char lchallenge[20];
	ctcopy += 12;		/* skip over "$siemens-s7$" */
	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	for (i = 0; i < 20; i++)
		lchallenge[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)lchallenge;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
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

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	challenge = (unsigned char*)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char buf[20];
		SHA_CTX ctx;
		if (new_keys) {
			unsigned char pad[20];
			int i;

			SHA1_Init(&ctx);
			SHA1_Update(&ctx, saved_key[index], strlen(saved_key[index]));
			SHA1_Final(buf, &ctx);
			for (i = 0; i < 20; ++i) {
				pad[i] = buf[i] ^ 0x36;
			}
			SHA1_Init(&ipad_ctx[index]);
			SHA1_Update(&ipad_ctx[index], pad, 20);
			SHA1_Update(&ipad_ctx[index], "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36", 44);
			for (i = 0; i < 20; ++i) {
				pad[i] = buf[i] ^ 0x5C;
			}
			SHA1_Init(&opad_ctx[index]);
			SHA1_Update(&opad_ctx[index], pad, 20);
			SHA1_Update(&opad_ctx[index], "\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C", 44);
		}
		memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
		SHA1_Update(&ctx, challenge, 20);
		SHA1_Final(buf, &ctx);
		memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
		SHA1_Update(&ctx, buf, 20);
		SHA1_Final((unsigned char*)(crypt_out[index]), &ctx);
	}
	new_keys = 0;

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (; index < count; index++)
#endif
		if (*(ARCH_WORD_32*)binary == crypt_out[index][0])
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

static void s7_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int salt_hash(void *salt)
{
    unsigned char *s = salt;
    unsigned int hash = 5381;
    unsigned int len = SALT_SIZE;

    while (len--)
        hash = ((hash << 5) + hash) ^ *s++;

    return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_s7 = {
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
		s7_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
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
		salt_hash,
		NULL,
		set_salt,
		s7_set_key,
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

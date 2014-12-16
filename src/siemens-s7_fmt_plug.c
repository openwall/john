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
#define OMP_SCALE               2048
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"Siemens-S7"
#define FORMAT_NAME		""
#define ALGORITHM_NAME		"HMAC-SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0
#define PLAINTEXT_LENGTH	125
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
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	ipad_ctx = mem_calloc_tiny(sizeof(*opad_ctx) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	opad_ctx = mem_calloc_tiny(sizeof(*opad_ctx) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	char *ctcopy;
	char *keeptr;
	int outcome;
	if (strncmp(ciphertext, "$siemens-s7$", 12) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 12;		/* skip over "$siemens-s7$" */
	if ((p = strtok(ctcopy, "$")) == NULL)	/* outcome */
		goto bail;
	outcome = atoi(p);
	if (outcome != 1 && outcome != 0)
		goto bail;
	if ((p = strtok(NULL, "$")) == NULL)	/* challenge */
		goto bail;
	if (strlen(p) != 40)
		goto bail;
	MEM_FREE(keeptr);
	return 1;
bail:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static unsigned char lchallenge[20];
	ctcopy += 12;		/* skip over "$siemens-s7$" */
	p = strtok(ctcopy, "$");
	p = strtok(NULL, "$");
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
	int count = *pcount;
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
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_s7 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
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
		fmt_default_done,
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

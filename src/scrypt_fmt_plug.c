/* scrypt cracker patch for JtR. Hacked together during May of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#include "crypto_scrypt.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               1 // So slow a format, a multiplier is NOT needed
#endif

#define FORMAT_LABEL		"scrypt"
#define FORMAT_NAME		"django-scrypt"
#define FORMAT_TAG		"scrypt"
#define TAG_LENGTH		6
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		64
#define SALT_SIZE		sizeof(struct custom_salt)
#define BINARY_ALIGN		4
#define SALT_ALIGN		4

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

/* notastrongpassword => scrypt$NBGmaGIXijJW$14$8$1$64$achPt01SbytSt+F3CcCFgEPr96+/j9iCTdejFdAARZ8mzfejrP64TJ5XBJa3gYwuCKOEGlw2E/lWCWS7LeS6CA== */

static struct fmt_tests scrypt_tests[] = {
	/* https://pypi.python.org/pypi/django-scrypt/ format hashes */
	{"scrypt$NBGmaGIXijJW$14$8$1$64$achPt01SbytSt+F3CcCFgEPr96+/j9iCTdejFdAARZ8mzfejrP64TJ5XBJa3gYwuCKOEGlw2E/lWCWS7LeS6CA==", "notastrongpassword"},
	{"scrypt$Cj0PzdtT3qS2$14$8$1$64$qn4CDnM8CcIBNrpQXHo6ti8vSUoSXj7GBFy7k1bp5wPs8jKjh/gHZ+qM9uk6LbcVHm02yBaI5WCbDm/Shq/MXA==", "realmenuseJtR"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int type;
	int N;
	int r;
	int p;
	unsigned char salt[32];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int isDigits(char *p) {
	while (*p && *p != '$') {
		if (*p <= '0' || *p >= '9')
			return 0;
		++p;
	}
	return 1;
}
static int valid(char *ciphertext, struct fmt_main *self)
{
	char *cp, *cp2;
	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH)) return 0;
	cp = ciphertext + TAG_LENGTH;
	if (*cp != '$') return 0;
	++cp;
	cp2 = strchr(cp, '$');
	if (!cp2) return 0;
	if (cp2-cp > 32) return 0;
	cp = &cp2[1];
	if (isDigits(cp) == 0) return 0;
	cp = strchr(cp, '$');
	if (!cp) return 0;
	++cp;
	if (isDigits(cp) == 0) return 0;
	cp = strchr(cp, '$');
	if (!cp) return 0;
	++cp;
	if (isDigits(cp) == 0) return 0;
	cp = strchr(cp, '$');
	if (!cp) return 0;
	++cp;
	if (isDigits(cp) == 0) return 0;
	cp = strchr(cp, '$');
	if (!cp) return 0;
	++cp;
	if (strlen(cp) != 88) return 0;
	return 1;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;
	ctcopy += TAG_LENGTH;
	p = strtok(ctcopy, "$");
	strncpy((char*)cs.salt, p, 32);
	p = strtok(NULL, "$");
	cs.N = atoi(p);
	p = strtok(NULL, "$");
	cs.r = atoi(p);
	p = strtok(NULL, "$");
	cs.p = atoi(p);
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	p = strrchr(ciphertext, '$') + 1;
	base64_decode(p, strlen(p), (char*)out);
	return out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

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
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		crypto_scrypt((unsigned char*)saved_key[index], strlen((char*)saved_key[index]),
				cur_salt->salt, strlen((char*)cur_salt->salt),
				1 << cur_salt->N, cur_salt->r,
				cur_salt->p, (unsigned char*)crypt_out[index],
				BINARY_SIZE);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
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

static void scrypt_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_scrypt = {
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
		scrypt_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		scrypt_set_key,
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

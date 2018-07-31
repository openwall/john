/*
 * Django scrypt cracker patch for JtR. Hacked together during May of 2013 by
 * Dhiru Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_django_scrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_django_scrypt);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64_convert.h"
#include "escrypt/crypto_scrypt.h"
#include "memdbg.h"

#define FORMAT_LABEL		"django-scrypt"
#define FORMAT_NAME		""
#define FORMAT_TAG		"scrypt$"
#define TAG_LENGTH		(sizeof(FORMAT_TAG)-1)
#if !defined(JOHN_NO_SIMD) && defined(__XOP__)
#define ALGORITHM_NAME		"Salsa20/8 128/128 XOP"
#elif !defined(JOHN_NO_SIMD) && defined(__AVX__)
#define ALGORITHM_NAME		"Salsa20/8 128/128 AVX"
#elif !defined(JOHN_NO_SIMD) && defined(__SSE2__)
#define ALGORITHM_NAME		"Salsa20/8 128/128 SSE2"
#else
#define ALGORITHM_NAME		"Salsa20/8 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		64
#define SALT_SIZE		sizeof(struct custom_salt)
#define BINARY_ALIGN		4
#define SALT_ALIGN		4

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#ifndef OMP_SCALE
#define OMP_SCALE           4 // Tuned w/ MKPC for core i7
#endif

/* notastrongpassword => scrypt$NBGmaGIXijJW$14$8$1$64$achPt01SbytSt+F3CcCFgEPr96+/j9iCTdejFdAARZ8mzfejrP64TJ5XBJa3gYwuCKOEGlw2E/lWCWS7LeS6CA== */

static struct fmt_tests scrypt_tests[] = {
	/* https://pypi.python.org/pypi/django-scrypt/ format hashes */
	{"scrypt$NBGmaGIXijJW$14$8$1$64$achPt01SbytSt+F3CcCFgEPr96+/j9iCTdejFdAARZ8mzfejrP64TJ5XBJa3gYwuCKOEGlw2E/lWCWS7LeS6CA==", "notastrongpassword"},
	{"scrypt$Cj0PzdtT3qS2$14$8$1$64$qn4CDnM8CcIBNrpQXHo6ti8vSUoSXj7GBFy7k1bp5wPs8jKjh/gHZ+qM9uk6LbcVHm02yBaI5WCbDm/Shq/MXA==", "realmenuseJtR"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	/* int type; */ // not used (another type probably required a new JtR format)
	int N;
	int r;
	int p;
	unsigned char salt[32];
} *cur_salt;

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
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
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

	/* ensure alignment */
	static union {
		struct custom_salt _cs;
		uint32_t dummy;
	} un;
	static struct custom_salt *cs = &(un._cs);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	strncpy((char*)cs->salt, p, 32);
	p = strtokm(NULL, "$");
	cs->N = atoi(p);
	p = strtokm(NULL, "$");
	cs->r = atoi(p);
	p = strtokm(NULL, "$");
	cs->p = atoi(p);
	MEM_FREE(keeptr);
	return (void *)cs;
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
	base64_convert(p, e_b64_mime, strlen(p), (char*)out, e_b64_raw, sizeof(buf.c), flg_Base64_DONOT_NULL_TERMINATE, 0);
	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

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
		if (crypto_scrypt((unsigned char*)saved_key[index], strlen((char*)saved_key[index]),
				cur_salt->salt, strlen((char*)cur_salt->salt),
				(1ULL) << cur_salt->N, cur_salt->r,
				cur_salt->p, (unsigned char*)crypt_out[index],
				BINARY_SIZE) == -1) {
			memset(crypt_out[index], 0, sizeof(crypt_out[index]));
		}
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

static void scrypt_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int tunable_cost_N(void *salt)
{
	static struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->N;
}

static unsigned int tunable_cost_r(void *salt)
{
	static struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->r;
}

static unsigned int tunable_cost_p(void *salt)
{
	static struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->p;
}

struct fmt_main fmt_django_scrypt = {
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
		{
			"N",
			"r",
			"p"
		},
		{ FORMAT_TAG },
		scrypt_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			tunable_cost_N,
			tunable_cost_r,
			tunable_cost_p
		},
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
		scrypt_set_key,
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

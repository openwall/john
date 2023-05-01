/*
 * Django 1.4 patch for JtR. Hacked together during May of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format => user:$django$*type*django-hash
 *
 * Where,
 *
 * type => 1, for Django 1.4 pbkdf_sha256 hashes and
 *
 * django-hash => Second column of "SELECT username, password FROM auth_user"
 *
 * July, 2012, the OpenSSL PKCS5_PBKDF2_HMAC function was replaced with a much faster
 * function pbkdf2() designed by JimF.  Originally this function was designed for
 * the mscash2 (DCC2). The same pbkdf2 function, is used, and simply required small
 * changes to use SHA256.
 *
 * This new code is 3x to 4x FASTER than the original OpenSSL code. Even though it is
 * only using OpenSSL functions. A lot of the high level stuff in OpenSSL sux for speed.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_django;
#elif FMT_REGISTERS_H
john_register_one(&fmt_django);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "base64_convert.h"
#include "pbkdf2_hmac_sha256.h"

#define FORMAT_LABEL            "Django"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$django$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA256 " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       " (x10000)"
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define HASH_LENGTH             44
#define BINARY_SIZE             32
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      (1 * SSE_GROUP_SZ_SHA256)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      8
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               2 // MKPC & scale tuned for i7
#endif

static struct fmt_tests django_tests[] = {
	{"$django$*1*pbkdf2_sha256$10000$qPmFbibfAY06$x/geVEkdZSlJMqvIYJ7G6i5l/6KJ0UpvLUU6cfj83VM=", "openwall"},
	{"$django$*1*pbkdf2_sha256$10000$BVmpZMBhRSd7$2nTDwPhSsDKOwpKiV04teVtf+a14Rs7na/lIB3KnHkM=", "123"},
	{"$django$*1*pbkdf2_sha256$10000$BVmpZMBhRSd1$bkdQo9RoatRomupPFP+XEo+Guuirq4mi+R1cFcV0U3M=", "openwall"},
	{"$django$*1*pbkdf2_sha256$10000$BVmpZMBhRSd6$Uq33DAHOFHUED+32IIqCqm+ITU1mhsGOJ7YwFf6h+6k=", "password"},
	{"$django$*1*pbkdf2_sha256$10000$34L3roCQ6ZfN$R21tJK1sIDfmj9BfBocefFfuGVwE3pXcLEhChNjc+pU=", "0123456789012345678901234567890123456789012345678901234567890123"},
	{"$django$*1*pbkdf2_sha256$10000$7qPqyUDw8kZV$pFmVRjlHvayoWEy8ZWXkHgfmgImUKLmkmruclpYVAxM=", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	int type;
	int iterations;
	union {
		unsigned char c[32];
		unsigned int i[8];
	} salt;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(sizeof(*saved_key),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_align(sizeof(*crypt_out), self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* type */
		goto err;
	/* type must be 1 */
	if (!isdec(p))
		goto err;
	if (atoi(p) != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* algorithm */
		goto err;
	if (strcmp(p, "pbkdf2_sha256") != 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p)) // FIXME: what about iterations == 0?
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (strlen(p)  > sizeof(cur_salt->salt.c)-1)
		goto err;
	if ((p = strtokm(NULL, "")) == NULL)	/* hash */
		goto err;
	if (strlen(p)-1 != base64_valid_length(p,e_b64_mime,flg_Base64_MIME_TRAIL_EQ, 0) || strlen(p)-1 > HASH_LENGTH-1)  {
		goto err;
	}
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char Buf[120], *ctcopy=Buf;
	char *p, *t;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	strncpy(Buf, ciphertext, 119);
	Buf[119] = 0;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$django$*" */
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	strtokm(NULL, "$");
	t = strtokm(NULL, "$");
	cs.iterations = atoi(t);
	t = strtokm(NULL, "$");
	strcpy((char*)cs.salt.c, t);

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{	static union {
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
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		int lens[MIN_KEYS_PER_CRYPT], i;
		unsigned char *pin[MIN_KEYS_PER_CRYPT];
		union {
			uint32_t *pout[MIN_KEYS_PER_CRYPT];
			unsigned char *poutc;
		} x;
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			x.pout[i] = crypt_out[i+index];
		}
		pbkdf2_sha256_sse((const unsigned char **)pin, lens, cur_salt->salt.c, strlen((char*)cur_salt->salt.c), cur_salt->iterations, &(x.poutc), 32, 0);
#else
		pbkdf2_sha256((unsigned char *)saved_key[index], strlen(saved_key[index]),
			cur_salt->salt.c, strlen((char*)cur_salt->salt.c),
			cur_salt->iterations, (unsigned char*)crypt_out[index], 32, 0);
#endif
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

static void django_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)my_salt->iterations;
}

static int salt_hash(void *salt)
{
	uint32_t s = *((struct custom_salt*)salt)->salt.i;

	return s & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_django = {
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
			"iteration count",
		},
		{ FORMAT_TAG },
		django_tests
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
			iteration_count,
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
		salt_hash,
		NULL,
		set_salt,
		django_set_key,
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

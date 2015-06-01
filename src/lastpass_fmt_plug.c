/* LastPass offline cracker patch for JtR. Hacked together during January of 2013 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * All the hard work was done by Milen (author of hashkill).
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.  */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_lastpass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_lastpass);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include <openssl/aes.h>
#include "pbkdf2_hmac_sha256.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               64
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"lp"
#define FORMAT_NAME		"LastPass offline"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME		"PBKDF2-SHA256 " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME		"PBKDF2-SHA256 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define BINARY_ALIGN		sizeof(ARCH_WORD_32)
#define SALT_ALIGN			sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA256
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

static struct fmt_tests lastpass_tests[] = {
	{"$lp$hackme@mailinator.com$6f5d8cec3615fc9ac7ba2e0569bce4f5", "strongpassword"},
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[32 / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int iterations;
	int salt_length;
	unsigned char salt[32];
} *cur_salt;

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	if (strncmp(ciphertext, "$lp$", 4))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 4;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* email */
		goto err;
	if (strlen(p) > 32)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* hash */
		goto err;
	if (strlen(p) != 32)
		goto err;
	if (!ishex(p))
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += 4;	/* skip over "$lp$" */
	p = strtokm(ctcopy, "$");
	strncpy((char*)cs.salt, p, 32);
	cs.salt_length = strlen((char*)p);
	MEM_FREE(keeptr);
	return (void *)&cs;
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
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
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
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		AES_KEY akey;
#ifdef SIMD_COEF_32
		int lens[MAX_KEYS_PER_CRYPT], i;
		unsigned char *pin[MAX_KEYS_PER_CRYPT];
		ARCH_WORD_32 key[MAX_KEYS_PER_CRYPT][8];
		union {
			ARCH_WORD_32 *pout[MAX_KEYS_PER_CRYPT];
			unsigned char *poutc;
		} x;
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			x.pout[i] = key[i];
		}
		pbkdf2_sha256_sse((const unsigned char **)pin, lens, cur_salt->salt, cur_salt->salt_length, 500, &(x.poutc), 32, 0);

		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			memset(&akey, 0, sizeof(AES_KEY));
			AES_set_encrypt_key((unsigned char*)key[i], 256, &akey);
			AES_ecb_encrypt((unsigned char*)"lastpass rocks\x02\x02", (unsigned char*)crypt_out[i+index], &akey, AES_ENCRYPT);
		}
#else
		unsigned char key[32];
		pbkdf2_sha256((unsigned char*)saved_key[index], strlen(saved_key[index]), cur_salt->salt, cur_salt->salt_length, 500, key, 32, 0);
#if !ARCH_LITTLE_ENDIAN
		{
			int i;
			for (i = 0; i < 8; ++i) {
				((ARCH_WORD_32*)key)[i] = JOHNSWAP(((ARCH_WORD_32*)key)[i]);
			}
		}
#endif
		memset(&akey, 0, sizeof(AES_KEY));
		AES_set_encrypt_key((unsigned char*)key, 256, &akey);
		AES_ecb_encrypt((unsigned char*)"lastpass rocks\x02\x02", (unsigned char*)crypt_out[index], &akey, AES_ENCRYPT);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
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

static void lastpass_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_lastpass = {
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
		lastpass_tests
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
		NULL,
		set_salt,
		lastpass_set_key,
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

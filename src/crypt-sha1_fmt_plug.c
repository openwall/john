/*
 * This file is based on the "cryptsha512_fmt_plug.c" file.
 *
 * This software is Copyright (c) 2014 Dhiru Kholia, and it is hereby released
 * to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Enhanced code (dropped usage of the Gladman hmac code), and addition of SSE2
 * logic, Aug 2014, JimF.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cryptsha1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cryptsha1);
#else

#include <string.h>
#ifdef _OPENMP
#ifndef OMP_SCALE
#define OMP_SCALE                   32 // tuned on core i7 w/ HT
#endif
#include <omp.h>
#endif

#include "arch.h"
#include "sha.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#define PBKDF1_LOGIC 1
#include "pbkdf2_hmac_sha1.h"
#include "base64_convert.h"
#include "sha1crypt_common.h"
#include "memdbg.h"

#define SHA1_SIZE 20

#define FORMAT_LABEL                "sha1crypt"
#define FORMAT_NAME                 "NetBSD's sha1crypt"
#define BENCHMARK_COMMENT           ""
#define BENCHMARK_LENGTH            -1001

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF1-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF1-SHA1 " ARCH_BITS_STR "/" ARCH_BITS_STR
#endif

#define PLAINTEXT_LENGTH            125

#define BINARY_ALIGN                4
#define SALT_SIZE                   sizeof(struct saltstruct)
#define SALT_ALIGN                  4

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif


/* An example hash (of password) is $sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq.
 * An sha1-crypt hash string has the format $sha1$rounds$salt$checksum, where:
 *
 * $sha1$ is the prefix used to identify sha1-crypt hashes, following the Modular Crypt Format
 * rounds is the decimal number of rounds to use (40000 in the example).
 * salt is 0-64 characters drawn from [./0-9A-Za-z] (jtNX3nZ2 in the example).
 * checksum is 28 characters drawn from the same set, encoding a 168-bit checksum.
 */

// static struct fmt_tests sha1crypt_common_tests[] = {  // located in sha1crypt_common.c

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct saltstruct {
	unsigned int length;
	unsigned int rounds;
	unsigned char salt[SALT_LENGTH+sizeof(SHA1_MAGIC)+7+1]; // allows up to 9999999 sized rounds with 64 byte salt.
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

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }


static void set_key(char *key, int index)
{
	int len = strlen(key);
	if (len > PLAINTEXT_LENGTH)
		len =  PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
	saved_key[index][len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
#ifdef SSE_GROUP_SZ_SHA1
		int lens[SSE_GROUP_SZ_SHA1], i;
		unsigned char *pin[SSE_GROUP_SZ_SHA1];
		union {
			ARCH_WORD_32 *pout[SSE_GROUP_SZ_SHA1];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA1; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = crypt_out[index+i];
		}
		pbkdf1_sha1_sse((const unsigned char **)pin, lens,
		                cur_salt->salt, cur_salt->length,
		                cur_salt->rounds, &(x.poutc),
		                BINARY_SIZE, 0);
#else
		pbkdf1_sha1((const unsigned char*)(saved_key[index]),
		            strlen(saved_key[index]),
		            cur_salt->salt, cur_salt->length,
		            cur_salt->rounds, (unsigned char*)crypt_out[index],
		            BINARY_SIZE, 0);
#endif
	}
	return count;
}

static void set_salt(void *salt)
{
	cur_salt = salt;
}

static void *get_salt(char *ciphertext)
{
	static struct saltstruct out;
	char tmp[sizeof(out.salt)];
	char *p;
	memset(&out, 0, sizeof(out));
	p = strrchr(ciphertext, '$') + 1;
	strnzcpy(tmp, ciphertext, p - ciphertext);
	out.rounds = strtoul(&ciphertext[sizeof(SHA1_MAGIC)-1], NULL, 10);
	// point p to the salt value, BUT we have to decorate the salt for this hash.
	p = strrchr(tmp, '$') + 1;
	// real salt used is: <salt><magic><iterations>
	out.length = snprintf((char*)out.salt, sizeof(out.salt), "%.*s%s%u", (int)strlen(p), p, SHA1_MAGIC, out.rounds);
	return &out;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
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

// Public domain hash function by DJ Bernstein
// We are hashing the entire struct
static int salt_hash(void *salt)
{
	unsigned char *s = salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < SALT_SIZE; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct saltstruct *p = (struct saltstruct *)salt;
	return p->rounds;
}
#endif

struct fmt_main fmt_cryptsha1 = {
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
		{
			"iteration count",
		},
#endif
		sha1crypt_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		sha1crypt_common_valid,
		fmt_default_split,
		sha1crypt_common_get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
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
		set_key,
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

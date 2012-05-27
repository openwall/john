/* WoltLab Burning Board 3 (WBB3) cracker patch for JtR. Hacked together during
 * May of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format => user:$wbb3$*type*hash
 *
 * Where,
 *
 * type => 1, for sha1($salt.sha1($salt.sha1($pass))) hashing scheme */

#if defined(__APPLE__) && defined(__MACH__) && \
	defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && \
	__MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#else
#include "sha.h"
#endif

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"wbb3"
#define FORMAT_NAME		"WoltLab BB3 SHA-1"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests wbb3_tests[] = {
	{"$wbb3$*1*0b053db07dc02bc6f6e24e00462f17e3c550afa9*e2063f7c629d852302d3020599376016ff340399", "123456"},
	{NULL}
};


static int omp_t = 1;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;

static struct custom_salt {
	int type;
	unsigned char salt[41];
	unsigned char hash[20];
} *salt_struct;

static void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	unsigned char *p = out;
	for (i = 0; i < len; ++i) {
		sprintf((char*)p, "%02x", str[i]);
		p += 2;
	}
}

static void init(struct fmt_main *pFmt)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	any_cracked = 0;
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$wbb3$", 6);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	ctcopy += 7;	/* skip over "$wbb3$*" */
	p = strtok(ctcopy, "*");
	cs.type = atoi(p);
	p = strtok(NULL, "*");
	strcpy((char *)cs.salt, p);
	p = strtok(NULL, "*");
	for (i = 0; i < 20; i++)
		cs.hash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	free(keeptr);
	return (void *)&cs;
}


static void set_salt(void *salt)
{
	salt_struct = (struct custom_salt *)salt;
	if (any_cracked) {
		memset(cracked, 0,
		    sizeof(*cracked) * omp_t * MAX_KEYS_PER_CRYPT);
		any_cracked = 0;
	}
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char hash[20];
		unsigned char hexhash[40+1];
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA1_Final(hash, &ctx);
		hex_encode(hash, 20, hexhash);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, salt_struct->salt, 40);
		SHA1_Update(&ctx, hexhash, 40);
		SHA1_Final(hash, &ctx);
		hex_encode(hash, 20, hexhash);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, salt_struct->salt, 40);
		SHA1_Update(&ctx, hexhash, 40);
		SHA1_Final(hash, &ctx);
		if(!memcmp(hash, salt_struct->hash, 20))
			any_cracked = cracked[index] = 1;
	}
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
	return cracked[index];
}

static void wbb3_set_key(char *key, int index)
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

struct fmt_main wbb3_fmt = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		wbb3_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		wbb3_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact,
		fmt_default_get_source
	}
};

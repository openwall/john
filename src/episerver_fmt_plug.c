/* *New* EPiServer cracker patch for JtR. Hacked together during Summer of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC. Based on sample
 * code by hashcat's atom.
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format:
 *
 * user:$episerver$*version*base64(salt)*base64(hash)
 *
 * Where,
 *
 * version == 0, for EPiServer 6.x standard config / .NET <= 3.5 SHA1 hash/salt format.
 * 		 hash =  sha1(salt | utf16bytes(password)). */

#include <openssl/sha.h>
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

#define FORMAT_LABEL		"episerver"
#define FORMAT_NAME		"EPiServer"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		256
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests episerver_tests[] = {
	{"$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*UQgnz/vPWap9UeD8Dhaw3h/fgFA=", "testPassword"},
	{"$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*uiP1YrZlVcHESbfsRt/wljwNeYU=", "sss"},
	{"$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*dxTlKqnxaVHs0210VcX+48QDonA=", "notused"},
	{NULL}
};

static int omp_t = 1;
static char unsigned esalt[16];
static char unsigned hash[20];
static int version;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char *cracked;

static void init(struct fmt_main *pFmt)
{

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$episerver$", 11);
}

static void *get_salt(char *ciphertext)
{
	return ciphertext;
}


static void set_salt(void *salt)
{
	char *saltcopy = strdup(salt);
	char *keeptr = saltcopy;
	saltcopy += 12;	/* skip over "$episerver$*" */
	char *p = strtok(saltcopy, "*");
	version = atoi(p);
	p = strtok(NULL, "*");
	base64_decode(p, strlen(p), (char*)esalt);
	p = strtok(NULL, "*");
	base64_decode(p, strlen(p), (char*)hash);
	free(keeptr);
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char passwordBuf[PLAINTEXT_LENGTH*2] = {0};
		int passwordBufSize = strlen(saved_key[index]) * 2;
		int i;
		unsigned char c;
		int position = 0;
		for(i = 0; (c = saved_key[index][i]); i++) {
			passwordBuf[position] = c;
			position += 2;
		}
		unsigned int sha1hash[5];
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, esalt, 16);
		SHA1_Update(&ctx, passwordBuf, passwordBufSize);
		SHA1_Final((unsigned char *)sha1hash, &ctx);
		if(!memcmp(sha1hash, hash, 20))
			cracked[index] = 1;
		else
			cracked[index] = 0;
	}
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

static void episerver_set_key(char *key, int index)
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

struct fmt_main episerver_fmt = {
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
		episerver_tests
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
		episerver_set_key,
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

/* Django 1.4 patch for JtR. Hacked together during May of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
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
 * django-hash => Second column of "SELECT username, password FROM auth_user" */


#include <openssl/evp.h>
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

#define FORMAT_LABEL		"django"
#define FORMAT_NAME		"Django"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests django_tests[] = {
	{"$django$*1*pbkdf2_sha256$10000$qPmFbibfAY06$x/geVEkdZSlJMqvIYJ7G6i5l/6KJ0UpvLUU6cfj83VM=", "openwall"},
	{NULL}
};


static int omp_t = 1;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;

static struct custom_salt {
	int type;
	int iterations;
	unsigned char salt[32];
	unsigned char hash[32];
} *salt_struct;

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
	return !strncmp(ciphertext, "$django$", 8);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	ctcopy += 9;	/* skip over "$django$*" */
	static struct custom_salt cs;
	p = strtok(ctcopy, "*");
	cs.type = atoi(p);
	p = strtok(NULL, "*");
	/* break up 'p' */
	char *t = strtok(p, "$");
	t = strtok(NULL, "$");
	cs.iterations = atoi(t);
	t = strtok(NULL, "$");
	strcpy((char*)cs.salt, t);
	t = strtok(NULL, "$");
	base64_decode(t, strlen(t), (char*)cs.hash);

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
		unsigned char out[32];
		if(PKCS5_PBKDF2_HMAC(saved_key[index], strlen(saved_key[index]),
			salt_struct->salt, strlen((char*)salt_struct->salt), salt_struct->iterations, EVP_sha256(), 32, out) != 0 ) {
			if(!memcmp(out, salt_struct->hash, 32))
				any_cracked = cracked[index] = 1;
		}
		else {
			fprintf(stderr, "PKCS5_PBKDF2_HMAC_SHA1 failed\n");
			exit(-1);
		}
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

static void django_set_key(char *key, int index)
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

struct fmt_main django_fmt = {
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
		django_tests
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
		django_set_key,
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

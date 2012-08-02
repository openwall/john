/* Office 97-2003 cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * Copyright © 2009, David Leblanc (http://offcrypto.codeplex.com/)
 *
 * License: Microsoft Public License (MS-PL)
 *
 * Version: 8 (Last edited Apr 10 2009 at 2:26 AM by dcleblanc) */

#include "md5.h"
#include "rc4.h"
#include <string.h>
#include "stdint.h"
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
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"oldoffice"
#define FORMAT_NAME		"Office <= 2003 RC4 MD5"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests KeePass_tests[] = {
	{"$oldoffice$1*de17a7f3c3ff03a39937ba9666d6e952*2374d5b6ce7449f57c9f252f9f9b53d2*e60e1185f7aecedba262f869c0236f81", "test"},
	{"$oldoffice$0*e40b4fdade5be6be329c4238e2099b8a*259590322b55f7a3c38cb96b5864e72d*2e6516bfaf981770fe6819a34998295d", "123456789012345"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	int type;
	unsigned char salt[16];
	unsigned char verifier[16];
	unsigned char verifierHash[16];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = 1;
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$oldoffice$", 11);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	ctcopy += 11;	/* skip over "$oldoffice$" */
	p = strtok(ctcopy, "*");
	cs.type = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.verifier[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.verifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	free(keeptr);

	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	if (any_cracked) {
		memset(cracked, 0, cracked_size);
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
		unsigned char passwordBuf[PLAINTEXT_LENGTH*2] = {0};
		int passwordBufSize = strlen(saved_key[index]) * 2;
		int i;
		unsigned char c;
		int position = 0;
		MD5_CTX ctx;
		unsigned char pwdHash[16];
		unsigned char rc4Key[16];
		unsigned char hashBuf[21 * 16];
		RC4_KEY key;

		/* convert password to UTF-16 */
		for(i = 0; (c = saved_key[index][i]); i++) {
			passwordBuf[position] = c;
			position += 2;
		}
		MD5_Init(&ctx);
		MD5_Update(&ctx, passwordBuf, passwordBufSize);
		MD5_Final(pwdHash, &ctx);
		for (i = 0; i < 16; i++)
		{
			memcpy(hashBuf + i * 21, pwdHash, 5);
			memcpy(hashBuf + i * 21 + 5, cur_salt->salt, 16);
		}
		MD5_Init(&ctx);
		MD5_Update(&ctx, hashBuf, 21 * 16);
		MD5_Final(pwdHash, &ctx);
		memcpy(hashBuf, pwdHash, 5);
		memset(hashBuf + 5, 0, 4);
		MD5_Init(&ctx);
		MD5_Update(&ctx, hashBuf, 9);
		MD5_Final(pwdHash, &ctx);
		memcpy(rc4Key, pwdHash, 16); /* 128-bit key */
		RC4_set_key(&key, 16, rc4Key);
		RC4(&key, 16, cur_salt->verifier, hashBuf); /* encryptedVerifier*/
		RC4(&key, 16, cur_salt->verifierHash, hashBuf + 16); /* encryptedVerifierHash */
		/* hash the decrypted verifier */
		MD5_Init(&ctx);
		MD5_Update(&ctx, hashBuf, 16);
		MD5_Final(pwdHash, &ctx);
		if(!memcmp(pwdHash, hashBuf + 16, 16))
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

static void KeePass_set_key(char *key, int index)
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

struct fmt_main oldoffice_fmt = {
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
		KeePass_tests
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
		KeePass_set_key,
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

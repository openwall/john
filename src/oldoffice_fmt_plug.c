/* Office 97-2003 cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * Copyright (c) 2009, David Leblanc (http://offcrypto.codeplex.com/)
 *
 * License: Microsoft Public License (MS-PL)
 *
 * Version: 8 (Last edited Apr 10 2009 at 2:26 AM by dcleblanc) */

#include "md5.h"
#include "rc4.h"
#include <string.h>
#include "stdint.h"
#include <assert.h>
#include <openssl/sha.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"oldoffice"
#define FORMAT_NAME		"Office <= 2003 MD5/SHA-1, RC4"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	64
#define BINARY_SIZE		0
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests oo_tests[] = {
	{"$oldoffice$1*de17a7f3c3ff03a39937ba9666d6e952*2374d5b6ce7449f57c9f252f9f9b53d2*e60e1185f7aecedba262f869c0236f81", "test"},
	{"$oldoffice$0*e40b4fdade5be6be329c4238e2099b8a*259590322b55f7a3c38cb96b5864e72d*2e6516bfaf981770fe6819a34998295d", "123456789012345"},
	/* 2003-RC4-40bit-MS-Base-Crypto-1.0_myhovercraftisfullofeels_.doc */
	{"$oldoffice$3*9f32522fe9bcb69b12f39d3c24b39b2f*fac8b91a8a578468ae7001df4947558f*f2e267a5bea45736b52d6d1051eca1b935eabf3a", "myhovercraftisfullofeels"},
	/* Test-RC4-40bit-MS-Base-DSS_myhovercraftisfullofeels_.doc */
	{"$oldoffice$3*095b777a73a10fb6bcd3e48d50f8f8c5*36902daab0d0f38f587a84b24bd40dce*25db453f79e8cbe4da1844822b88f6ce18a5edd2", "myhovercraftisfullofeels"},
	/* 2003-RC4-40bit-MS-Base-DH-SChan_myhovercraftisfullofeels_.doc */
	{"$oldoffice$3*284bc91cb64bc847a7a44bc7bf34fb69*1f8c589c6fcbd43c42b2bc6fff4fd12b*2bc7d8e866c9ea40526d3c0a59e2d37d8ded3550", "myhovercraftisfullofeels"},
	/* Test-RC4-128bit-MS-Strong-Crypto_myhovercraftisfullofeels_.doc */
	{"$oldoffice$4*a58b39c30a06832ee664c1db48d17304*986a45cc9e17e062f05ceec37ec0db17*fe0c130ef374088f3fec1979aed4d67459a6eb9a", "myhovercraftisfullofeels"},
	/* the following hash was extracted from Proc2356.ppt (manually + by oldoffice2john.py */
	{"$oldoffice$3*DB575DDA2E450AB3DFDF77A2E9B3D4C7*AB183C4C8B5E5DD7B9F3AF8AE5FFF31A*B63594447FAE7D4945D2DAFD113FD8C9F6191BF5", "crypto"},
	{"$oldoffice$3*3fbf56a18b026e25815cbea85a16036c*216562ea03b4165b54cfaabe89d36596*91308b40297b7ce31af2e8c57c6407994b205590", "openwall"},
	/* 2003-RC4-40bit-MS-Base-1.0_myhovercraftisfullofeels_.xls */
	{"$oldoffice$3*f426041b2eba9745d30c7949801f7d3a*888b34927e5f31e2703cc4ce86a6fd78*ff66200812fd06c1ba43ec2be9f3390addb20096", "myhovercraftisfullofeels"},
	{NULL}
};

/* Password encoded in UCS-2 */
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
/* UCS-2 password length, in octets */
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	int type;
	unsigned char salt[16];
	unsigned char verifier[16]; /* or encryptedVerifier */
	unsigned char verifierHash[20];  /* or encryptedVerifierHash */
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
	if (options.utf8)
		self->params.plaintext_length = 3 * PLAINTEXT_LENGTH > 125 ?
			125 : 3 * PLAINTEXT_LENGTH;
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
	                            self->params.max_keys_per_crypt, sizeof(UTF16));
	saved_len = mem_calloc_tiny(sizeof(*saved_len) *
	                            self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
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
	if(cs.type < 3) {
		for (i = 0; i < 16; i++)
			cs.verifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	else {
		for (i = 0; i < 20; i++)
			cs.verifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	MEM_FREE(keeptr);
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
		int i;
		MD5_CTX ctx;
		unsigned char pwdHash[16];
		unsigned char hashBuf[21 * 16];
		RC4_KEY key;

		if(cur_salt->type < 3) {
			MD5_Init(&ctx);
			MD5_Update(&ctx, saved_key[index], saved_len[index]);
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
			RC4_set_key(&key, 16, pwdHash); /* rc4Key */
			RC4(&key, 16, cur_salt->verifier, hashBuf); /* encryptedVerifier */
			RC4(&key, 16, cur_salt->verifierHash, hashBuf + 16); /* encryptedVerifierHash */
			/* hash the decrypted verifier */
			MD5_Init(&ctx);
			MD5_Update(&ctx, hashBuf, 16);
			MD5_Final(pwdHash, &ctx);
			if(!memcmp(pwdHash, hashBuf + 16, 16))
				any_cracked = cracked[index] = 1;
		}
		else {
			SHA_CTX ctx;
			unsigned char H0[24];
			unsigned char Hfinal[20];
			unsigned char DecryptedVerifier[16];
			unsigned char DecryptedVerifierHash[20];

			SHA1_Init(&ctx);
			SHA1_Update(&ctx, cur_salt->salt, 16);
			SHA1_Update(&ctx, saved_key[index], saved_len[index]);
			SHA1_Final(H0, &ctx);
			memset(&H0[20], 0, 4);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, H0, 24);
			SHA1_Final(Hfinal, &ctx);
			if(cur_salt->type < 4)
				memset(&Hfinal[5], 0, 11);
			RC4_set_key(&key, 16, Hfinal); /* dek */
			RC4(&key, 16, cur_salt->verifier, DecryptedVerifier);
			RC4(&key, 20, cur_salt->verifierHash, DecryptedVerifierHash);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, DecryptedVerifier, 16);
			SHA1_Final(Hfinal, &ctx);
			if(!memcmp(Hfinal, DecryptedVerifierHash, 16))
				any_cracked = cracked[index] = 1;
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
	return 1;
}

static void set_key(char *key, int index)
{
	/* convert key to UTF-16LE */
	saved_len[index] = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
	if (saved_len[index] < 0)
		saved_len[index] = strlen16(saved_key[index]);
	saved_len[index] <<= 1;
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8,
		oo_tests
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
		set_key,
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

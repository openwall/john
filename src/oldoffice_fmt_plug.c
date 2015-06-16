/* MS Office 97-2003 cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2014, magnum
 * Copyright (c) 2009, David Leblanc (http://offcrypto.codeplex.com/)
 *
 * License: Microsoft Public License (MS-PL)
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_oldoffice;
#elif FMT_REGISTERS_H
john_register_one(&fmt_oldoffice);
#else

#include "md5.h"
#include "rc4.h"
#include <string.h>
#include "stdint.h"
#include <assert.h>
#include "sha.h"
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
#ifndef OMP_SCALE
#define OMP_SCALE               256
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"oldoffice"
#define FORMAT_NAME		"MS Office <= 2003"
#define ALGORITHM_NAME		"MD5/SHA1 RC4 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1000
#define PLAINTEXT_LENGTH	64
#define BINARY_SIZE		0
#define SALT_SIZE		sizeof(struct custom_salt)
#define BINARY_ALIGN	1
#define SALT_ALIGN	sizeof(int)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define CIPHERTEXT_LENGTH	(TAG_LEN + 120)
#define FORMAT_TAG		"$oldoffice$"
#define TAG_LEN			(sizeof(FORMAT_TAG) - 1)

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
	/* Meet-in-the-middle candidate produced with oclHashcat -m9710 */
	/* Real pw is "hashcat", one collision is "zvDtu!" */
	{"$oldoffice$1*d6aabb63363188b9b73a88efb9c9152e*afbbb9254764273f8f4fad9a5d82981f*6f09fd2eafc4ade522b5f2bee0eaf66d*f2ab1219ae", "zvDtu!"},
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
	unsigned int has_mitm;
	unsigned char mitm[5]; /* Meet-in-the-middle hint, if we have one */
} *cur_salt;

static struct custom_salt cs;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = 1;
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	if (pers_opts.target_enc == UTF_8)
		self->params.plaintext_length = 3 * PLAINTEXT_LENGTH > 125 ?
			125 : 3 * PLAINTEXT_LENGTH;
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(1, cracked_size);
	cur_salt = &cs;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int res;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LEN))
		return 0;
	if (strlen(ciphertext) > CIPHERTEXT_LENGTH)
		return 0;
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += TAG_LEN;
	if (!(ptr = strtokm(ctcopy, "*"))) /* type */
		goto error;
	res = atoi(ptr);
	if (res > 4)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* salt */
		goto error;
	if (strlen(ptr) != 32)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* verifier */
		goto error;
	if (strlen(ptr) != 32)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* verifier hash */
		goto error;
	if (res < 3 && strlen(ptr) != 32)
		goto error;
	if (res >= 3 && strlen(ptr) != 40)
		goto error;
	if (!ishex(ptr))
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH];

	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);

	return out;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(cs));
	ctcopy += TAG_LEN;	/* skip over "$oldoffice$" */
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.verifier[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
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
	if ((p = strtokm(NULL, "*"))) {
		cs.has_mitm = 1;
		for (i = 0; i < 5; i++)
			cs.mitm[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	} else
		cs.has_mitm = 0;
	MEM_FREE(keeptr);
	return (void *)&cs;
}

#if 0
static char *source(char *source, void *binary)
{
	static char Buf[CIPHERTEXT_LENGTH];
	unsigned char *cpi, *cp = (unsigned char*)Buf;
	int i, len;

	cp += sprintf(Buf, "%s%d*", FORMAT_TAG, cur_salt->type);

	cpi = cur_salt->salt;
	for (i = 0; i < 16; i++) {
		*cp++ = itoa16[*cpi >> 4];
		*cp++ = itoa16[*cpi & 0xf];
		cpi++;
	}
	*cp++ = '*';

	cpi = cur_salt->verifier;
	for (i = 0; i < 16; i++) {
		*cp++ = itoa16[*cpi >> 4];
		*cp++ = itoa16[*cpi & 0xf];
		cpi++;
	}
	*cp++ = '*';

	len = (cur_salt->type < 3) ? 16 : 20;
	cpi = cur_salt->verifierHash;
	for (i = 0; i < len; i++) {
		*cp++ = itoa16[*cpi >> 4];
		*cp++ = itoa16[*cpi & 0xf];
		cpi++;
	}

	if (cur_salt->has_mitm) {
		*cp++ = '*';
		cpi = cur_salt->mitm;
		for (i = 0; i < 5; i++) {
			*cp++ = itoa16[*cpi >> 4];
			*cp++ = itoa16[*cpi & 0xf];
			cpi++;
		}
	}

	*cp = 0;
	return Buf;
}
#endif

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		int i;
		RC4_KEY key;

		if(cur_salt->type < 3) {
			MD5_CTX ctx;
			unsigned char mid_key[16];
			unsigned char pwdHash[16];
			unsigned char hashBuf[21 * 16];

			MD5_Init(&ctx);
			MD5_Update(&ctx, saved_key[index], saved_len[index]);
			MD5_Final(mid_key, &ctx);
			for (i = 0; i < 16; i++)
			{
				memcpy(hashBuf + i * 21, mid_key, 5);
				memcpy(hashBuf + i * 21 + 5, cur_salt->salt, 16);
			}
			MD5_Init(&ctx);
			MD5_Update(&ctx, hashBuf, 21 * 16);
			MD5_Final(mid_key, &ctx);
			// Early reject if we got a hint
			if (cur_salt->has_mitm &&
			    memcmp(mid_key, cur_salt->mitm, 5))
				continue;
			memcpy(hashBuf, mid_key, 5);
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
			if(!memcmp(pwdHash, hashBuf + 16, 16)) {
#ifdef _OPENMP
#pragma omp critical
#endif
				{
					any_cracked = cracked[index] = 1;
					cur_salt->has_mitm = 1;
					memcpy(cur_salt->mitm, mid_key, 5);
				}
			}
		}
		else {
			SHA_CTX ctx;
			unsigned char H0[24];
			unsigned char mid_key[20];
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
			SHA1_Final(mid_key, &ctx);
			// Early reject if we got a hint
			if (cur_salt->has_mitm &&
			    memcmp(mid_key, cur_salt->mitm, 5))
				continue;
			if(cur_salt->type < 4) {
				memcpy(Hfinal, mid_key, 5);
				memset(&Hfinal[5], 0, 11);
			} else
				memcpy(Hfinal, mid_key, 20);
			RC4_set_key(&key, 16, Hfinal); /* dek */
			RC4(&key, 16, cur_salt->verifier, DecryptedVerifier);
			RC4(&key, 20, cur_salt->verifierHash, DecryptedVerifierHash);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, DecryptedVerifier, 16);
			SHA1_Final(Hfinal, &ctx);
			if(!memcmp(Hfinal, DecryptedVerifierHash, 16)) {
#ifdef _OPENMP
#pragma omp critical
#endif
				{
					any_cracked = cracked[index] = 1;
					cur_salt->has_mitm = 1;
					memcpy(cur_salt->mitm, mid_key, 5);
				}
			}
		}
	}
	return count;
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

#if FMT_MAIN_VERSION > 11
static unsigned int oo_hash_type(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->type;
}
#endif

struct fmt_main fmt_oldoffice = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8 | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{
			"hash type",
		},
#endif
		oo_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			oo_hash_type,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
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

#endif /* plugin stanza */

/* KDE KWallet cracker patch for JtR. Written by Narendra Kangralkar
 * <narendrakangralkar at gmail.com> and Dhiru Kholia <dhiru at openwall.com>.
 *
 * Also see https://github.com/gaganpreet/kwallet-dump ;)
 *
 * This software is Copyright (c) 2013 by above authors and it is hereby
 * released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_kwallet;
#elif FMT_REGISTERS_H
john_register_one(&fmt_kwallet);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include <openssl/blowfish.h>
#include "sha.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               64
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"kwallet"
#define FORMAT_NAME		"KDE KWallet"
#define ALGORITHM_NAME		"SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		0
#define PLAINTEXT_LENGTH	125
#define SALT_SIZE		sizeof(*cur_salt)
#define BINARY_ALIGN		1
#define SALT_ALIGN			sizeof(int)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
// #define BENCH_LARGE_PASSWORDS   1

static struct fmt_tests kwallet_tests[] = {
	{"$kwallet$112$25be8c9cdaa53f5404d7809ff48a37752b325c8ccd296fbd537440dfcef9d66f72940e97141d21702b325c8ccd296fbd537440dfcef9d66fcd953cf1e41904b0c494ad1e718760e74c4487cc1449233d85525e7974da221774010bb9582b1d68b55ea9288f53a2be6bd15b93a5e1b33d", "openwall"},
	{"$kwallet$240$e5383800cf0ccabf76461a647bf7ed94b7260f0ac33374ea1fec0bb0144b7e3f8fa3d0f368a61075827ac60beb62be830ece6fb2f9cfb13561ed4372af19d0a720a37b0d21132a59513b3ab9030395671c9725d7d6592ad98a4754795c858c59df6049522384af98c77d5351ddc577da07ea10e7d44b3fbc9af737744f53ed0a0a67252599b66a4d1fc65926d7097dc50f45b57f41f11934e0cfc4d5491f82b43f38acde1fd337d51cf47eb5da1bcd8bff1432d7b02f0d316633b33ced337d202a44342fc79db6aea568fb322831d886d4cb6dcc50a3e17c1027550b9ee94f56bc33f9861d2b24cbb7797d79f967bea4", ""},
#ifdef BENCH_LARGE_PASSWORDS
	{"$kwallet$240$f17296588b2dd9f22f7c9ec43fddb5ee28db5edcb69575dcb887f5d2d0bfcc9317773c0f4e32517ace087d33ace8155a099e16c259c1a2f4f8992fc17481b122ef9f0c38c9eafd46794ff34e32c3ad83345f2d4e19ce727379856af9b774c00dca25a8528f5a2318af1fcbffdc6e73e7e081b106b4fbfe1887ea5bde782f9b3c3a2cfe3b215a65c66c03d053bfdee4d5d940e3e28f0c2d9897460fc1153af198b9037aac4dcd76e999c6d6a1f67f559e87349c6416cd7fc37b85ee230ef8caa2417b65732b61dbdb68fd2d12eb3df87474a05f337305c79427a970700a1b63f2018ba06f32e522bba4d30a0ec8ae223d", "pythonpythonpythonpythonpython"},
#endif
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned char ct[0x10000];
	unsigned int ctlen;
} *cur_salt;

static void init(struct fmt_main *self)
{

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int res;
	if (strncmp(ciphertext,  "$kwallet$", 9) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 9;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* ctlen */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (!res)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* ct */
		goto err;
	if (hexlenl(p) != res*2)
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
	static struct custom_salt *salt;
	char *keeptr = ctcopy;
	int i;
	char *p;
	ctcopy += 9;	/* skip over "$kwallet$" */
	if (!salt) salt = mem_calloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	memset(salt, 0, sizeof(*salt));
	p = strtokm(ctcopy, "$");
	salt->ctlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < salt->ctlen; i++)
		salt->ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)salt;
}

static void password2hash(const char *password, unsigned char *hash, int *key_size)
{
	SHA_CTX ctx;
	unsigned char output[20 * ((PLAINTEXT_LENGTH + 15) / 16)];
	unsigned char buf[20];
	int i, j, oindex = 0;
	int plength = strlen(password);

	// divide the password into blocks of size 16 and hash the resulting
	// individually!
	for (i = 0; i <= plength; i += 16) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, password + i, MIN(plength - i, 16));
		// To make brute force take longer
		for (j = 0; j < 2000; j++) {
			SHA1_Final(buf, &ctx);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, buf, 20);
		}
		memcpy(output + oindex, buf, 20);
		oindex += 20;
	}

	if (plength < 16) {
		// key size is 20
		memcpy(hash, output, 20);
		*key_size = 20;
	}
	else if (plength < 32) {
		// key size is 40 (20/20)
		memcpy(hash, output, 40);
		*key_size = 40;
	}
	else if (plength < 48) {
		// key size is 56 (20/20/16 split)
		memcpy(hash, output, 56);
		*key_size = 56;
	}
	else {
		// key size is 56 (14/14/14 split)
		memcpy(hash + 14 * 0, output +  0, 14);
		memcpy(hash + 14 * 1, output + 20, 14);
		memcpy(hash + 14 * 2, output + 40, 14);
		*key_size = 56;
	}
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int verify_passphrase(char *passphrase)
{
	unsigned char key[56]; /* 56 seems to be the max. key size */
	SHA_CTX ctx;
	BF_KEY bf_key;
	int sz;
	int i;
	int key_size = 0;
	unsigned char testhash[20];
	unsigned char buffer[0x10000]; // XXX respect the stack limits!
	const char *t;
	size_t fsize;
	password2hash(passphrase, key, &key_size);
	memcpy(buffer, cur_salt->ct, cur_salt->ctlen);

	/* Blowfish implementation in KWallet is wrong w.r.t endianness
	 * Well, that is why we had bad_blowfish_plug.c originally ;) */

	alter_endianity(buffer, cur_salt->ctlen);
	/* decryption stuff */
	BF_set_key(&bf_key, key_size, key);
	for(i = 0; i < cur_salt->ctlen; i += 8) {
		BF_ecb_encrypt(buffer + i, buffer + i, &bf_key, 0);
	}
	alter_endianity(buffer, cur_salt->ctlen);

	/* verification stuff */
	t = (char *) buffer;

	// strip the leading data
	t += 8;	// one block of random data

	// strip the file size off
	fsize = 0;
	fsize |= ((size_t) (*t) << 24) & 0xff000000;
	t++;
	fsize |= ((size_t) (*t) << 16) & 0x00ff0000;
	t++;
	fsize |= ((size_t) (*t) << 8) & 0x0000ff00;
	t++;
	fsize |= (size_t) (*t) & 0x000000ff;
	t++;
	if (fsize > (size_t) (cur_salt->ctlen) - 8 - 4) {
		// file structure error
		return -1;
	}
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, t, fsize);
	SHA1_Final(testhash, &ctx);
	// compare hashes
	sz = cur_salt->ctlen;
	for (i = 0; i < 20; i++) {
		if (testhash[i] != buffer[sz - 20 + i]) {
			return -2;
		}
	}
	return 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		int ret;
		ret = verify_passphrase(saved_key[index]);
		if(ret == 0)
			cracked[index] = 1;
		else
			cracked[index] = 0;
	}
	return count;
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

static void kwallet_set_key(char *key, int index)
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

struct fmt_main fmt_kwallet = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{ NULL },
		kwallet_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		kwallet_set_key,
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

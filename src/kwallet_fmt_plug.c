/* KDE KWallet cracker patch for JtR. Written by Narendra Kangralkar
 * <narendrakangralkar at gmail.com> and Dhiru Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 by above authors
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "bad_blowfish.h"
#include <openssl/sha.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"kwallet"
#define FORMAT_NAME		"KDE KWallet SHA-1"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		0
#define PLAINTEXT_LENGTH	125
#define SALT_SIZE		sizeof(*cur_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests kwallet_tests[] = {
	{"$kwallet$112$25be8c9cdaa53f5404d7809ff48a37752b325c8ccd296fbd537440dfcef9d66f72940e97141d21702b325c8ccd296fbd537440dfcef9d66fcd953cf1e41904b0c494ad1e718760e74c4487cc1449233d85525e7974da221774010bb9582b1d68b55ea9288f53a2be6bd15b93a5e1b33d", "openwall"},
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned char ct[0x10000];
	unsigned char ctlen;
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
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
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
	if ((p = strtok(ctcopy, "$")) == NULL)	/* ctlen */
		goto err;
	res = atoi(p);
	if ((p = strtok(NULL, "$")) == NULL)	/* ct */
		goto err;
	if(strlen(p) != res * 2)
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
	int i;
	char *p;
	ctcopy += 9;	/* skip over "$kwallet$*" */
	cur_salt = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	p = strtok(ctcopy, "$");
	cur_salt->ctlen = atoi(p);
	p = strtok(NULL, "$");
	for (i = 0; i < cur_salt->ctlen; i++)
		cur_salt->ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)cur_salt;
}
#define MIN(x,y) ((x) < (y) ? (x) : (y))
static int password2hash(const char *password, unsigned char *hash)
{
	SHA_CTX ctx;
	unsigned char block1[20] = { 0 };
	int i;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, password, MIN(strlen(password), 16));
	// To make brute force take longer
	for (i = 0; i < 2000; i++) {
		SHA1_Final(block1, &ctx);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, block1, 20);
	}
	memcpy(hash, block1, 20);

	/*if (password.size() > 16) {

	   sha.process(password.data() + 16, qMin(password.size() - 16, 16));
	   QByteArray block2(shasz, 0);
	   // To make brute force take longer
	   for (int i = 0; i < 2000; i++) {
	   memcpy(block2.data(), sha.hash(), shasz);
	   sha.reset();
	   sha.process(block2.data(), shasz);
	   }

	   sha.reset();

	   if (password.size() > 32) {
	   sha.process(password.data() + 32, qMin(password.size() - 32, 16));

	   QByteArray block3(shasz, 0);
	   // To make brute force take longer
	   for (int i = 0; i < 2000; i++) {
	   memcpy(block3.data(), sha.hash(), shasz);
	   sha.reset();
	   sha.process(block3.data(), shasz);
	   }

	   sha.reset();

	   if (password.size() > 48) {
	   sha.process(password.data() + 48, password.size() - 48);

	   QByteArray block4(shasz, 0);
	   // To make brute force take longer
	   for (int i = 0; i < 2000; i++) {
	   memcpy(block4.data(), sha.hash(), shasz);
	   sha.reset();
	   sha.process(block4.data(), shasz);
	   }

	   sha.reset();
	   // split 14/14/14/14
	   hash.resize(56);
	   memcpy(hash.data(),      block1.data(), 14);
	   memcpy(hash.data() + 14, block2.data(), 14);
	   memcpy(hash.data() + 28, block3.data(), 14);
	   memcpy(hash.data() + 42, block4.data(), 14);
	   block4.fill(0);
	   } else {
	   // split 20/20/16
	   hash.resize(56);
	   memcpy(hash.data(),      block1.data(), 20);
	   memcpy(hash.data() + 20, block2.data(), 20);
	   memcpy(hash.data() + 40, block3.data(), 16);
	   }
	   block3.fill(0);
	   } else {
	   // split 20/20
	   hash.resize(40);
	   memcpy(hash.data(),      block1.data(), 20);
	   memcpy(hash.data() + 20, block2.data(), 20);
	   }
	   block2.fill(0);
	   } else {
	   // entirely block1
	   hash.resize(20);
	   memcpy(hash.data(), block1.data(), 20);
	   }

	   block1.fill(0); */
	return 0;
}



static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int verify_passphrase(char *passphrase)
{
	unsigned char key[20];
	SHA_CTX ctx;
	BlowFish _bf;
	int sz;
	int i;
	unsigned char testhash[20];
	unsigned char buffer[0x10000];
	const char *t;
	long fsize;
	CipherBlockChain bf;
	password2hash(passphrase, key);
	CipherBlockChain_constructor(&bf, &_bf);
	CipherBlockChain_setKey(&bf, (void *) key, 20 * 8);
	memcpy(buffer, cur_salt->ct, cur_salt->ctlen);
	CipherBlockChain_decrypt(&bf, buffer, cur_salt->ctlen);

	t = (char *) buffer;

	// strip the leading data
	t += 8;	// one block of random data

	// strip the file size off
	fsize = 0;
	fsize |= ((long) (*t) << 24) & 0xff000000;
	t++;
	fsize |= ((long) (*t) << 16) & 0x00ff0000;
	t++;
	fsize |= ((long) (*t) << 8) & 0x0000ff00;
	t++;
	fsize |= (long) (*t) & 0x000000ff;
	t++;
	if (fsize < 0 || fsize > (long) (cur_salt->ctlen) - 8 - 4) {
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


static void crypt_all(int count)
{
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

struct fmt_main fmt_kwallet = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		kwallet_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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

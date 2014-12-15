/* LastPass sniffed session cracker patch for JtR. Hacked together during
 * November of 2012 by Dhiru Kholia <dhiru at openwall.com>.
 *
 * Burp Suite is awesome. Open-source it!
 *
 * This software is Copyright (c) 2012 Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sniffed_lastpass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sniffed_lastpass);
#else

#include <string.h>
#include <errno.h>
#include "arch.h"
#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#include <openssl/aes.h>
#include "pbkdf2_hmac_sha256.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"LastPass"
#define FORMAT_NAME		"sniffed sessions"
#ifdef MMX_COEF_SHA256
#define ALGORITHM_NAME		"PBKDF2-SHA256 AES " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME		"PBKDF2-SHA256 AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	15
#define BINARY_SIZE		0
#define SALT_SIZE		sizeof(struct custom_salt)
#define BINARY_ALIGN		1
#define SALT_ALIGN			sizeof(int)
#ifdef MMX_COEF_SHA256
#define MIN_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA256
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

#define SALTLEN 8
#define IVLEN 8
#define CTLEN 1040

/* sentms=1352643586902&xml=2&username=hackme%40mailinator.com&method=cr&hash=4c11d8717015d92db74c42bc1a2570abea3fa18ab17e58a51ce885ee217ccc3f&version=2.0.15&encrypted_username=i%2BhJCwPOj5eQN4tvHcMguoejx4VEmiqzOXOdWIsZKlk%3D&uuid=aHnPh8%40NdhSTWZ%40GJ2fEZe%24cF%40kdzdYh&lang=en-US&iterations=500&sessonly=0&otp=&sesameotp=&multifactorresponse=&lostpwotphash=07a286341be484fc3b96c176e611b10f4d74f230c516f944a008f960f4ec8870&requesthash=i%2BhJCwPOj5eQN4tvHcMguoejx4VEmiqzOXOdWIsZKlk%3D&requestsrc=cr&encuser=i%2BhJCwPOj5eQN4tvHcMguoejx4VEmiqzOXOdWIsZKlk%3D&hasplugin=2.0.15
 * decodeURIComponent("hackme%40mailinator.com")
 * decodeURIComponent("i%2BhJCwPOj5eQN4tvHcMguoejx4VEmiqzOXOdWIsZKlk%3D") */

/* C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\Extensions\hdokiejnpimakedhajhdlcegeplioahd\2.0.15_0
 * lpfulllib.js and server.js are main files involved */

static struct fmt_tests lastpass_tests[] = {
	{"$lastpass$hackme@mailinator.com$500$i+hJCwPOj5eQN4tvHcMguoejx4VEmiqzOXOdWIsZKlk=", "openwall"},
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned int iterations;
	char username[129];
	unsigned char encrypted_username[40];
	unsigned char length;
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

static int isdec(char *q)
{
	char buf[24];
	int x = atoi(q);
	sprintf(buf, "%d", x);
	return !strcmp(q,buf) && *q != '-';
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	if (strncmp(ciphertext, "$lastpass$", 10) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 10;
	if ((p = strtok(ctcopy, "$")) == NULL)	/* username */
		goto err;
	if (strlen(p) > 129)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* data */
		goto err;
	if (strlen(p) > 50) /* not exact! */
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
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += 10;	/* skip over "$lastpass$" */
	p = strtok(ctcopy, "$");
	i = strlen(p);
	if (i > 16)
		i = 16;
	cs.length = i; /* truncated length */
	strncpy(cs.username, p, 128);
	p = strtok(NULL, "$");
	cs.iterations = atoi(p);
	p = strtok(NULL, "$");
	base64_decode(p, strlen(p), (char*)cs.encrypted_username);

	MEM_FREE(keeptr);
	return (void *)&cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		unsigned char out[32];
		unsigned char iv[16];
		AES_KEY akey;
#ifdef MMX_COEF_SHA256
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
		pbkdf2_sha256_sse((const unsigned char **)pin, lens, (unsigned char*)cur_salt->username, strlen((char*)cur_salt->username), cur_salt->iterations, &(x.poutc), 32, 0);

		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			unsigned char *Key = (unsigned char*)key[i];
			memset(iv, 0, sizeof(iv));
			if(AES_set_decrypt_key(Key, 256, &akey) < 0) {
				fprintf(stderr, "AES_set_decrypt_key failed in crypt!\n");
			}
			AES_cbc_encrypt(cur_salt->encrypted_username, out, 32, &akey, iv, AES_DECRYPT);
			if(strncmp((const char*)out, cur_salt->username, cur_salt->length) == 0)
				cracked[i+index] = 1;
			else
				cracked[i+index] = 0;
		}
#else
		ARCH_WORD_32 key[8];
		// PKCS5_PBKDF2_HMAC(saved_key[index], strlen(saved_key[index]), (unsigned char*)cur_salt->username, strlen((char*)cur_salt->username), cur_salt->iterations, EVP_sha256(), 32, key);
		pbkdf2_sha256((unsigned char*)saved_key[index], strlen(saved_key[index]), (unsigned char*)cur_salt->username, strlen((char*)cur_salt->username), cur_salt->iterations, (unsigned char*)key,32,0);
		//pbkdf2_sha256_x((unsigned char*)saved_key[index], strlen(saved_key[index]), (unsigned char*)cur_salt->username, strlen((char*)cur_salt->username), cur_salt->iterations, (unsigned char*)key);

#if !ARCH_LITTLE_ENDIAN
		{
			int i;
			for (i = 0; i < 8; ++i) {
				key[i] = JOHNSWAP(key[i]);
			}
		}
#endif

		if(AES_set_decrypt_key((const unsigned char *)key, 256, &akey) < 0) {
			fprintf(stderr, "AES_set_decrypt_key failed in crypt!\n");
		}
		memset(iv, 0, sizeof(iv));
		AES_cbc_encrypt(cur_salt->encrypted_username, out, 32, &akey, iv, AES_DECRYPT);

		if(strncmp((const char*)out, cur_salt->username, cur_salt->length) == 0)
			cracked[index] = 1;
		else
			cracked[index] = 0;
#endif
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

static void lastpass_set_key(char *key, int index)
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

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->iterations;
}
#endif

struct fmt_main fmt_sniffed_lastpass = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
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
		lastpass_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		lastpass_set_key,
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

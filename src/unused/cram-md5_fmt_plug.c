/* Cracker for CRAM-MD5 challenge-response authentication mechanism.
 * Hacked together during November of 2012 by Dhiru Kholia <dhiru at openwall.com>.
 *
 * See http://susam.in/blog/auth-cram-md5/ and
 *
 * http://www.openwall.com/lists/john-users/2010/07/27/1
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#if FMT_EXTERNS_H
extern struct fmt_main cram_md5_fmt;
#elif FMT_REGISTERS_H
john_register_one(&cram_md5_fmt);
#else

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>

#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"cram_md5"
#define FORMAT_NAME		"CRAM-MD5"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_LENGTH		256
#define USER_LENGTH		256
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests cram_md5_tests[] = {

	/* Challenge ==> PDE3ODkzLjEzMjA2NzkxMjNAdGVzc2VyYWN0LnN1c2FtLmluPg==
	 * Response ==> YWxpY2UgNjRiMmE0M2MxZjZlZDY4MDZhOTgwOTE0ZTIzZTc1ZjA= */
	{"$cram_md5$PDE3ODkzLjEzMjA2NzkxMjNAdGVzc2VyYWN0LnN1c2FtLmluPg==$YWxpY2UgNjRiMmE0M2MxZjZlZDY4MDZhOTgwOTE0ZTIzZTc1ZjA=", "wonderland"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	unsigned char salt[SALT_LENGTH];
	int saltlen;
	unsigned char username[USER_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void base64_decode_good(char *input, char *output)
{
	BIO *out_buffer, *buffer;
	int length = strlen(input);

	/* dirty hack */
	input[length] = '\n';
	input[length + 1] = 0;
	length += 1;

	out_buffer = BIO_new(BIO_f_base64());
	buffer = BIO_new_mem_buf(input, length);
	buffer = BIO_push(out_buffer, buffer);

	BIO_read(buffer, output, length);

	BIO_free_all(buffer);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, "$cram_md5$", 10) != 0)
		return 0;
	return 1;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char pinput[SALT_LENGTH] = { 0 };
	char *p;
	static struct custom_salt cs;

	memset(cs.salt, 0, SALT_LENGTH);

	ctcopy += 10;

	p = strtok(ctcopy, "$");
	strncpy(pinput, p, SALT_LENGTH);
	base64_decode_good(pinput, (char*)cs.salt);
	cs.saltlen = strlen((char*)cs.salt);

	p = strtok(NULL, "$");
	strncpy(pinput, p, SALT_LENGTH);
	base64_decode_good(pinput, (char*)cs.username);
	p = strrchr((char*)cs.username, ' '); /* find username - hash delimiter */
	*p = 0;

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char pinput[256] = { 0 };
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	strncpy(pinput, p, SALT_LENGTH);
	base64_decode_good(pinput, (char*)out);
	p = strrchr((char*)out, ' ') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

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
#endif
	for (index = 0; index < count; index++)
	{
		unsigned char *result;
		result = HMAC(EVP_md5(), saved_key[index], strlen(saved_key[index]), cur_salt->salt, cur_salt->saltlen, NULL, NULL);
		memcpy(crypt_out[index], result, 16);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
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

static void cram_md5_set_key(char *key, int index)
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

struct fmt_main cram_md5_fmt = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		cram_md5_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
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
		fmt_default_salt_hash,
		set_salt,
		cram_md5_set_key,
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

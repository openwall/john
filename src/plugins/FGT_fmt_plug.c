/*
 * Fortigate (FortiOS) Password cracker
 *
 * This software is Copyright (c) 2012 Mat G. <mat.jtr at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Passwords are located in "config system admin" part of the configuration file :
 *
 * config system admin
 *     edit "<username>"
 *        set password ENC AK1wTiFOMv7mZOTvQNmKQBAY98hZZjSRLxAY8vZp8NlDWU=
 *
 * Password is : AK1|base64encode(salt|hashed_password)
 * where hashed_password is SHA1(salt|password|fortinet_magic)
 *
 * salt is 12 bytes long
 * hashed_password is 20 bytes long (SHA1 salt)
 * encoded password is 47 bytes long (3 bytes for AK1 and 44 bytes of base64encode(salt|hashed_password))
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_FGT;
#elif FMT_REGISTERS_H
john_register_one(&fmt_FGT);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "common.h"
#include "formats.h"
#include "misc.h"
#include "sha.h"
#include "base64_convert.h"

#define FORMAT_LABEL		"Fortigate"
#define FORMAT_NAME             "FortiOS"
#define ALGORITHM_NAME		"SHA1 32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	7

#define PLAINTEXT_LENGTH	32
#define CIPHERTEXT_LENGTH	44
#define HASH_LENGTH             CIPHERTEXT_LENGTH + 3

#define BINARY_SIZE             20
#define BINARY_ALIGN		4
#define SALT_SIZE               12
#define SALT_ALIGN		4

#define FORTINET_MAGIC          "\xa3\x88\xba\x2e\x42\x4c\xb0\x4a\x53\x79\x30\xc1\x31\x07\xcc\x3f\xa1\x32\x90\x29\xa9\x81\x5b\x70"
#define FORTINET_MAGIC_LENGTH   24

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		512

#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE               16
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif
#endif // __MIC__

static struct fmt_tests fgt_tests[] =
{
	{"AK1wTiFOMv7mZOTvQNmKQBAY98hZZjSRLxAY8vZp8NlDWU=", "fortigate"},
	{"AK1Vd1SCGVtAAT931II/U22WTppAISQkITHOlz0ukIg4nA=", "admin"},
	{"AK1DZLDpqz335ElPtuiNTpguiozY7xVaHjHYnxw6sNlI6A=", "ftnt"},
	{NULL}
};

static SHA_CTX ctx_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int (*saved_key_len);
static uint32_t (*crypt_key)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
	saved_key_len = mem_calloc(self->params.max_keys_per_crypt,
	                           sizeof(*saved_key_len));
}

static void done(void)
{
	MEM_FREE(saved_key_len);
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, "AK1", 3))
		return 0;
	if (strlen(ciphertext) != HASH_LENGTH)
		return 0;
	if (ciphertext[HASH_LENGTH - 1] != '=')
		return 0;

	return 1;
}

static void * get_salt(char *ciphertext)
{
	static union {
		char b[SALT_SIZE];
		uint32_t dummy;
	} out;
	char buf[SALT_SIZE+BINARY_SIZE+1];

	base64_convert(ciphertext+3, e_b64_mime, CIPHERTEXT_LENGTH, buf, e_b64_raw, sizeof(buf), flg_Base64_NO_FLAGS, 0);

	memcpy(out.b, buf, SALT_SIZE);

	return out.b;
}

static void set_salt(void *salt)
{
	SHA1_Init(&ctx_salt);
	SHA1_Update(&ctx_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	saved_key_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char * get_key(int index)
{
	return saved_key[index];
}

static void * get_binary(char *ciphertext)
{
	static union {
		char b[BINARY_SIZE];
		uint32_t dummy;
	} bin;
	char buf[SALT_SIZE+BINARY_SIZE+1];

	memset(buf, 0, sizeof(buf));
	base64_convert(ciphertext+3, e_b64_mime, CIPHERTEXT_LENGTH, buf, e_b64_raw, sizeof(buf), flg_Base64_NO_FLAGS, 0);

	// skip over the 12 bytes of salt and get only the hashed password
	memcpy(bin.b, buf+SALT_SIZE, BINARY_SIZE);

	return bin.b;
}


static int cmp_all(void *binary, int count)
{
	uint32_t b0 = *(uint32_t *)binary;
	int i;

	for (i = 0; i < count; i++) {
		if (b0 != *(uint32_t *)crypt_key[i])
			continue;
		if (!memcmp(binary, crypt_key[i], BINARY_SIZE))
			return 1;
	}
	return 0;


}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i=0;
	char *cp=FORTINET_MAGIC;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(ctx_salt, count, saved_key, saved_key_len, crypt_key, cp)
#endif
	for (i = 0; i < count; i++) {
		SHA_CTX ctx;

		memcpy(&ctx, &ctx_salt, sizeof(ctx));

		SHA1_Update(&ctx, saved_key[i], saved_key_len[i]);
		SHA1_Update(&ctx, cp, FORTINET_MAGIC_LENGTH);
		SHA1_Final((unsigned char*)crypt_key[i], &ctx);
	}
	return count;
}


#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	uint32_t mysalt = *(uint32_t *)salt;
	return mysalt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_FGT = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP ,
		{ NULL },
		{ NULL },
		fgt_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
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
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

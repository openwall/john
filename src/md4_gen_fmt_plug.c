/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "md4.h"

#define FORMAT_LABEL			"md4-gen"
#define FORMAT_NAME			"Generic salted MD4"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16
#define SALT_SIZE			64 /* length + type + 62 chars */

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"$MD4p$salt$15ad2b7a23e5088942f9d3772181b384", "password"},
	{"$MD4s$salt$fb483dbef17c51c13e2322fcbec5da79", "password"},
	{NULL}
};

static char saved_salt[SALT_SIZE];
static int saved_key_length;
static char saved_key[PLAINTEXT_LENGTH + 1];
static MD4_CTX ctx;
static ARCH_WORD_32 crypt_out[4];

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *p, *q;

	if (strncmp(ciphertext, "$MD4", 4) ||
	    (ciphertext[4] != 'p' && ciphertext[4] != 's') ||
	    ciphertext[5] != '$')
		return 0;

	p = strrchr(ciphertext, '$');
	if (!p || /* can't happen */
	    p - ciphertext < 6 || /* must not be the 1st or 2nd '$' */
	    p - ciphertext > 6 + SALT_SIZE - 2)
		return 0;

	q = ++p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[BINARY_SIZE];
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < sizeof(out); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void *salt(char *ciphertext)
{
	static unsigned char out[SALT_SIZE];
	char *p;
	int length;

	memset(out, 0, sizeof(out));
	p = ciphertext + 6;
	length = strrchr(ciphertext, '$') - p;
	out[0] = length;
	out[1] = ciphertext[4];
	memcpy(out + 2, p, length);

	return out;
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
	return crypt_out[0] & 0xF;
}

static int get_hash_1(int index)
{
	return crypt_out[0] & 0xFF;
}

static int get_hash_2(int index)
{
	return crypt_out[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return crypt_out[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return crypt_out[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	return crypt_out[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return crypt_out[0] & 0x7FFFFFF;
}

static int salt_hash(void *salt)
{
	unsigned int hash = 0;
	char *p = (char *)salt;

	while (*p) {
		hash <<= 1;
		hash += (unsigned char)*p++;
		if (hash >> SALT_HASH_LOG) {
			hash ^= hash >> SALT_HASH_LOG;
			hash &= (SALT_HASH_SIZE - 1);
		}
	}

	hash ^= hash >> SALT_HASH_LOG;
	hash &= (SALT_HASH_SIZE - 1);

	return hash;
}

static void set_salt(void *salt)
{
	memcpy(saved_salt, salt, *(unsigned char *)salt + 2);
}

static void set_key(char *key, int index)
{
	saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);
}

static char *get_key(int index)
{
	saved_key[saved_key_length] = 0;
	return saved_key;
}

static void crypt_all(int count)
{
	MD4_Init(&ctx);
	if (saved_salt[1] == 'p') {
		MD4_Update(&ctx, &saved_salt[2], (unsigned char)saved_salt[0]);
		MD4_Update(&ctx, saved_key, saved_key_length);
	} else {
		MD4_Update(&ctx, saved_key, saved_key_length);
		MD4_Update(&ctx, &saved_salt[2], (unsigned char)saved_salt[0]);
	}
	MD4_Final((unsigned char *)crypt_out, &ctx);
}

static int cmp_all(void *binary, int count)
{
	return !memcmp(binary, crypt_out, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_md4_gen = {
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
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		set_salt,
		set_key,
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
		cmp_all,
		cmp_exact,
		fmt_default_get_source
	}
};

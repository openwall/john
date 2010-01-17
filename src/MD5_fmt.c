/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2008,2010 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "MD5_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"md5"
#define FORMAT_NAME			"FreeBSD MD5"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		15
#define CIPHERTEXT_LENGTH		22

#define BINARY_SIZE			4
#define SALT_SIZE			8

#define MIN_KEYS_PER_CRYPT		MD5_N
#define MAX_KEYS_PER_CRYPT		MD5_N

static struct fmt_tests tests[] = {
	{"$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
	{"$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
	{"$1$12345678$xek.CpjQUVgdf/P2N9KQf/", ""},
	{"$1$1234$BdIMOAWFOV2AQlLsrN/Sw.", "1234"},
	{NULL}
};

static char saved_key[MD5_N][PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext)
{
	char *pos, *start;

	if (strncmp(ciphertext, "$1$", 3)) return 0;

	for (pos = &ciphertext[3]; *pos && *pos != '$'; pos++);
	if (!*pos || pos < &ciphertext[3] || pos > &ciphertext[11]) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 0x3C) return 0;

	return 1;
}

static int binary_hash_0(void *binary)
{
	return *(MD5_word *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(MD5_word *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(MD5_word *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(MD5_word *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(MD5_word *)binary & 0xFFFFF;
}

static int get_hash_0(int index)
{
	return MD5_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
	return MD5_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
	return MD5_out[index][0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return MD5_out[index][0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return MD5_out[index][0] & 0xFFFFF;
}

static int salt_hash(void *salt)
{
	return
		((int)atoi64[ARCH_INDEX(((char *)salt)[0])] |
		((int)atoi64[ARCH_INDEX(((char *)salt)[1])] << 6)) & 0x3FF;
}

static void set_key(char *key, int index)
{
	MD5_std_set_key(key, index);

	strnfcpy(saved_key[index], key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	saved_key[index][PLAINTEXT_LENGTH] = 0;

	return saved_key[index];
}

static int cmp_all(void *binary, int count)
{
#if MD5_X2
	return *(MD5_word *)binary == MD5_out[0][0] ||
		*(MD5_word *)binary == MD5_out[1][0];
#else
	return *(MD5_word *)binary == MD5_out[0][0];
#endif
}

static int cmp_one(void *binary, int index)
{
	return *(MD5_word *)binary == MD5_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	return !memcmp(MD5_std_get_binary(source), MD5_out[index],
	    sizeof(MD5_binary));
}

struct fmt_main fmt_MD5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		MD5_ALGORITHM_NAME,
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
		MD5_std_init,
		valid,
		fmt_default_split,
		(void *(*)(char *))MD5_std_get_binary,
		(void *(*)(char *))MD5_std_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		(void (*)(void *))MD5_std_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		(void (*)(int))MD5_std_crypt,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

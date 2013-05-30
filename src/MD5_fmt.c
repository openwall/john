/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2008,2010-2012 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "MD5_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"md5crypt"
#define FORMAT_NAME			""

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		15
#define CIPHERTEXT_LENGTH		22

#define BINARY_SIZE			4
#define BINARY_ALIGN			4
#define SALT_SIZE			9
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		MD5_N
#define MAX_KEYS_PER_CRYPT		MD5_N

static struct fmt_tests tests[] = {
	{"$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
	{"$apr1$Q6ZYh...$RV6ft2bZ8j.NGrxLYaJt9.", "test"},
	{"$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
	{"$1$$qRPK7m23GJusamGpoGLby/", ""},
	{"$apr1$a2Jqm...$grFrwEgiQleDr0zR4Jx1b.", "15 chars is max"},
	{"$1$$AuJCr07mI7DSew03TmBIv/", "no salt"},
	{"$1$`!@#%^&*$E6hD76/pKTS8qToBCkux30", "invalid salt"},
	{"$1$12345678$xek.CpjQUVgdf/P2N9KQf/", ""},
	{"$1$1234$BdIMOAWFOV2AQlLsrN/Sw.", "1234"},
	{"$apr1$rBXqc...$NlXxN9myBOk95T0AyLAsJ0", "john"},
	{"$apr1$Grpld/..$qp5GyjwM2dnA5Cdej9b411", "the"},
	{"$apr1$GBx.D/..$yfVeeYFCIiEXInfRhBRpy/", "ripper"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];

struct fmt_main fmt_MD5;

static void init(struct fmt_main *self)
{
	MD5_std_init();

#if MD5_std_mt
	fmt_MD5.params.min_keys_per_crypt = MD5_std_min_kpc;
	fmt_MD5.params.max_keys_per_crypt = MD5_std_max_kpc;
#endif

	saved_key = mem_alloc_tiny(
	    sizeof(*saved_key) * fmt_MD5.params.max_keys_per_crypt,
	    MEM_ALIGN_CACHE);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos, *start;

	if (strncmp(ciphertext, "$1$", 3)) {
		if (strncmp(ciphertext, "$apr1$", 6))
			return 0;
		ciphertext += 3;
	}

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

static int binary_hash_5(void *binary)
{
	return *(MD5_word *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(MD5_word *)binary & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
	init_t();
	return MD5_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
	init_t();
	return MD5_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
	init_t();
	return MD5_out[index][0] & 0xFFF;
}

static int get_hash_3(int index)
{
	init_t();
	return MD5_out[index][0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	init_t();
	return MD5_out[index][0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	init_t();
	return MD5_out[index][0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	init_t();
	return MD5_out[index][0] & 0x7FFFFFF;
}

static int salt_hash(void *salt)
{
	unsigned int i, h, retval;

	retval = 0;
	for (i = 0; i <= 6; i += 2) {
		h = (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i])];
		h ^= ((unsigned char *)salt)[i + 1];
		h <<= 6;
		h ^= (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i + 1])];
		h ^= ((unsigned char *)salt)[i];
		retval += h;
	}

	retval ^= retval >> SALT_HASH_LOG;
	retval &= SALT_HASH_SIZE - 1;

	return retval;
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	MD5_std_crypt(count);
	return count;
}

static int cmp_all(void *binary, int count)
{
#if MD5_std_mt
	int t, n = (count + (MD5_N - 1)) / MD5_N;
#endif
	for_each_t(n) {
#if MD5_X2
		if (*(MD5_word *)binary == MD5_out[0][0] ||
		    *(MD5_word *)binary == MD5_out[1][0])
			return 1;
#else
		if (*(MD5_word *)binary == MD5_out[0][0])
			return 1;
#endif
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	init_t();
	return *(MD5_word *)binary == MD5_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	init_t();
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
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#if MD5_std_mt
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		(void *(*)(char *))MD5_std_get_binary,
		(void *(*)(char *))MD5_std_get_salt,
		fmt_default_source,
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
		(void (*)(void *))MD5_std_set_salt,
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
		cmp_one,
		cmp_exact
	}
};

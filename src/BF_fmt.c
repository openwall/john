/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2008,2010-2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "BF_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"bcrypt"
#define FORMAT_NAME			""

#define BENCHMARK_COMMENT		" (\"$2a$05\", 32 iterations)"
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		72
#define CIPHERTEXT_LENGTH		60

#define BINARY_SIZE			4
#define BINARY_ALIGN			4
#define SALT_SIZE			sizeof(BF_salt)
#define SALT_ALIGN			4

#define MIN_KEYS_PER_CRYPT		BF_Nmin
#define MAX_KEYS_PER_CRYPT		BF_N

static struct fmt_tests tests[] = {
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
		"U*U"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
		"U*U*"},
	{"$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
		"U*U*U"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
		""},
	{"$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
		"0123456789abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		"chars after 72 are ignored"},
	{"$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
		"\xa3"},
	{"$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
		"\xa3"},
	{"$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS",
		"\xd1\x91"},
	{"$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS",
		"\xd0\xc1\xd2\xcf\xcc\xd8"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6",
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"chars after 72 are ignored as usual"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy",
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
		""},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe",
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"},
	{NULL}
};

static char saved_key[BF_N][PLAINTEXT_LENGTH + 1];
static char keys_mode;
static int sign_extension_bug;
static BF_salt saved_salt;

#ifdef _OPENMP
#include <omp.h>

struct fmt_main fmt_BF;
#endif

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int n = BF_Nmin * omp_get_max_threads(), max;
	if (n < BF_Nmin)
		n = BF_Nmin;
	if (n > BF_N)
		n = BF_N;
	fmt_BF.params.min_keys_per_crypt = n;
	max = n * BF_cpt;
	while (max > BF_N)
		max -= n;
	fmt_BF.params.max_keys_per_crypt = max;
#endif

	keys_mode = 'y';
	sign_extension_bug = 0;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int rounds;
	char *pos;

	if (strncmp(ciphertext, "$2a$", 4) &&
	    strncmp(ciphertext, "$2x$", 4) &&
	    strncmp(ciphertext, "$2y$", 4))
		return 0;

	if (ciphertext[4] < '0' || ciphertext[4] > '9') return 0;
	if (ciphertext[5] < '0' || ciphertext[5] > '9') return 0;
	if (ciphertext[6] != '$') return 0;
	rounds = atoi(ciphertext + 4);
	if (rounds < 4 || rounds > 31) return 0;

	for (pos = &ciphertext[7]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos || pos - ciphertext != CIPHERTEXT_LENGTH) return 0;

	if (BF_atoi64[ARCH_INDEX(*(pos - 1))] & 3) return 0;
	if (BF_atoi64[ARCH_INDEX(ciphertext[28])] & 0xF) return 0;

	return 1;
}

static int binary_hash_0(void *binary)
{
	return *(BF_word *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(BF_word *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(BF_word *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(BF_word *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(BF_word *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(BF_word *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(BF_word *)binary & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
	return BF_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
	return BF_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
	return BF_out[index][0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return BF_out[index][0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return BF_out[index][0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	return BF_out[index][0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return BF_out[index][0] & 0x7FFFFFF;
}

static int salt_hash(void *salt)
{
	return ((BF_salt *)salt)->salt[0] & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	memcpy(&saved_salt, salt, sizeof(saved_salt));
}

static void set_key(char *key, int index)
{
	BF_std_set_key(key, index, sign_extension_bug);

	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	if (keys_mode != saved_salt.subtype) {
		int i;

		keys_mode = saved_salt.subtype;
		sign_extension_bug = (keys_mode == 'x');
		for (i = 0; i < count; i++)
			BF_std_set_key(saved_key[i], i, sign_extension_bug);
	}

	BF_std_crypt(&saved_salt, count);

	return count;
}

static int cmp_all(void *binary, int count)
{
#if BF_N > 2
	int i;
	for (i = 0; i < count; i++)
		if (*(BF_word *)binary == BF_out[i][0])
			return 1;
	return 0;
#elif BF_N == 2
	return
	    *(BF_word *)binary == BF_out[0][0] ||
	    *(BF_word *)binary == BF_out[1][0];
#else
	return *(BF_word *)binary == BF_out[0][0];
#endif
}

static int cmp_one(void *binary, int index)
{
	return *(BF_word *)binary == BF_out[index][0];
}

static int cmp_exact(char *source, int index)
{
#if BF_mt == 1
	BF_std_crypt_exact(index);
#endif

	return !memcmp(BF_std_get_binary(source), BF_out[index],
	    sizeof(BF_binary));
}

struct fmt_main fmt_BF = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		BF_ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#if BF_mt > 1
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
		BF_std_get_binary,
		BF_std_get_salt,
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
		cmp_one,
		cmp_exact
	}
};

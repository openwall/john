/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2011,2012 by Solar Designer
 * Copyright (c) 2015 by magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * NOTE: Due to core limitations this format can not crack a plaintext
 * containing ':' or that has trailing whitespace.
 *
 * Example hash generation:
 *
 * Without usernames:
 * perl -ne 'print "\$0\$$_" if m/^[^:]{0,124}[^:\s]$/' < in > out
 *
 * With usernames:
 * perl -ne 'chomp; print "$_:\$0\$$_\n" if m/^[^:]{0,124}[^:\s]$/' < in > out
 *
 */

#define FMT_STRUCT	fmt_zzz_plaintext

#if FMT_EXTERNS_H
extern struct fmt_main FMT_STRUCT;
#elif FMT_REGISTERS_H
john_register_one(&FMT_STRUCT);
#else

#include <string.h>

#include "common.h"
#include "formats.h"
#include "options.h"

#define FORMAT_LABEL			"plaintext"
#define FORMAT_TAG			"$0$"
#define FORMAT_TAG_LEN			(sizeof(FORMAT_TAG) - 1)
#define FORMAT_NAME			"$0$"
#define ALGORITHM_NAME			"n/a"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_MIN_LENGTH		0
/* Max 125, but 95 typically produces fewer L1 data cache tag collisions */
#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		(PLAINTEXT_LENGTH + FORMAT_TAG_LEN)

typedef struct {
	uint32_t hash;
	char c0;
} plaintext_binary;

#define BINARY_SIZE			sizeof(plaintext_binary)
#define BINARY_ALIGN			sizeof(uint32_t)
#define SALT_SIZE			0
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		(0x4000 / (PLAINTEXT_LENGTH + 1))

static struct fmt_tests tests[] = {
	{"$0$cleartext", "cleartext"},
	{FORMAT_TAG, ""},
	{"$0$magnum", "magnum"},
	{"$0$ spa  ce", " spa  ce"},
	{"$0$password", "password"},
	{NULL}
};

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext, struct fmt_main *self)
{
	int len;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ciphertext += FORMAT_TAG_LEN;

	len = strlen(ciphertext);

	if (len < PLAINTEXT_MIN_LENGTH || len > PLAINTEXT_LENGTH)
		return 0;

	return 1;
}

static MAYBE_INLINE uint32_t string_hash(char *s)
{
	uint32_t hash, extra;
	char *p;

	p = s + 2;
	hash = (unsigned char)s[0];
	if (!hash)
		goto out;
	extra = (unsigned char)s[1];
	if (!extra)
		goto out;

	while (*p) {
		hash <<= 5;
		hash += (unsigned char)p[0];
		if (!p[1]) break;
		extra *= hash | 1812433253;
		extra += (unsigned char)p[1];
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> 20;
			extra ^= extra >> 20;
			hash &= 0xfffff;
		}
	}

	hash -= extra;
	hash ^= extra << 10;

	hash ^= hash >> 16;

out:
	return hash;
}

static void *get_binary(char *ciphertext)
{
	static plaintext_binary out;

	ciphertext += FORMAT_TAG_LEN;
	memset(&out, 0, sizeof(out));
	out.hash = string_hash(ciphertext);
	out.c0 = ciphertext[0];

	return &out;
}

static int binary_hash_0(void *binary)
{
	uint32_t hash = ((plaintext_binary *)binary)->hash;
	hash ^= hash >> 8;
	return (hash ^ (hash >> 4)) & PH_MASK_0;
}

static int binary_hash_1(void *binary)
{
	uint32_t hash = ((plaintext_binary *)binary)->hash;
	return (hash ^ (hash >> 8)) & PH_MASK_1;
}

static int binary_hash_2(void *binary)
{
	uint32_t hash = ((plaintext_binary *)binary)->hash;
	return (hash ^ (hash >> 12)) & PH_MASK_2;
}

static int binary_hash_3(void *binary)
{
	return ((plaintext_binary *)binary)->hash & PH_MASK_3;
}

static int binary_hash_4(void *binary)
{
	return ((plaintext_binary *)binary)->hash & PH_MASK_4;
}

static int binary_hash_5(void *binary)
{
	return ((plaintext_binary *)binary)->hash & PH_MASK_5;
}

static int binary_hash_6(void *binary)
{
	return ((plaintext_binary *)binary)->hash & PH_MASK_6;
}

static int get_hash_0(int index)
{
	uint32_t hash = string_hash(saved_key[index]);
	hash ^= hash >> 8;
	return (hash ^ (hash >> 4)) & PH_MASK_0;
}

static int get_hash_1(int index)
{
	uint32_t hash = string_hash(saved_key[index]);
	return (hash ^ (hash >> 8)) & PH_MASK_1;
}

static int get_hash_2(int index)
{
	uint32_t hash = string_hash(saved_key[index]);
	return (hash ^ (hash >> 12)) & PH_MASK_2;
}

static int get_hash_3(int index)
{
	return string_hash(saved_key[index]) & PH_MASK_3;
}

static int get_hash_4(int index)
{
	return string_hash(saved_key[index]) & PH_MASK_4;
}

static int get_hash_5(int index)
{
	return string_hash(saved_key[index]) & PH_MASK_5;
}

static int get_hash_6(int index)
{
	return string_hash(saved_key[index]) & PH_MASK_6;
}

static void set_key(char *key, int index)
{
	char *p = saved_key[index];

	if (options.verbosity >= VERB_DEBUG && !bench_or_test_running)
		fprintf(stderr, "%s(%s, %d)\n", __FUNCTION__, key, index);

	while (*key)
		*p++ = *key++;
	*p = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	return *pcount;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (((plaintext_binary *)binary)->c0 != saved_key[i][0])
			continue;
		if (((plaintext_binary *)binary)->hash == string_hash(saved_key[i]))
			return 1;
	}

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return
	    ((plaintext_binary *)binary)->c0 == saved_key[index][0] &&
	    ((plaintext_binary *)binary)->hash == string_hash(saved_key[index]);
}

static int cmp_exact(char *source, int index)
{
	source += FORMAT_TAG_LEN;
	return !strcmp(source, saved_key[index]);
}

struct fmt_main FMT_STRUCT = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_MIN_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		fmt_default_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
		{ NULL },
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
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
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

#endif /* plugin stanza */

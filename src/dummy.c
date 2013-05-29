/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2011,2012 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <string.h>

#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"dummy"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"N/A"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

/* Max 125, but 95 typically produces fewer L1 data cache tag collisions */
#define PLAINTEXT_LENGTH		95

typedef struct {
	ARCH_WORD_32 hash;
	char c0;
} dummy_binary;

#define BINARY_SIZE			sizeof(dummy_binary)
#define BINARY_ALIGN			sizeof(ARCH_WORD_32)
#define SALT_SIZE			0
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		(0x4000 / (PLAINTEXT_LENGTH + 1))

static struct fmt_tests tests[] = {
	{"$dummy$64756d6d79", "dummy"},
	{"$dummy$", ""},
	{"$dummy$70617373776f7264", "password"},
	{NULL}
};

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q, c;

	if (strncmp(ciphertext, "$dummy$", 7))
		return 0;

	p = strrchr(ciphertext, '$');

/* Support saltless hashes only for now */
	if (p - ciphertext != 6)
		return 0;

	q = ++p;
	while ((c = *q)) {
		q++;
		if (atoi16[ARCH_INDEX(c)] == 0x7F)
			return 0;
		if (c >= 'A' && c <= 'F') /* support lowercase only */
			return 0;
	}

/* Must be an even number of hex chars (zero is OK) */
	if ((q - p) & 1)
		return 0;

/* We won't be able to crack passwords longer than PLAINTEXT_LENGTH.
 * Also, we rely on this check having been performed before decode(). */
	if (((q - p) >> 1) > PLAINTEXT_LENGTH)
		return 0;

	return 1;
}

static char *decode(char *ciphertext)
{
	static char out[PLAINTEXT_LENGTH + 1];
	char *p, *q, c;

	p = strrchr(ciphertext, '$') + 1;
	q = out;
	while ((c = *p)) {
		p++;
		*q++ = (atoi16[ARCH_INDEX(c)] << 4) | atoi16[ARCH_INDEX(*p++)];
	}
	*q = 0;

	return out;
}

static MAYBE_INLINE ARCH_WORD_32 string_hash(char *s)
{
	ARCH_WORD_32 hash, extra;
	char *p;

	p = s + 2;
	hash = (unsigned char)s[0];
	if (!hash)
		goto out;
	extra = (unsigned char)s[1];
	if (!extra)
		goto out;

	while (*p) {
		hash <<= 3; extra <<= 2;
		hash += (unsigned char)p[0];
		if (!p[1]) break;
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

static void *binary(char *ciphertext)
{
	static dummy_binary out;
	char *decoded;

	decoded = decode(ciphertext);

	out.hash = string_hash(decoded);
	out.c0 = decoded[0];

	return &out;
}

static int binary_hash_0(void *binary)
{
	ARCH_WORD_32 hash = ((dummy_binary *)binary)->hash;
	hash ^= hash >> 8;
	return (hash ^ (hash >> 4)) & 0xf;
}

static int binary_hash_1(void *binary)
{
	ARCH_WORD_32 hash = ((dummy_binary *)binary)->hash;
	return (hash ^ (hash >> 8)) & 0xff;
}

static int binary_hash_2(void *binary)
{
	ARCH_WORD_32 hash = ((dummy_binary *)binary)->hash;
	return (hash ^ (hash >> 12)) & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((dummy_binary *)binary)->hash & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((dummy_binary *)binary)->hash & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((dummy_binary *)binary)->hash & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((dummy_binary *)binary)->hash & 0x7ffffff;
}

static int get_hash_0(int index)
{
	ARCH_WORD_32 hash = string_hash(saved_key[index]);
	hash ^= hash >> 8;
	return (hash ^ (hash >> 4)) & 0xf;
}

static int get_hash_1(int index)
{
	ARCH_WORD_32 hash = string_hash(saved_key[index]);
	return (hash ^ (hash >> 8)) & 0xff;
}

static int get_hash_2(int index)
{
	ARCH_WORD_32 hash = string_hash(saved_key[index]);
	return (hash ^ (hash >> 12)) & 0xfff;
}

static int get_hash_3(int index)
{
	return string_hash(saved_key[index]) & 0xffff;
}

static int get_hash_4(int index)
{
	return string_hash(saved_key[index]) & 0xfffff;
}

static int get_hash_5(int index)
{
	return string_hash(saved_key[index]) & 0xffffff;
}

static int get_hash_6(int index)
{
	return string_hash(saved_key[index]) & 0x7ffffff;
}

static void set_key(char *key, int index)
{
	char *p = saved_key[index];
	*p = 0;
	strncat(p, key, PLAINTEXT_LENGTH);
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
		if (((dummy_binary *)binary)->c0 != saved_key[i][0])
			continue;
		if (((dummy_binary *)binary)->hash == string_hash(saved_key[i]))
			return 1;
	}

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return
	    ((dummy_binary *)binary)->c0 == saved_key[index][0] &&
	    ((dummy_binary *)binary)->hash == string_hash(saved_key[index]);
}

static int cmp_exact(char *source, int index)
{
	return !strcmp(decode(source), saved_key[index]);
}

struct fmt_main fmt_dummy = {
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
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		fmt_default_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		fmt_default_salt,
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

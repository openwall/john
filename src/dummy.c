/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2011 by Solar Designer
 */

#include <string.h>

#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"dummy"
#define FORMAT_NAME			"dummy"
#define ALGORITHM_NAME			"N/A"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		72

#define BINARY_SIZE			128
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		64
#define MAX_KEYS_PER_CRYPT		128

static struct fmt_tests tests[] = {
	{"$dummy$64756d6d79", "dummy"},
	{"$dummy$", ""},
	{"$dummy$70617373776f7264", "password"},
	{NULL}
};

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext)
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

/* Should leave at least one byte for NUL termination (we will sometimes treat
 * these "binaries" as strings). */
	if (((q - p) >> 1) >= BINARY_SIZE)
		return 0;

	return 1;
}

static void *binary(char *ciphertext)
{
	static char out[BINARY_SIZE];
	char *p, *q, c;

	memset(out, 0, sizeof(out));

	p = strrchr(ciphertext, '$') + 1;
	q = out;
	while ((c = *p)) {
		p++;
		*q++ = (atoi16[ARCH_INDEX(c)] << 4) | atoi16[ARCH_INDEX(*p++)];
	}

	return out;
}

static unsigned int string_hash(char *s)
{
	unsigned int hash, extra;
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

static int binary_hash_0(void *binary)
{
	unsigned int hash = string_hash((char *)binary);
	hash ^= hash >> 8;
	return (hash ^ (hash >> 4)) & 0xf;
}

static int binary_hash_1(void *binary)
{
	unsigned int hash = string_hash((char *)binary);
	return (hash ^ (hash >> 8)) & 0xff;
}

static int binary_hash_2(void *binary)
{
	unsigned int hash = string_hash((char *)binary);
	return (hash ^ (hash >> 12)) & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return string_hash((char *)binary) & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return string_hash((char *)binary) & 0xfffff;
}

static int get_hash_0(int index)
{
	unsigned int hash = string_hash(saved_key[index]);
	hash ^= hash >> 8;
	return (hash ^ (hash >> 4)) & 0xf;
}

static int get_hash_1(int index)
{
	unsigned int hash = string_hash(saved_key[index]);
	return (hash ^ (hash >> 8)) & 0xff;
}

static int get_hash_2(int index)
{
	unsigned int hash = string_hash(saved_key[index]);
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

static void crypt_all(int count)
{
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (*(char *)binary != saved_key[i][0])
			continue;
		if (!strcmp((char *)binary, saved_key[i]))
			return 1;
	}

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !strcmp((char *)binary, saved_key[index]);
}

static int cmp_exact(char *source, int index)
{
	return 1;
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
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		fmt_default_init,
		valid,
		fmt_default_split,
		binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
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
			get_hash_4
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

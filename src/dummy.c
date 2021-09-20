/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2011,2012 by Solar Designer
 *
 * With many minor changes in jumbo by other contributors.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"
#include "formats.h"
#include "options.h"

#define FORMAT_LABEL			"dummy"
#define FORMAT_TAG			"$dummy$"
#define FORMAT_TAG_LEN			(sizeof(FORMAT_TAG)-1)
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"N/A"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

/* Max 125, but 95 typically produces fewer L1 data cache tag collisions */
#define PLAINTEXT_LENGTH		95
#define MAX_PLAINTEXT_LENGTH		(PLAINTEXT_BUFFER_SIZE - 3) // 125

typedef struct {
	uint32_t hash;
	char c0;
} dummy_binary;

#define BINARY_SIZE			sizeof(dummy_binary)
#define BINARY_ALIGN			sizeof(uint32_t)
#define SALT_SIZE			0
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		(0x4000 / (PLAINTEXT_LENGTH + 1))

static struct fmt_tests tests[] = {
	{"$dummy$64756d6d79", "dummy"},
	{"$dummy$", ""},
	{"$dummy$00", ""}, // note, NOT canonical
	{"$dummy$0064756d6d79", ""}, // note, NOT canonical
	{"$dummy$70617373776f7264", "password"},
	{NULL}
};

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];
static int warned = 0;

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q, c;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	p = strrchr(ciphertext, '$');

/* Support saltless hashes only for now */
	if (p - ciphertext != 6)
		return 0;

	q = ++p;
	while ((c = *q)) {
		q++;
		if (atoi16l[ARCH_INDEX(c)] == 0x7F)
			return 0;
	}

/* Must be an even number of hex chars (zero is OK) */
	if ((q - p) & 1)
		return 0;

/* We won't be able to crack passwords longer than PLAINTEXT_LENGTH.
 * Also, we rely on this check having been performed before decode(). */
	if (((q - p) >> 1) > PLAINTEXT_LENGTH) {
		/*
		 * Warn if the dummy hash is not supported due to the maximum
		 * password length, but otherwise would be valid.
		 * Would one warning for each invalid hash be better?
		 */
		if (options.verbosity >= VERB_DEFAULT && warned < 2 &&
		    ((q - p) >> 1) > MAX_PLAINTEXT_LENGTH) {
			warned = 2;
			fprintf(stderr,
			        "dummy password length %d > max. supported length %d\n",
				(int)((q - p) >> 1), MAX_PLAINTEXT_LENGTH);
		}
		else if (options.verbosity >= VERB_DEFAULT && warned == 0 &&
		         ((q - p) >> 1) > PLAINTEXT_LENGTH) {
			warned = 1;
			/*
			 * Should a hint to recompile with adjusted PLAINTEXT_LENGTH
			 * be added here? Or is dummy format only used by experts anyway?
			 */
			fprintf(stderr,
			        "dummy password length %d > currently supported length %d\n",
			        (int)((q - p) >> 1), PLAINTEXT_LENGTH);
		}
		return 0;
	}
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	// canonical fix for any hash with embedded null.
	char *cp;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return ciphertext;
	cp = &ciphertext[FORMAT_TAG_LEN];
	while (cp[0] && cp[1]) {
		if (cp[0] == '0' && cp[1] == '0') {
			char *cp2 = str_alloc_copy(ciphertext);
			cp2[cp-ciphertext] = 0;
			return cp2;
		}
		cp += 2;
	}
	return ciphertext;
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

static void *binary(char *ciphertext)
{
	static dummy_binary out;
	char *decoded;

	memset(&out, 0, sizeof(out));	/* Jumbo only */
	decoded = decode(ciphertext);

	out.hash = string_hash(decoded);
	out.c0 = decoded[0];

	return &out;
}

static int binary_hash_0(void *binary)
{
	uint32_t hash = ((dummy_binary *)binary)->hash;
	hash ^= hash >> 8;
	return (hash ^ (hash >> 4)) & PH_MASK_0;
}

static int binary_hash_1(void *binary)
{
	uint32_t hash = ((dummy_binary *)binary)->hash;
	return (hash ^ (hash >> 8)) & PH_MASK_1;
}

static int binary_hash_2(void *binary)
{
	uint32_t hash = ((dummy_binary *)binary)->hash;
	return (hash ^ (hash >> 12)) & PH_MASK_2;
}

static int binary_hash_3(void *binary)
{
	return ((dummy_binary *)binary)->hash & PH_MASK_3;
}

static int binary_hash_4(void *binary)
{
	return ((dummy_binary *)binary)->hash & PH_MASK_4;
}

static int binary_hash_5(void *binary)
{
	return ((dummy_binary *)binary)->hash & PH_MASK_5;
}

static int binary_hash_6(void *binary)
{
	return ((dummy_binary *)binary)->hash & PH_MASK_6;
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
		0,
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
		split,
		binary,
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

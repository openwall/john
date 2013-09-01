/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "escrypt/crypto_scrypt.h"

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"scrypt"
#define FORMAT_NAME			""
#ifdef __XOP__
#define ALGORITHM_NAME			"Salsa20/8 128/128 XOP"
#elif defined(__AVX__)
#define ALGORITHM_NAME			"Salsa20/8 128/128 AVX"
#elif defined(__SSE2__)
#define ALGORITHM_NAME			"Salsa20/8 128/128 SSE2"
#else
#define ALGORITHM_NAME			"Salsa20/8 32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		" (16384, 8, 1)"
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125

#define BINARY_SIZE			128
#define BINARY_ALIGN			1
#define SALT_SIZE			BINARY_SIZE
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"$7$C6..../....SodiumChloride$"
	    "kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D", "pleaseletmein"},
	{"$7$C6..../....\x01\x09\x0a\x0d\x20\x7f\x80\xff$"
	    "b7cKqzsQk7txdc9As1WZBHjUPNWQWJW8A.UUUTA5eD1",
	    "\x01\x09\x0a\x0d\x20\x7f\x80\xff"},
	{"$7$2/..../....$rNxJWVHNv/mCNcgE/f6/L4zO6Fos5c2uTzhyzoisI62", ""},
	{"$7$86....E....NaCl$xffjQo7Bm/.SKRS4B2EuynbOLjAmXU5AbDbRXhoBl64",
	    "password"},
	{NULL}
};

static int max_threads;
static escrypt_local_t *local;

static char saved_salt[SALT_SIZE];
static struct {
	char key[PLAINTEXT_LENGTH + 1];
	char out[BINARY_SIZE];
} *buffer;

static void init(struct fmt_main *self)
{
	int i;

#ifdef _OPENMP
	max_threads = omp_get_max_threads();
	self->params.min_keys_per_crypt *= max_threads;
	self->params.max_keys_per_crypt *= max_threads;
#else
	max_threads = 1;
#endif

	local = mem_alloc(sizeof(*local) * max_threads);
	for (i = 0; i < max_threads; i++)
		escrypt_init_local(&local[i]);

	buffer = mem_alloc(sizeof(*buffer) * self->params.max_keys_per_crypt);
}

static void done(void)
{
	int i;

	for (i = 0; i < max_threads; i++)
		escrypt_free_local(&local[i]);

	MEM_FREE(local);
	MEM_FREE(buffer);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	int length;

	if (strncmp(ciphertext, "$7$", 3))
		return 0;

	for (p = ciphertext + 3; p < ciphertext + (3 + 1 + 5 + 5); p++)
		if (atoi64[ARCH_INDEX(*p)] == 0x7F)
			return 0;

	p = strrchr(ciphertext, '$');
	if (!p)
		return 0;

	if (p - ciphertext > BINARY_SIZE - (1 + 43))
		return 0;

	length = 0;
	while (atoi64[ARCH_INDEX(*++p)] != 0x7F)
		length++;

	return !*p && length == 43;
}

static void *binary(char *ciphertext)
{
	static char out[BINARY_SIZE];
	strncpy(out, ciphertext, sizeof(out)); /* NUL padding is required */
	return out;
}

static void *salt(char *ciphertext)
{
	static char out[SALT_SIZE];
	char *p = strrchr(ciphertext, '$');
	/* NUL padding is required */
	memset(out, 0, sizeof(out));
	memcpy(out, ciphertext, p - ciphertext);
	return out;
}

#define H(s, i) \
	((int)(unsigned char)(atoi64[ARCH_INDEX((s)[(i)])] ^ (s)[(i) - 1]))

#define H0(s) \
	int i = strlen(s) - 2; \
	return i > 0 ? H((s), i) & 0xF : 0
#define H1(s) \
	int i = strlen(s) - 2; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 4)) & 0xFF : 0
#define H2(s) \
	int i = strlen(s) - 2; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 6)) & 0xFFF : 0
#define H3(s) \
	int i = strlen(s) - 2; \
	return i > 4 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10)) & 0xFFFF : 0
#define H4(s) \
	int i = strlen(s) - 2; \
	return i > 6 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10) ^ (H((s), i - 6) << 15)) & 0xFFFFF : 0

static int binary_hash_0(void *binary)
{
	H0((char *)binary);
}

static int binary_hash_1(void *binary)
{
	H1((char *)binary);
}

static int binary_hash_2(void *binary)
{
	H2((char *)binary);
}

static int binary_hash_3(void *binary)
{
	H3((char *)binary);
}

static int binary_hash_4(void *binary)
{
	H4((char *)binary);
}

static int get_hash_0(int index)
{
	H0(buffer[index].out);
}

static int get_hash_1(int index)
{
	H1(buffer[index].out);
}

static int get_hash_2(int index)
{
	H2(buffer[index].out);
}

static int get_hash_3(int index)
{
	H3(buffer[index].out);
}

static int get_hash_4(int index)
{
	H4(buffer[index].out);
}

static int salt_hash(void *salt)
{
	int i, h;

	i = strlen((char *)salt) - 1;
	if (i > 1) i--;

	h = (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i])];
	h ^= ((unsigned char *)salt)[i - 1];
	h <<= 6;
	h ^= (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i - 1])];
	h ^= ((unsigned char *)salt)[i];

	return h & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	strcpy(saved_salt, salt);
}

static void set_key(char *key, int index)
{
	strnzcpy(buffer[index].key, key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return buffer[index].key;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
	int failed = 0;

#pragma omp parallel for default(none) private(index) shared(count, failed, max_threads, local, saved_salt, buffer)
#endif
	for (index = 0; index < count; index++) {
		uint8_t *hash;
#ifdef _OPENMP
		int t = omp_get_thread_num();
#else
		const int t = 0;
#endif
		if (t < max_threads) {
			hash = escrypt_r(&local[t],
			    (const uint8_t *)buffer[index].key,
			    strlen(buffer[index].key),
			    (const uint8_t *)saved_salt,
			    (uint8_t *)&buffer[index].out,
			    sizeof(buffer[index].out));
		} else { /* should not happen */
			escrypt_local_t local;
			hash = NULL;
			if (escrypt_init_local(&local) == 0) {
				hash = escrypt_r(&local,
				    (const uint8_t *)buffer[index].key,
				    strlen(buffer[index].key),
				    (const uint8_t *)saved_salt,
				    (uint8_t *)&buffer[index].out,
				    sizeof(buffer[index].out));
				escrypt_free_local(&local);
			}
		}
		if (!hash) {
#ifdef _OPENMP
#pragma omp critical
			failed = 1;
			buffer[index].out[0] = 0;
#else
			fprintf(stderr, "scrypt memory allocation failed\n");
			error();
#endif
		}
	}

#ifdef _OPENMP
	if (failed) {
		fprintf(stderr, "scrypt memory allocation failed\n");
		error();
	}
#endif

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!strcmp((char *)binary, buffer[index].out))
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !strcmp((char *)binary, buffer[index].out);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_scrypt = {
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
		0,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			NULL,
			NULL
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
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

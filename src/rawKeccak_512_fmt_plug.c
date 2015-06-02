/* Keccak-512 cracker patch for JtR. Hacked together during January of 2013
 * by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 by Solar Designer
 * based on rawMD4_fmt.c code, with trivial changes by groszek.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawKeccak;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawKeccak);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "KeccakHash.h"

#ifdef _OPENMP
#ifndef OMP_SCALE
#define OMP_SCALE			2048
#endif
#include <omp.h>
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"Raw-Keccak"
#define FORMAT_NAME		""
#if defined(__AVX__)
#define ALGORITHM_NAME			"128/128 AVX"
#elif defined(__XOP__)
#define ALGORITHM_NAME			"128/128 XOP"
#elif defined(__SSE4_1__)
#define ALGORITHM_NAME			"128/128 SSE4.1"
#elif defined(__SSSE3__)
#define ALGORITHM_NAME			"128/128 SSSE3"
#elif defined(__SSE2__)
#define ALGORITHM_NAME			"128/128 SSE2"
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		128

#define BINARY_SIZE			64
#define SALT_SIZE			0

#define BINARY_ALIGN			4
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", ""},
	{"$keccak$d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609", "The quick brown fox jumps over the lazy dog"},
	{"$keccak$e4a7e8f5572f4853ef26a862f31687c249b1cd7922df2aac1f4348d8ceef944c74d1949e3465704a5f3f89fb53e0dcce3ea142c90af04c84cc7e548f144f8f0b", "abcd"},
	{NULL}
};

static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)
    [(BINARY_SIZE + sizeof(ARCH_WORD_32) - 1) / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, "$keccak$", 8))
		p += 8;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[8 + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, "$keccak$", 8))
		ciphertext += 8;

	memcpy(out, "$keccak$", 8);
	memcpy(out + 8, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + 8);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 8;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index)
{
	return crypt_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
	return crypt_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
	return crypt_out[index][0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return crypt_out[index][0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return crypt_out[index][0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	return crypt_out[index][0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return crypt_out[index][0] & 0x7FFFFFF;
}

static void set_key(char *key, int index)
{
	int len = strlen(key);
	saved_len[index] = len;
	if (len > PLAINTEXT_LENGTH)
		len = saved_len[index] = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
}

static char *get_key(int index)
{
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		Keccak_HashInstance hash;
		Keccak_HashInitialize(&hash, 576, 1024, 512, 0x01);
		Keccak_HashUpdate(&hash, (unsigned char*)saved_key[index], saved_len[index] * 8);
		Keccak_HashFinal(&hash, (unsigned char*)crypt_out[index]);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_rawKeccak = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		"Keccak 512 " ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
                BINARY_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
                SALT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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

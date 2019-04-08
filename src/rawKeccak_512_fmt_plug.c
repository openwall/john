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

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "KeccakHash.h"

#define FORMAT_LABEL		"Raw-Keccak"
#define FORMAT_NAME		""
#define FORMAT_TAG           "$keccak$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)

#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		128

#define BINARY_SIZE			64
#define SALT_SIZE			0

#define BINARY_ALIGN			4
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		256

#ifndef OMP_SCALE
#define OMP_SCALE			64 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	{"0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", ""},
	{"$keccak$d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609", "The quick brown fox jumps over the lazy dog"},
	{"$keccak$e4a7e8f5572f4853ef26a862f31687c249b1cd7922df2aac1f4348d8ceef944c74d1949e3465704a5f3f89fb53e0dcce3ea142c90af04c84cc7e548f144f8f0b", "abcd"},
	{"$keccak$b7c090825b238d33cff5c92075f4dd80ce1b36359ce399ce9fce2a2d91232d5a494a58c37f489c3c859b779b3740cd7791d7666793779ee5c67476d31f91c814", "UPPERCASE"},
	{"$keccak$40b787e94778266fb196a73b7a77edf9de2ef172451a2b87531324812250df8f26fcc11e69b35afddbe639956c96153e71363f97010bc99405dd2d77b8c41986", "123456789"},
	{NULL}
};

static int (*saved_len);
// the Keccak function can read up to next even 8 byte offset.
// making the buffer larger avoid reading past end of buffer
static char (*saved_key)[(((PLAINTEXT_LENGTH+1)+7)/8)*8];
static uint32_t (*crypt_out)
    [(BINARY_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

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
	if (!strncmp(p, FORMAT_TAG, FORMAT_TAG_LEN))
		p += FORMAT_TAG_LEN;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[FORMAT_TAG_LEN + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		ciphertext += FORMAT_TAG_LEN;

	memcpy(out, FORMAT_TAG, FORMAT_TAG_LEN);
	memcpylwr(out + FORMAT_TAG_LEN, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + FORMAT_TAG_LEN;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		Keccak_HashInstance hash;
		Keccak_HashInitialize(&hash, 576, 1024, 512, 0x01);
		Keccak_HashUpdate(&hash, (unsigned char*)saved_key[index], saved_len[index] * 8);
		Keccak_HashFinal(&hash, (unsigned char*)crypt_out[index]);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
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
                BINARY_ALIGN,
		SALT_SIZE,
                SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD |
		FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
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
		{ NULL },
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
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

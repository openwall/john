/*
 * This  software is Copyright © 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * Based on Raw-SHA1, but this is OpenSSL only.
 */

#include <string.h>
#include <openssl/sha.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"raw-sha"
#define FORMAT_NAME			"Raw SHA0"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define FORMAT_TAG			"$SHA$"
#define TAG_LENGTH			5

#define PLAINTEXT_LENGTH		125
#define HASH_LENGTH			40
#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define BINARY_SIZE			20
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"17e7ba749415d4d332447a43830ef39ac8100ab8", "magnum"},
	{FORMAT_TAG "f96cea198ad1dd5617ac084a3d92c6107708c0ef", ""},
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	if (strlen(ciphertext) != HASH_LENGTH)
		return 0;

	for (i = 0; i < HASH_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static char *split(char *ciphertext, int index)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	strncpy(out, FORMAT_TAG, sizeof(out));

	memcpy(&out[TAG_LENGTH], ciphertext, HASH_LENGTH);
	out[CIPHERTEXT_LENGTH] = 0;

	strlwr(&out[TAG_LENGTH]);

	return out;
}

static void set_key(char *key, int index) {
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *get_key(int index) {
	return saved_key;
}

static int cmp_all(void *binary, int count) {
	return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static int cmp_exact(char *source, int count){
  return (1);
}

static int cmp_one(void * binary, int index)
{
	return cmp_all(binary, index);
}

static void crypt_all(int count)
{
	SHA_Init( &ctx );
	SHA_Update( &ctx, (unsigned char *) saved_key, strlen( saved_key ) );
	SHA_Final( (unsigned char *) crypt_key, &ctx);
}

static void *binary(char *ciphertext)
{
	static ARCH_WORD_32 outb[BINARY_SIZE / 4];
	unsigned char *realcipher = (unsigned char*)outb;
	int i;

	ciphertext += TAG_LENGTH;

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void *)realcipher;
}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }
static int binary_hash_5(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffffff; }
static int binary_hash_6(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0x7ffffff; }

static int get_hash_0(int index) { return ((unsigned int *)crypt_key)[0] & 0xf; }
static int get_hash_1(int index) { return ((unsigned int *)crypt_key)[0] & 0xff; }
static int get_hash_2(int index) { return ((unsigned int *)crypt_key)[0] & 0xfff; }
static int get_hash_3(int index) { return ((unsigned int *)crypt_key)[0] & 0xffff; }
static int get_hash_4(int index) { return ((unsigned int *)crypt_key)[0] & 0xfffff; }
static int get_hash_5(int index) { return ((unsigned int *)crypt_key)[0] & 0xffffff; }
static int get_hash_6(int index) { return ((unsigned int *)crypt_key)[0] & 0x7ffffff; }

struct fmt_main fmt_rawSHA0 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		valid,
		split,
		binary,
		fmt_default_salt,
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

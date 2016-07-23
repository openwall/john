/* This format is reverse engineered from InsidePro Hash Manager!
 *
 * This software is Copyright (c) 2015, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_palshop;
#elif FMT_REGISTERS_H
john_register_one(&fmt_palshop);
#else

#include "arch.h"
#include "sha.h"
#include "md5.h"
#include <string.h>
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               64
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL            "Palshop"
#define FORMAT_NAME             "MD5(Palshop)"
#define ALGORITHM_NAME          "MD5 + SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             20  /* 20 chracters of "m2" */
#define SALT_SIZE               0
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define FORMAT_TAG              "$palshop$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)


static struct fmt_tests palshop_tests[] = {
	{"$palshop$68b11ee90ed17ef14aa0f51af494c2c63ad7d281a9888cb593e", "123"},
	{"ea3a8d0f4cd9e5e22ccede1ad59dd2c5c7e839348a8a519d505", "ABC"},
	// http://leopard.500mb.net/HashGenerator/
	{"$palshop$f2e3babc50b316e6e886f3062a37cead6d1bd16dd2bed49f7bc", "long password"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static size_t *saved_len;

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	static int omp_t = 1;
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*crypt_out));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_len));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext;
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;

	if(!p)
		return 0;
	if (!ishex_oddOK(p))
		return 0;

	if (strlen(p) != 51)
		return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p = ciphertext;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;

	memcpy(out, p, BINARY_SIZE);

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		unsigned char m1[32];
		unsigned char s1[40];
		unsigned char m2[32];
		// unsigned char s2[40];
		unsigned char data[51 + 1] = {0};
		unsigned char buffer[20];
		MD5_CTX mctx;
		SHA_CTX sctx;

		// m1 = md5($p)
		MD5_Init(&mctx);
		MD5_Update(&mctx, saved_key[index], saved_len[index]);
		MD5_Final(buffer, &mctx);
		hex_encode(buffer, 16, m1);

		// s1 = sha1($p)
		SHA1_Init(&sctx);
		SHA1_Update(&sctx, saved_key[index], saved_len[index]);
		SHA1_Final((unsigned char*)crypt_out[index], &sctx);
		hex_encode((unsigned char*)crypt_out[index], 20, s1);

		// data = m1[11:] + s1[:29] + m1[0:1]  // 51 bytes!
		memcpy(data, m1 + 11, 32 - 11);
		memcpy(data + 21, s1, 29);
		data[50] = m1[0];

		// m2 = md5(data)
		MD5_Init(&mctx);
		MD5_Update(&mctx, data, 51);
		MD5_Final(buffer, &mctx);
		hex_encode(buffer, 16, m2);

		// s2 = sha1(data)
		// SHA1_Init(&sctx);
		// SHA1_Update(&sctx, data, 51);
		// SHA1_Final((unsigned char*)crypt_out[index], &sctx);
		// hex_encode((unsigned char*)crypt_out[index], 20, s1);

		// hash =  m2[11:] + s2[:29] + m2[0], but starting 20 bytes should be enough!
		memcpy((unsigned char*)crypt_out[index], m2 + 11, 20);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (*((ARCH_WORD_32*)binary) == crypt_out[index][0])
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

static void palshop_set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_palshop = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		palshop_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
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
		palshop_set_key,
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

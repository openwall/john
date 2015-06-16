/* Skein cracker patch for JtR. Hacked together during April of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_skein_256;
extern struct fmt_main fmt_skein_512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_skein_256);
john_register_one(&fmt_skein_512);
#else

#include <string.h>
#include "arch.h"
#include "sph_skein.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
// OMP_SCALE tuned on core i7 quad core HT
//        256bt  512bt
// 1   -  233k   232k
// 64  - 5406k  5377k
// 128 - 6730k  6568k
// 256 - 7618k  7405k
// 512 - 8243k  8000k
// 1k  - 8610k  8408k  ** this level chosen
// 2k  - 8804k  8610k
// 4k  - 8688k  8648k
#ifndef OMP_SCALE
#define OMP_SCALE  1024
#endif
#endif
#include "memdbg.h"

// Skein-256 or Skein-512 are the real format labels.
#define FORMAT_LABEL		"Skein"
#define FORMAT_NAME		""
#define FORMAT_TAG		"$skein$"
#define TAG_LENGTH		7
#define ALGORITHM_NAME		"Skein 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE256		32
#define BINARY_SIZE512		64
#define CMP_SIZE		28 // skein224
#define SALT_SIZE		0
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define BINARY_ALIGN		4
#define SALT_ALIGN		1

static struct fmt_tests skein_256_tests[] = {
	{"39CCC4554A8B31853B9DE7A1FE638A24CCE6B35A55F2431009E18780335D2621", ""},
	{"$skein$39CCC4554A8B31853B9DE7A1FE638A24CCE6B35A55F2431009E18780335D2621", ""},
	// john.pot uses lower case
	{"$skein$39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621", ""},
	{NULL}
};

static struct fmt_tests skein_512_tests[] = {
	{"71b7bce6fe6452227b9ced6014249e5bf9a9754c3ad618ccc4e0aae16b316cc8ca698d864307ed3e80b6ef1570812ac5272dc409b5a012df2a579102f340617a", "\xff"},
	{"$skein$BC5B4C50925519C290CC634277AE3D6257212395CBA733BBAD37A4AF0FA06AF41FCA7903D06564FEA7A2D3730DBDB80C1F85562DFCC070334EA4D1D9E72CBA7A", ""},
	// john.pot uses lower case
	{"$skein$bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a", ""},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE512 / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self, int len)
{
	char *p;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	if (strlen(p) != len)
		return 0;

	while(*p)
		if(atoi16[ARCH_INDEX(*p++)]==0x7f)
			return 0;
	return 1;
}

static int valid256(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 64);
}
static int valid512(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 128);
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + BINARY_SIZE512*2 + 1];
	
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	
	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	strnzcpy(out + TAG_LENGTH, ciphertext, BINARY_SIZE512*2 + 1);
	strlwr(out + TAG_LENGTH);
	return out;
}

static void *get_binary_256(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE256];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = strrchr(ciphertext, '$') + 1;
	else
		p = ciphertext;
	for (i = 0; i < BINARY_SIZE256; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void *get_binary_512(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE512];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = strrchr(ciphertext, '$') + 1;
	else
		p = ciphertext;
	for (i = 0; i < BINARY_SIZE512; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static int crypt_256(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		sph_skein256_context ctx;

		sph_skein256_init(&ctx);
		sph_skein256(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_skein256_close(&ctx, (unsigned char*)crypt_out[index]);
	}
	return count;
}

static int crypt_512(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		sph_skein512_context ctx;

		sph_skein512_init(&ctx);
		sph_skein512(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_skein512_close(&ctx, (unsigned char*)crypt_out[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], CMP_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], CMP_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void skein_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static char *prepare(char *fields[10], struct fmt_main *self) {
	static char buf[128+TAG_LENGTH+1];
	char *hash = fields[1];
	int len = strlen(hash);
	if ( (len == 64 || len == 128) && valid(hash, self, len) ) {
		sprintf(buf, "%s%s", FORMAT_TAG, hash);
		return buf;
	}
	return hash;
}

struct fmt_main fmt_skein_256 = {
	{
		"skein-256",
		"Skein 256",
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE256,
		BINARY_ALIGN,
		SALT_SIZE,
		BINARY_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		skein_256_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		prepare,
		valid256,
		split,
		get_binary_256,
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
		skein_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_256,
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


struct fmt_main fmt_skein_512 = {
	{
		"skein-512",
		"Skein 512",
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE512,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		skein_512_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		prepare,
		valid512,
		split,
		get_binary_512,
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
		skein_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_512,
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

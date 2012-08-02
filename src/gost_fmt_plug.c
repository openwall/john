/*
 * GOST 3411 cracker patch for JtR. Hacked together during
 * May of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Sergey V. <sftp.mtuci at gmail com>, and JimF
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Sergey V. <sftp.mtuci at gmail com>, and JimF
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format => user:gost-hash;
 *		   user:$gost$gost-hash;
 *		   user:$gost-cp$gost-cryptopro-hash;
 */

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "gost.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"gost"
#define FORMAT_NAME		"GOST R 34.11-94"

#define FORMAT_TAG		"$gost$"
#define TAG_LENGTH		6
#define FORMAT_TAG_CP		"$gost-cp$"
#define TAG_CP_LENGTH		9

#if !defined(USE_GCC_ASM_IA32) && defined(USE_GCC_ASM_X64)
#define ALGORITHM_NAME		"64/64"
#else
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	64
#define CIPHERTEXT_LENGTH	64
#define BINARY_SIZE		32
#define SALT_SIZE		1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests gost_tests[] = {
	{"ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d", ""},
	{"d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd", "a"},
	{FORMAT_TAG    "ad4434ecb18f2c99b60cbe59ec3d2469582b65273f48de72db2fde16a4889a4d", "message digest"},
	{FORMAT_TAG    "0886f91e7fcaff65eb2635a1a4c9f203003e0ce5ea74b72fc6462cc72649694e",
	 "This is very very long pass phrase for test gost hash function."},
	{FORMAT_TAG_CP "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0", ""},
	{FORMAT_TAG_CP "e74c52dd282183bf37af0079c9f78055715a103f17e3133ceff1aacf2f403011", "a"},
	{FORMAT_TAG_CP "bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0", "message digest"},
	{FORMAT_TAG_CP "5394adfacb65a9ac5781c3080b244c955a9bf03befd51582c3850b8935f80762",
	 "This is very very long pass phrase for test gost hash function."},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[8];
static int is_cryptopro; /* non 0 for CryptoPro hashes */

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	gost_init_table();
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	else if (!strncmp(p, FORMAT_TAG_CP, TAG_CP_LENGTH))
		p += TAG_CP_LENGTH;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;

	return !*q && q - p == CIPHERTEXT_LENGTH;
}


static char *split(char *ciphertext, int index)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;
	else if (!strncmp(ciphertext, FORMAT_TAG_CP, TAG_CP_LENGTH))
		return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static char i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		i=0;
	else
		i=1;
	return &i;
}

static void set_salt(void *salt)
{
	is_cryptopro = *(char*)salt;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;
	else
		p = ciphertext + TAG_CP_LENGTH;

	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		gost_ctx ctx;

		if (is_cryptopro)
			john_gost_cryptopro_init(&ctx);
		else
			john_gost_init(&ctx);
		john_gost_update(&ctx, (const unsigned char*)saved_key[index],
			    strlen(saved_key[index]));

		john_gost_final(&ctx, (unsigned char *)crypt_out[index]);
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (crypt_out[index][0] == *(ARCH_WORD_32*)binary)
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

static void set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_gost = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		gost_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
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
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

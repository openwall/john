/*
 * GOST 3411 cracker patch for JtR. Hacked together during
 * May of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Sergey V. <sftp.mtuci at gmail com>, and JimF
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Sergey V. <sftp.mtuci at gmail com>, and JimF
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format => user:gost-hash;
 *		   user:$gost$gost-hash;
 *		   user:$gost-cp$gost-cryptopro-hash;
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_gost;
#elif FMT_REGISTERS_H
john_register_one(&fmt_gost);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "gost.h"

#define FORMAT_LABEL            "gost"
#define FORMAT_NAME             "GOST R 34.11-94"

#define FORMAT_TAG              "$gost$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG_CP           "$gost-cp$"
#define TAG_CP_LENGTH           (sizeof(FORMAT_TAG_CP)-1)
#if !defined(USE_GCC_ASM_IA32) && defined(USE_GCC_ASM_X64)
#define ALGORITHM_NAME          "64/64"
#else
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507 // Actually unsalted but two variants
#define PLAINTEXT_LENGTH        125
#define CIPHERTEXT_LENGTH       64
#define BINARY_SIZE             32
#define SALT_SIZE               1
#define SALT_ALIGN              1
#define BINARY_ALIGN            sizeof(uint32_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      128

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests gost_tests[] = {
	{"ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d", ""},
	{"d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd", "a"},
	{FORMAT_TAG    "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d", ""},
	{FORMAT_TAG    "d42c539e367c66e9c88a801f6649349c21871b4344c6a573f849fdce62f314dd", "a"},
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
static uint32_t (*crypt_out)[8];
static int is_cryptopro; /* non 0 for CryptoPro hashes */

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	gost_init_table();
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
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


static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_CP_LENGTH + CIPHERTEXT_LENGTH + 1];
	char *cp=&out[TAG_LENGTH];
	strcpy(out, FORMAT_TAG);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	else if (!strncmp(ciphertext, FORMAT_TAG_CP, TAG_CP_LENGTH)) {
		ciphertext += TAG_CP_LENGTH;
		strcpy(out, FORMAT_TAG_CP);
		cp=&out[TAG_CP_LENGTH];
	}
	memcpy(cp, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(cp);
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

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		gost_ctx ctx;

		if (is_cryptopro)
			john_gost_cryptopro_init(&ctx);
		else
			john_gost_init(&ctx);
		john_gost_update(&ctx, (const unsigned char*)saved_key[index],
			    strlen(saved_key[index]));

		john_gost_final(&ctx, (unsigned char *)crypt_out[index]);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (crypt_out[index][0] == *(uint32_t*)binary)
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
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
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
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG, FORMAT_TAG_CP },
		gost_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
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
		set_salt,
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

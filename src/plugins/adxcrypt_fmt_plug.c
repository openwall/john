/*
 * JtR format to crack the IBM/Toshiba 4960 OS ADXCRYPT hashes.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * The ADXCRYPT algorithm was reverse engineered by Dhiru Kholia on
 * 15-August-2018.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_adxcrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_adxcrypt);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               512  // tuned on i7-7820HQ

#include "formats.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"

#define FORMAT_LABEL            "adxcrypt"
#define FORMAT_NAME             "IBM/Toshiba 4690"
#define FORMAT_TAG              "$adxcrypt$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "ADXCRYPT 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        8
#define BINARY_SIZE             8
#define SALT_SIZE               0
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      256

static struct fmt_tests adxcrypt_tests[] = {
	{"$adxcrypt$54886955", "99999999"},  // default credentials
	{"$adxcrypt$54886955", "786r"},  // collided password, works fine on a real system
	{"$adxcrypt$43891846", "30"},
	{"$adxcrypt$43691826", "31"},
	{"$adxcrypt$43391806", "32"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

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
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	// not strictly true
	if (hexlenl(ciphertext + FORMAT_TAG_LEN, &extra) != 4 * 2 || extra)
                goto err;

	return 1;

err:
	return 0;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;

	p = strrchr(ciphertext, '$') + 1;
	memcpy(out, p, 8);

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

/*
 * This code looks weird as it is actually cleaned-up decompiled code.
 *
 * Known plain text = 30
 * Cipher text = 43891846
 *
 * Known plain text = 31
 * Cipher text = 43691826
 *
 * Known plain text = 32
 * Cipher text = 43391806
 */
static void adxcrypt(char *input, unsigned char *output, int16_t length)
{
	char *in;
	int count;
	int32_t idx;
	uint32_t a, b;

	union {
		char b[8];
		uint32_t w[2];
	} buffer;

	// setup work buffer
	if (length > 0)
		memcpy(buffer.b, input, length);
	else
		return;  // -1100;

	// handle "padding"
	count = length;
	while (count < 8) {
		if (count < 8 && length > 0) {
			in = input;
			idx = 0;
			do {
				++idx;
				buffer.b[count] = (*in++) + count;
				count++;
			} while (count < 8 && length > idx);
		}
	}

	// loop
	idx = 0;
#if ARCH_LITTLE_ENDIAN==1
	a = (buffer.w[0] + buffer.w[1]) ^ 0xBEEFFACE;
#else
	a = JOHNSWAP((buffer.w[0] + buffer.w[1]) ^ 0xCEFAEFBE);
#endif
	do {
		if ( (a & 0xF) <= 9 )
			b = a & 0xF;
		else
			b = (a & 0xF) - 7;
		++idx;
		*output++ = b + 48;
		a >>= 4;
	} while ( idx < 8 );
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		adxcrypt(saved_key[index], (unsigned char*)crypt_out[index], strlen(saved_key[index]));
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

static void adxcrypt_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_adxcrypt = {
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
		FMT_CASE | FMT_TRUNC | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{ NULL },
		{ FORMAT_TAG },
		adxcrypt_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
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
		adxcrypt_set_key,
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

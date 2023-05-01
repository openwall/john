/*
 * MYSQL_half_fmt.c
 *
 * Copyright (c) 2008 by <earthquake at rycon.hu>
 *
 * John the ripper MYSQL-fast module
 *
 * Note: The mysql hash's first 8byte is relevant,
 * the another ones depends on the first 8. Maybe
 * the passwords after 9-10character have collision
 * in the first 8byte, so we have to check the full
 * hash.
 *
 * Unbelievable good optimization by Péter Kasza
 *
 * http://rycon.hu/
 *
 * OpenMP support and other assorted hacks by Solar Designer
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_MYSQL_fast;
#elif FMT_REGISTERS_H
john_register_one(&fmt_MYSQL_fast);
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"
#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif
#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"

#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE			2048
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE			16 // This and MKPC tuned for core i7
#endif
#endif

#define FORMAT_LABEL			"mysql"
#define FORMAT_NAME			"MySQL pre-4.1"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		16

#define BINARY_SIZE			4
#define SALT_SIZE			0
#define BINARY_ALIGN		sizeof(uint32_t)
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		512

static struct fmt_tests tests[] = {
	// ciphertext, plaintext
	{"445ff82636a7ba59", "probe"},
	{"60671c896665c3fa", "a"},
	{"1acbed4a27b20da3", "hash"},
	{"77ff75006118bab8", "hacker"},
	{"1b38cd9c2f809809", "hacktivity2008"},
	{"1b38cd9c2f809809", "hacktivity 2008"},
	{"6fc81597422015a8", "johnmodule"},
	{"30f098972cc8924d", "http://guh.nu"},
	{"3fc56f6037218993", "Andrew Hintz"},
	{"697a7de87c5390b2", "drew"},
	{"1eb71cf460712b3e", "http://4tphi.net"},
	{"28ff8d49159ffbaf", "http://violating.us"},
	{"5d2e19393cc5ef67", "password"},
	{"5030573512345671", ""},
	{"723d80f65bf9d670", "UPPERCASE"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_key)[BINARY_SIZE / 4];

static void init(struct fmt_main *self)
{

	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                      sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                      sizeof(*crypt_key));
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}

static int valid(char* ciphertext, struct fmt_main *self)
{
	unsigned int i;

	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) != CIPHERTEXT_LENGTH)
		return 0;

	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] > 15)
			return 0;

	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	memcpy(out, ciphertext, CIPHERTEXT_LENGTH);
	out[CIPHERTEXT_LENGTH] = 0;
	strlwr(out);

	return out;
}

static void *get_binary_size(char *ciphertext, int size)
{
	/* maybe bigger than BINARY_SIZE for use from cmp_exact() */
	static uint32_t buff_[8];
	unsigned char *buff = (unsigned char *)buff_;
	unsigned int i;

	for (i = 0; i < size; i++) {
#if ARCH_LITTLE_ENDIAN
		buff[(i & ~3U) | (3 - (i & 3))] = atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 + atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
#else
		buff[i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 + atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
#endif
	}

	return buff;
}

static void *get_binary(char *ciphertext)
{
	return get_binary_size(ciphertext, BINARY_SIZE);
}

static void set_key(char* key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char* get_key(int index)
{
	return saved_key[index];
}

static int cmp_one(void* binary, int index)
{
	return *(uint32_t *)binary == crypt_key[index][0];
}

static int cmp_all(void* binary, int count)
{
	int i;

#ifdef _OPENMP
	int retval = 0;
#pragma omp parallel for default(none) private(i) shared(count, binary, crypt_key, retval)
	for (i = 0; i < count; i++)
		if (*(uint32_t *)binary == crypt_key[i][0])
#pragma omp atomic
			retval |= 1;
	return retval;
#else
	for (i = 0; i < count; i++)
		if (*(uint32_t *)binary == crypt_key[i][0])
			return 1;
	return 0;
#endif
}

static int cmp_exact(char* source, int index)
{
	uint32_t *binary = get_binary_size(source, 8);
	register uint32_t nr = 1345345333, add = 7, nr2 = 0x12345671;
	register uint32_t tmp;
	unsigned char *p;

	p = (unsigned char *)saved_key[index];
	for (; *p; p++) {
		if (*p == ' ' || *p == '\t')
			continue;

		tmp = (uint32_t)*p;
		nr ^= (((nr & 63) + add) * tmp) + (nr << 8);
		nr2 += (nr2 << 8) ^ nr;
		add += tmp;
	}

	return
		binary[0] == (nr & (((uint32_t)1 << 31) - 1)) &&
		binary[1] == (nr2 & (((uint32_t)1 << 31) - 1));
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(count, saved_key, crypt_key)
#endif
	for (i = 0; i < count; i++) {
		unsigned char *p = (unsigned char *)saved_key[i];

		if (*p) {
			uint32_t nr, add;
			uint32_t tmp;
			while (*p == ' ' || *p == '\t')
				p++;
			tmp = (uint32_t) (unsigned char) *p++;
			nr = 1345345333 ^ ((((1345345333 & 63) + 7) * tmp) + (1345345333U << 8));
			add = 7 + tmp;
			for (; *p; p++) {
				if (*p == ' ' || *p == '\t')
					continue;
				tmp = (uint32_t) (unsigned char) *p;
				nr ^= (((nr & 63) + add) * tmp) + (nr << 8);
				add += tmp;
			}
			crypt_key[i][0] = (nr & (((uint32_t)1 << 31) - 1));
			continue;
		}
		crypt_key[i][0] = (1345345333 & (((uint32_t)1 << 31) - 1));
	}
	return count;
}

#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

struct fmt_main fmt_MYSQL_fast =
{
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ NULL },
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

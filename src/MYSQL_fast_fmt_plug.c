/* MYSQL_half_fmt.c
 *
 * Copyright (c) 2008 by <earthquake at rycon.hu>
 *
 * John the ripper MYSQL-fast module
 *
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"mysql-fast"
#define FORMAT_NAME			"MYSQL_fast"
#define ALGORITHM_NAME			"mysql-fast"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		16

#define BINARY_SIZE			8
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		64

static struct fmt_tests mysql_tests[] = {
	// ciphertext, plaintext
	{"445ff82636a7ba59", "probe"},
	{"60671c896665c3fa", "a"},
	{"1acbed4a27b20da3", "hash"},
	{"77ff75006118bab8", "hacker"},
	{"1b38cd9c2f809809", "hacktivity2008"},
	{"1b38cd9c2f809809", "hacktivity 2008"},
	{"6fc81597422015a8", "johnmodule"},
	{NULL}
};

static ARCH_WORD_32 crypt_key[MAX_KEYS_PER_CRYPT][BINARY_SIZE / 4];
static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];

static int mysql_valid(char* ciphertext, struct fmt_main *pFmt)
{
	unsigned int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;

	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
	{
		if (!(((ciphertext[i] >= '0') && (ciphertext[i] <= '9')) ||
			((ciphertext[i] >= 'a') && (ciphertext[i] <= 'f')) ||
			((ciphertext[i] >= 'A') && (ciphertext[i] <= 'F')))
				)
			return 0;
	}

	return 1;
}

static void* mysql_get_binary(char* ciphertext)
{
	static unsigned long buff_[BINARY_SIZE / sizeof(unsigned long)];
	unsigned char *buff = (unsigned char *)buff_;
	unsigned int i;

	for (i = 0; i < BINARY_SIZE / 2; i++)
	{
#if ARCH_LITTLE_ENDIAN == 1
		buff[((BINARY_SIZE / 2) - 1) - i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 + atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
#else
		buff[i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 + atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
#endif
	}

	return buff;
}

static void mysql_set_key(char* key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char* mysql_get_key(int index)
{
	return saved_key[index];
}

static int mysql_cmp_one(void* binary, int index)
{
	return *(ARCH_WORD_32 *)binary == crypt_key[index][0];
}

static int mysql_cmp_all(void* binary, int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (*(ARCH_WORD_32 *)binary == crypt_key[i][0])
			return 1;
	}

	return 0;
}

static int mysql_cmp_exact(char* source, int index)
{
	register unsigned long nr = 1345345333L, add = 7, nr2 = 0x12345671L;
	register unsigned long tmp;
	char* password;
	char ctmp[CIPHERTEXT_LENGTH+1];

	password = saved_key[index];
	for (; *password; password++)
	{
		if (*password == ' ' || *password == '\t')
			continue;

		tmp = (unsigned long) (unsigned char) *password;
		nr ^= (((nr & 63) + add) * tmp) + (nr << 8);
		nr2 += (nr2 << 8) ^ nr;
		add += tmp;
	}

	sprintf(ctmp, "%08lx%08lx", (nr & (((unsigned long) 1L << 31) -1L)), (nr2 & (((unsigned long) 1L << 31) -1L)));
	return !memcmp(source, ctmp, CIPHERTEXT_LENGTH);
}

static void mysql_crypt_all(int count)
{
	unsigned long nr, add;
	unsigned long tmp;
	unsigned int i;
	char* password;

	for (i = 0; i < count; i++)
	{
		nr=1345345333L;
		add=7;

		password = saved_key[i];
		for (; *password; password++)
		{
			if (*password == ' ' || *password == '\t')
				continue;

			tmp = (unsigned long) (unsigned char) *password;
			nr ^= (((nr & 63) + add) * tmp) + (nr << 8);
			add += tmp;
		}

		crypt_key[i][0] = (nr & (((ARCH_WORD_32)1 << 31) - 1));
	}
}

int mysql_binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

int mysql_binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

int mysql_binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

int mysql_binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

int mysql_binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

int mysql_get_hash_0(int index)
{
	return crypt_key[index][0] & 0xF;
}

int mysql_get_hash_1(int index)
{
	return crypt_key[index][0] & 0xFF;
}

int mysql_get_hash_2(int index)
{
	return crypt_key[index][0] & 0xFFF;
}

int mysql_get_hash_3(int index)
{
	return crypt_key[index][0] & 0xFFFF;
}

int mysql_get_hash_4(int index)
{
	return crypt_key[index][0] & 0xFFFFF;
}

struct fmt_main fmt_MYSQL_fast =
{
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
		FMT_CASE | FMT_8_BIT,
		mysql_tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		mysql_valid,
		fmt_default_split,
		mysql_get_binary,
		fmt_default_salt,
		{
			mysql_binary_hash_0,
			mysql_binary_hash_1,
			mysql_binary_hash_2,
			mysql_binary_hash_3,
			mysql_binary_hash_4
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		mysql_set_key,
		mysql_get_key,
		fmt_default_clear_keys,
		mysql_crypt_all,
		{
			mysql_get_hash_0,
			mysql_get_hash_1,
			mysql_get_hash_2,
			mysql_get_hash_3,
			mysql_get_hash_4
		},
		mysql_cmp_all,
		mysql_cmp_one,
		mysql_cmp_exact
	}
};

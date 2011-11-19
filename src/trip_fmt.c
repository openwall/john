/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2011 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "DES_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"trip"
#define FORMAT_NAME			"Tripcode DES"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		8
#define CIPHERTEXT_LENGTH		10

static struct fmt_tests tests[] = {
	{"Rk7VUsDT2U", "simpson"},
	{"3GqYIJ3Obs", "tripcode"},
	{NULL}
};

#define ALGORITHM_NAME			DES_STD_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		0x40
#if DES_128K
#define MAX_KEYS_PER_CRYPT		0x100
#else
#define MAX_KEYS_PER_CRYPT		0x80
#endif

static struct {
	union {
		double dummy;
		DES_binary binary;
	} aligned;
	char key[PLAINTEXT_LENGTH];
} buffer[MAX_KEYS_PER_CRYPT];

static DES_binary binary_mask;
static unsigned char salt_map[0x100];

static void init(void)
{
	char fake_crypt[14];
	ARCH_WORD *alt_binary;
	int i;

	DES_std_init();

	memset(fake_crypt, '.', 13);
	fake_crypt[13] = 0;
	memcpy(binary_mask, DES_std_get_binary(fake_crypt),
	    sizeof(binary_mask));

	fake_crypt[2] = 'z';
	alt_binary = DES_std_get_binary(fake_crypt);

	for (i = 0; i < 16 / DES_SIZE; i++) {
		binary_mask[i] ^= ~alt_binary[i];
		binary_mask[i] &= DES_BINARY_MASK;
	}

	for (i = 0; i < 0x100; i++) {
		char *from = ":;<=>?@[\\]^_`";
		char *to = "ABCDEFGabcdef";
		char *p;
		if (atoi64[i] != 0x7F)
			salt_map[i] = i;
		else if ((p = strchr(from, i)))
			salt_map[i] = to[p - from];
		else
			salt_map[i] = '.';
	}
}

static int valid(char *ciphertext)
{
	char *pos;

	for (pos = ciphertext; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++)
		;
	if (*pos || pos - ciphertext != CIPHERTEXT_LENGTH)
		return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 3)
		return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	char fake_crypt[14];

	fake_crypt[0] = '.';
	fake_crypt[1] = '.';
	fake_crypt[2] = '.';
	memcpy(&fake_crypt[3], ciphertext, 11);

	return DES_std_get_binary(fake_crypt);
}

static int binary_hash_0(void *binary)
{
	return DES_STD_HASH_0(*(ARCH_WORD *)binary);
}

static int binary_hash_1(void *binary)
{
	return DES_STD_HASH_1(*(ARCH_WORD *)binary);
}

static int binary_hash_2(void *binary)
{
	return DES_STD_HASH_2(*(ARCH_WORD *)binary);
}

#define binary_hash_3 NULL
#define binary_hash_4 NULL
#define binary_hash_5 NULL
#define binary_hash_6 NULL

static int get_hash_0(int index)
{
	return DES_STD_HASH_0(buffer[index].aligned.binary[0]);
}

static int get_hash_1(int index)
{
	ARCH_WORD binary;

	binary = buffer[index].aligned.binary[0];
	return DES_STD_HASH_1(binary);
}

static int get_hash_2(int index)
{
	ARCH_WORD binary;

	binary = buffer[index].aligned.binary[0];
	return DES_STD_HASH_2(binary);
}

#define get_hash_3 NULL
#define get_hash_4 NULL
#define get_hash_5 NULL
#define get_hash_6 NULL

static void crypt_all(int count)
{
	int index;

	for (index = 0; index < count; index++) {
		static ARCH_WORD prev_salt = -1;
		ARCH_WORD salt;
		unsigned ARCH_WORD *out;
		char fake_crypt[14];

		if (!buffer[index].key[0]) {
			fake_crypt[0] = '.';
			fake_crypt[1] = '.';
		} else
		if (!buffer[index].key[1]) {
			fake_crypt[0] = 'H';
			fake_crypt[1] = '.';
		} else
		if (!buffer[index].key[2]) {
			fake_crypt[0] =
			    salt_map[ARCH_INDEX(buffer[index].key[1])];
			fake_crypt[1] = 'H';
		} else {
			fake_crypt[0] =
			    salt_map[ARCH_INDEX(buffer[index].key[1])];
			fake_crypt[1] =
			    salt_map[ARCH_INDEX(buffer[index].key[2])];
		}
		fake_crypt[13] = 0;
		salt = DES_std_get_salt(fake_crypt);
		if (salt != prev_salt)
			DES_std_set_salt(prev_salt = salt);

		DES_std_set_key(buffer[index].key);

		DES_std_crypt(DES_KS_current,
		    out = buffer[index].aligned.binary);

		{
			ARCH_WORD mask;
#if ARCH_BITS < 64
			mask = (out[0] ^ out[1]) & salt;
			out[0] ^= mask;
			out[1] ^= mask;
			mask = (out[2] ^ out[3]) & salt;
			out[2] ^= mask;
			out[3] ^= mask;
#else
			mask = (out[0] ^ (out[0] >> 32)) & salt;
			out[0] ^= mask ^ (mask << 32);
			mask = (out[1] ^ (out[1] >> 32)) & salt;
			out[1] ^= mask ^ (mask << 32);
#endif
		}
		out[0] &= binary_mask[0];
	}
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
	if (*(unsigned ARCH_WORD *)binary == buffer[index].aligned.binary[0])
		return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *(unsigned ARCH_WORD *)binary == buffer[index].aligned.binary[0];
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD *binary;
	int word;

	binary = get_binary(source);

	for (word = 0; word < 16 / DES_SIZE; word++)
	if ((unsigned ARCH_WORD)binary[word] !=
	    (buffer[index].aligned.binary[word] & binary_mask[word]))
		return 0;

	return 1;
}

static void set_key(char *key, int index)
{
	memcpy(buffer[index].key, key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

	memcpy(out, buffer[index].key, PLAINTEXT_LENGTH);
	out[PLAINTEXT_LENGTH] = 0;

	return out;
}

struct fmt_main fmt_trip = {
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
		FMT_CASE,
		tests
	}, {
		init,
		valid,
		fmt_default_split,
		get_binary,
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

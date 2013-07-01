/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2010-2012 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "DES_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"bsdicrypt"
#define FORMAT_NAME			"BSDI crypt(3)"

#define BENCHMARK_COMMENT		" (\"_J9..\", 725 iterations)"
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		64
#define CIPHERTEXT_LENGTH		20

static struct fmt_tests tests[] = {
	{"_J9..CCCCXBrJUJV154M", "U*U*U*U*"},
	{"_J9..CCCCXUhOBTXzaiE", "U*U***U"},
	{"_J9..CCCC4gQ.mB/PffM", "U*U***U*"},
	{"_J9..XXXXvlzQGqpPPdk", "*U*U*U*U"},
	{"_J9..XXXXsqM/YSSP..Y", "*U*U*U*U*"},
	{"_J9..XXXXVL7qJCnku0I", "*U*U*U*U*U*U*U*U"},
	{"_J9..XXXXAj8cFbP5scI", "*U*U*U*U*U*U*U*U*"},
	{"_J9..SDizh.vll5VED9g", "ab1234567"},
	{"_J9..SDizRjWQ/zePPHc", "cr1234567"},
	{"_J9..SDizxmRI1GjnQuE", "zxyDPWgydbQjgq"},
	{"_K9..SaltNrQgIYUAeoY", "726 even"},
	{"_J9..SDSD5YGyRCr4W4c", ""},
	{NULL}
};

#if DES_BS

#include "DES_bs.h"

#define ALGORITHM_NAME			DES_BS_ALGORITHM_NAME

#define BINARY_SIZE			sizeof(ARCH_WORD_32)
#define BINARY_ALIGN			sizeof(ARCH_WORD_32)
#define SALT_SIZE			(ARCH_SIZE * 2)
#define SALT_ALIGN			ARCH_SIZE

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		DES_BS_DEPTH

#else

#define ALGORITHM_NAME			DES_STD_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define BINARY_ALIGN			ARCH_SIZE
#define SALT_SIZE			(ARCH_SIZE * 2)
#define SALT_ALIGN			ARCH_SIZE

#define MIN_KEYS_PER_CRYPT		4
#define MAX_KEYS_PER_CRYPT		8

static ARCH_WORD saved_salt, current_salt;

#endif

static int saved_count;

static struct {
#if !DES_BS
	DES_KS KS;
	DES_binary binary;
#endif
	char key[PLAINTEXT_LENGTH];
} *buffer;

struct fmt_main fmt_BSDI;

static void init(struct fmt_main *self)
{
	DES_std_init();

#if DES_BS
	DES_bs_init(0, (DES_bs_cpt + 28) / 29);
#if DES_bs_mt
	fmt_BSDI.params.min_keys_per_crypt = DES_bs_min_kpc;
	fmt_BSDI.params.max_keys_per_crypt = DES_bs_max_kpc;
#endif

	DES_std_set_salt(0);
	DES_count = 1;
#else
	current_salt = -1;
#endif

	buffer = mem_alloc_tiny(
	    sizeof(*buffer) * fmt_BSDI.params.max_keys_per_crypt,
	    MEM_ALIGN_CACHE);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	if (ciphertext[0] != '_') return 0;

	for (pos = &ciphertext[1]; pos < &ciphertext[9]; pos++)
	if (!*pos) return 0;

	for (pos = &ciphertext[9]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos || pos - ciphertext != CIPHERTEXT_LENGTH) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 3) return 0;

	return 1;
}

static void *salt(char *ciphertext)
{
	static ARCH_WORD out[2];

#if DES_BS
	out[0] = DES_raw_get_salt(ciphertext);
#else
	out[0] = DES_std_get_salt(ciphertext);
#endif
	out[1] = DES_raw_get_count(ciphertext);

	return out;
}

#if DES_BS

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0x7FFFFFF;
}

#define get_hash_0 DES_bs_get_hash_0
#define get_hash_1 DES_bs_get_hash_1
#define get_hash_2 DES_bs_get_hash_2
#define get_hash_3 DES_bs_get_hash_3
#define get_hash_4 DES_bs_get_hash_4
#define get_hash_5 DES_bs_get_hash_5
#define get_hash_6 DES_bs_get_hash_6

static int salt_hash(void *salt)
{
	return *(ARCH_WORD *)salt & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	DES_bs_set_salt(*(ARCH_WORD *)salt);
	saved_count = ((ARCH_WORD *)salt)[1];
}

#else

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
	return DES_STD_HASH_0(buffer[index].binary[0]);
}

static int get_hash_1(int index)
{
	ARCH_WORD binary;

	binary = buffer[index].binary[0];
	return DES_STD_HASH_1(binary);
}

static int get_hash_2(int index)
{
	ARCH_WORD binary;

	binary = buffer[index].binary[0];
	return DES_STD_HASH_2(binary);
}

#define get_hash_3 NULL
#define get_hash_4 NULL
#define get_hash_5 NULL
#define get_hash_6 NULL

static int salt_hash(void *salt)
{
	return DES_STD_HASH_2(*(ARCH_WORD *)salt) & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	saved_salt = *(ARCH_WORD*)salt;
	saved_count = ((ARCH_WORD *)salt)[1];
}

#endif

static void set_key(char *key, int index)
{
	char *ptr, *chr;
	int pos, word;
	unsigned ARCH_WORD block[2];
	union {
		double dummy;
		DES_binary binary;
	} aligned;
	char chars[8];
#if DES_BS
	char *final = key;
#endif

	DES_std_set_key(key);

	for (pos = 0, ptr = key; pos < 8 && *ptr; pos++, ptr++);
	block[1] = block[0] = 0;

	while (*ptr) {
		ptr -= 8;
		for (word = 0; word < 2; word++)
		for (pos = 0; pos < 4; pos++)
			block[word] ^= (ARCH_WORD)*ptr++ << (1 + (pos << 3));

#if !DES_BS
		if (current_salt)
			DES_std_set_salt(current_salt = 0);
		DES_count = 1;
#endif

		DES_std_set_block(block[0], block[1]);
		DES_std_crypt(DES_KS_current, aligned.binary);
		DES_std_get_block(aligned.binary, block);

		chr = chars;
		for (word = 0; word < 2; word++)
		for (pos = 0; pos < 4; pos++) {
			*chr++ = 0x80 |
				((block[word] >> (1 + (pos << 3))) ^ *ptr);
			if (*ptr) ptr++;
		}

#if DES_BS
		final = chars;
		if (*ptr)
#endif
			DES_raw_set_key(chars);
	}

#if DES_BS
	DES_bs_set_key(final, index);
#else
	memcpy(buffer[index].KS, DES_KS_current, sizeof(DES_KS));
#endif
	strnfcpy(buffer[index].key, key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

	return strnzcpy(out, buffer[index].key, PLAINTEXT_LENGTH + 1);
}

#if DES_BS

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	DES_bs_crypt(saved_count, count);
	return count;
}

static int cmp_one(void *binary, int index)
{
	return DES_bs_cmp_one((ARCH_WORD_32 *)binary, 32, index);
}

static int cmp_exact(char *source, int index)
{
	return DES_bs_cmp_one(DES_bs_get_binary(source), 64, index);
}

#else

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

	if (current_salt != saved_salt)
		DES_std_set_salt(current_salt = saved_salt);

	memset(DES_IV, 0, sizeof(DES_IV));
	DES_count = saved_count;

	for (index = 0; index < count; index++)
		DES_std_crypt(buffer[index].KS, buffer[index].binary);

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
	if (*(unsigned ARCH_WORD *)binary ==
	    (buffer[index].binary[0] & DES_BINARY_MASK))
		return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *(unsigned ARCH_WORD *)binary ==
		(buffer[index].binary[0] & DES_BINARY_MASK);
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD *binary;
	int word;

	binary = DES_std_get_binary(source);

	for (word = 0; word < 16 / DES_SIZE; word++)
	if ((unsigned ARCH_WORD)binary[word] !=
	    (buffer[index].binary[word] & DES_BINARY_MASK))
		return 0;

	return 1;
}

#endif

struct fmt_main fmt_BSDI = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#if DES_BS && DES_bs_mt
		FMT_OMP |
#endif
#if DES_BS
		FMT_CASE | FMT_BS,
#else
		FMT_CASE,
#endif
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		(void *(*)(char *))
#if DES_BS
			DES_bs_get_binary,
#else
			DES_std_get_binary,
#endif
		salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
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
#if DES_BS
		(int (*)(void *, int))DES_bs_cmp_all,
#else
		cmp_all,
#endif
		cmp_one,
		cmp_exact
	}
};

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "DES_bs.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"lm"
#define FORMAT_NAME			"NT LM DES"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		7
#define CIPHERTEXT_LENGTH		32

#define LM_EMPTY			"AAD3B435B51404EE"
#define LM_EMPTY_LOWER			"aad3b435b51404ee"

static struct fmt_tests tests[] = {
	{"$LM$A9C604D244C4E99D", "AAAAAA"},
	{"$LM$CBC501A4D2227783", "AAAAAAA"},
	{"$LM$3466C2B0487FE39A", "CRACKPO"},
	{"$LM$DBC5E5CBA8028091", "IMPUNIT"},
	{LM_EMPTY LM_EMPTY, ""},
	{"$LM$73CC402BD3E79175", "SCLEROS"},
	{"$LM$5ECD9236D21095CE", "YOKOHAM"},
	{"$LM$A5E6066DE61C3E35", "ZZZZZZZ"},
	{"$LM$1FB363FEB834C12D", "ZZZZZZ"},
	{NULL}
};

#define ALGORITHM_NAME			DES_BS_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		DES_BS_DEPTH

static void init(void)
{
	DES_bs_init(1);
}

static int valid(char *ciphertext)
{
	char *pos;
	char lower[CIPHERTEXT_LENGTH - 16 + 1];

	for (pos = ciphertext; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH) {
		strcpy(lower, &ciphertext[16]);
		strlwr(lower);
		if (strcmp(lower, LM_EMPTY_LOWER))
			return 2;
		else
			return 1;
	}

	if (strncmp(ciphertext, "$LM$", 4)) return 0;

	for (pos = &ciphertext[4]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos || pos - ciphertext != 20) return 0;

	return 1;
}

static char *split(char *ciphertext, int index)
{
	static char out[21];

	if (!strncmp(ciphertext, "$LM$", 4)) return ciphertext;

	out[0] = '$';
	out[1] = 'L';
	out[2] = 'M';
	out[3] = '$';

	if (index)
		memcpy(&out[4], &ciphertext[16], 16);
	else
		memcpy(&out[4], ciphertext, 16);

	out[20] = 0;
	return out;
}

static void *get_binary(char *ciphertext)
{
	return DES_bs_get_binary_LM(ciphertext + 4);
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD *)binary & 0xFFF;
}

static int get_hash_0(int index)
{
	return DES_bs_get_hash(index, 4);
}

static int get_hash_1(int index)
{
	return DES_bs_get_hash(index, 8);
}

static int get_hash_2(int index)
{
	return DES_bs_get_hash(index, 12);
}

static void set_salt(void *salt)
{
}

static int cmp_all(void *binary, int count)
{
	return DES_bs_cmp_all((ARCH_WORD *)binary);
}

static int cmp_one(void *binary, int index)
{
	return DES_bs_cmp_one((ARCH_WORD *)binary, 32, index);
}

static int cmp_exact(char *source, int index)
{
	return DES_bs_cmp_one(get_binary(source), 64, index);
}

static char *get_key(int index)
{
#if !DES_BS_VECTOR && ARCH_BITS >= 64
	return (char *)DES_bs_all.E.extras.keys[index];
#else
	return (char *)DES_bs_all.keys[index];
#endif
}

struct fmt_main fmt_LM = {
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
		FMT_8_BIT | FMT_BS,
		tests
	}, {
		init,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2
		},
		fmt_default_salt_hash,
		set_salt,
		DES_bs_set_key_LM,
		get_key,
		DES_bs_clear_keys_LM,
		(void (*)(int))DES_bs_crypt_LM,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

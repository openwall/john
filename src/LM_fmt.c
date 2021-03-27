/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005,2010-2012,2017 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "DES_bs.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"LM"
#define FORMAT_NAME			""
#define FORMAT_TAG			"$LM$"
#define FORMAT_TAG_LEN			(sizeof(FORMAT_TAG)-1)

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		7
#define CIPHERTEXT_LENGTH		32

#define LM_EMPTY			"aad3b435b51404ee"

static struct fmt_tests tests[] = {
	{"$LM$a9c604d244c4e99d", "aaaaaa"},
	{"$LM$cbc501a4d2227783", "AAAAAAA"},
	{"$LM$3466c2b0487fe39a", "CRACKPO"},
	{"$LM$dbc5e5cba8028091", "impunit"},
	{LM_EMPTY LM_EMPTY, ""},
	{"$LM$73cc402bd3e79175", "SCLEROS"},
	{"$LM$5ecd9236d21095ce", "YOKOHAM"},
	{"$LM$A5E6066DE61C3E35", "ZZZZZZZ"}, /* uppercase encoding */
	{"$LM$1FB363feB834C12D", "ZZZZZZ"}, /* mixed case encoding */
	{"$LM$fea4ab7d7b7d0452", "0688648"},

	{NULL}
};

#define ALGORITHM_NAME			DES_BS_ALGORITHM_NAME

#define BINARY_SIZE			(sizeof(uint32_t) * 2)
#define BINARY_ALIGN			sizeof(uint32_t)
#define SALT_SIZE			0
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		DES_BS_DEPTH

#if DES_bs_mt
struct fmt_main fmt_LM;
#endif

static void init(struct fmt_main *self)
{
	DES_bs_init(1, DES_bs_cpt);
#if DES_bs_mt
	fmt_LM.params.min_keys_per_crypt = DES_bs_min_kpc;
	fmt_LM.params.max_keys_per_crypt = DES_bs_max_kpc;
#endif
}

static char *prepare(char *fields[10], struct fmt_main *self)
{
	if (fields[1][0] != '$' && fields[2] && strlen(fields[2]) == 32)
		return fields[2];
	return fields[1];
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;
	char lower[CIPHERTEXT_LENGTH - 16 + 1];

	for (pos = ciphertext; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH) {
		strcpy(lower, &ciphertext[16]);
		strlwr(lower);
		if (strcmp(lower, LM_EMPTY))
			return 2;
		else
			return 1;
	}

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) return 0;

	for (pos = &ciphertext[FORMAT_TAG_LEN]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos || pos - ciphertext != 20) return 0;

	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[21];

/* We don't just "return ciphertext" for already split hashes since we may
 * need to convert hashes stored by older versions of John to all-lowercase. */
	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		ciphertext += FORMAT_TAG_LEN;

	memcpy(out, FORMAT_TAG, FORMAT_TAG_LEN);

	if (index)
		memcpylwr(&out[FORMAT_TAG_LEN], &ciphertext[16], 16);
	else
		memcpylwr(&out[FORMAT_TAG_LEN], ciphertext, 16);

	out[20] = 0;

	return out;
}

static void *binary(char *ciphertext)
{
	return DES_bs_get_binary_LM(ciphertext + FORMAT_TAG_LEN);
}

static char *source(char *source, void *binary)
{
	return split(DES_bs_get_source_LM(binary), 0, NULL);
}

static int binary_hash_0(void *binary)
{
	return *(uint32_t *)binary & PH_MASK_0;
}

static int binary_hash_1(void *binary)
{
	return *(uint32_t *)binary & PH_MASK_1;
}

static int binary_hash_2(void *binary)
{
	return *(uint32_t *)binary & PH_MASK_2;
}

static int binary_hash_3(void *binary)
{
	return *(uint32_t *)binary & PH_MASK_3;
}

static int binary_hash_4(void *binary)
{
	return *(uint32_t *)binary & PH_MASK_4;
}

static int binary_hash_5(void *binary)
{
	return *(uint32_t *)binary & PH_MASK_5;
}

static int binary_hash_6(void *binary)
{
	return *(uint32_t *)binary & PH_MASK_6;
}

static int cmp_one(void *binary, int index)
{
	return DES_bs_cmp_one((uint32_t *)binary, 64, index);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static char *get_key(int index)
{
	static char out[8];
	unsigned char *src;
	char *dst;

	init_t();

	src = DES_bs_all.pxkeys[index];
	dst = out;
	while (dst < &out[7] && (*dst = *src)) {
		src += sizeof(DES_bs_vector) * 8;
		dst++;
	}
	*dst = 0;

	return out;
}

struct fmt_main fmt_LM = {
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
/*
 * Do not add FAST_FORMATS_OMP checks to LM, because its use of OpenMP is in
 * code shared with other formats.
 */
#if DES_bs_mt
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_8_BIT | FMT_TRUNC | FMT_BS | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		prepare,
		valid,
		split,
		binary,
		fmt_default_salt,
		{ NULL },
		source,
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
		NULL,
		fmt_default_set_salt,
		DES_bs_set_key_LM,
		get_key,
		fmt_default_clear_keys,
		DES_bs_crypt_LM,
		{
			DES_bs_get_hash_0,
			DES_bs_get_hash_1,
			DES_bs_get_hash_2,
			DES_bs_get_hash_3,
			DES_bs_get_hash_4,
			DES_bs_get_hash_5,
			DES_bs_get_hash_6
		},
		(int (*)(void *, int))DES_bs_cmp_all,
		cmp_one,
		cmp_exact
	}
};

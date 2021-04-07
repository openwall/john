/*
 * This file is part of John the Ripper password cracker,
 * based on rawSHA256_fmt.c code
 *
 * This software is Copyright (c) 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * The DragonFly BSD 2.10.1-REL crypt-sha2 hashes are seriously broken. See
 * http://www.openwall.com/lists/john-dev/2012/01/16/1
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_dragonfly3_32;
extern struct fmt_main fmt_dragonfly3_64;
#elif FMT_REGISTERS_H
john_register_one(&fmt_dragonfly3_32);
john_register_one(&fmt_dragonfly3_64);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "sha2.h"

#define FORMAT_LABEL_32			"dragonfly3-32"
#define FORMAT_LABEL_64			"dragonfly3-64"
#define FORMAT_NAME_32			"DragonFly BSD $3$ w/ bug, 32-bit"
#define FORMAT_NAME_64			"DragonFly BSD $3$ w/ bug, 64-bit"
#define ALGORITHM_NAME			"SHA256 32/" ARCH_BITS_STR
#define FORMAT_TAG				"$3$"
#define FORMAT_TAG_LEN			(sizeof(FORMAT_TAG)-1)

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		44

#define BINARY_SIZE			32
#define BINARY_ALIGN			4
#define SALT_SIZE_32			(1+4+8)	// 1st char is length
#define SALT_SIZE_64			(1+8+8)
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		64

#ifndef OMP_SCALE
#define OMP_SCALE			4  // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests_32[] = {
	{"$3$z$EBG66iBCGfUfENOfqLUH/r9xQxI1cG373/hRop6j.oWs", "magnum"},
	{"$3$f6daU5$Xf/u8pKp.sb4VCLKz7tTZMUKJ3J4oOfZgUSHYOFL.M0n", ""},
	{"$3$PNPA2tJ$ppD4bXqPMYFVdYVYrxXGMWeYB6Xv8e6jmXbvrB5V.okl", "password"},
	{"$3$jWhDSrS$bad..Dy7UAyabPyfrEi3fgQ2qtT.5fE7C5EMNo/n.Qk5", "John the Ripper"},
	{"$3$SSYEHO$hkuDmUQHT2Tr0.ai.lUVyb9bCC875Up.CZVa6UJZ.Muv", "DragonFly BSD"},
	{"$3$pomO$a2ltqo.LlUSt1DG68sv2FZOdLcul0gYQ3xmn6z0G.I6Y", "123"},
	{"$3$F$8Asqp58WwQ3WDMhaR3yQMSJGdCtpBqckemkCSNnJ.gRr", "12345678"},
	{NULL}
};

static struct fmt_tests tests_64[] = {
	{"$3$z$sNV7KLtLxvJRsj2MfBtGZFuzXP3CECITaFq/rvsy.Y.Q", "magnum"},
	{"$3$f6daU5$eV2SX9vUHTMsoy3Ic7cWiQ4mOxyuyenGjYQWkJmy.AF3", ""},
	{"$3$PNPA2tJ$GvXjg6zSge3YDh5I35JlYZHoQS2r0/.vn36fQzSY.A0d", "password"},
	{"$3$jWhDSrS$5yBH7KFPmsg.PhPeDMj1MY4fv9061zdbYumPe2Ve.Y5J", "John the Ripper"},
	{"$3$SSYEHO$AMYLyanRYs8F2U07FsBrSFuOIygJ4kgqvpBB17BI.61N", "DragonFly BSD"},
	{"$3$e$TzMK1ePmjnZI/YbGes/1PAKqbj8aOV31Hf8Tz9es.kkq", "123"},
	{"$3$XcMa$idKoaBQXdRlhfJFDjnV0jDryW/nEBAGXONyzJvnH.cR3", "12345678"},
	{NULL}
};

static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)
    [(BINARY_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
static char *cur_salt;
static int salt_len;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos, *start;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ciphertext += FORMAT_TAG_LEN;

	for (pos = ciphertext; *pos && *pos != '$'; pos++);
	if (!*pos || pos < ciphertext || pos > &ciphertext[8]) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;

	return 1;
}

#define TO_BINARY(b1, b2, b3) \
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

static void *get_binary(char *ciphertext)
{
	static uint32_t outbuf[BINARY_SIZE/4];
	uint32_t value;
	char *pos;
	unsigned char *out = (unsigned char*)outbuf;
	int i;

	pos = strrchr(ciphertext, '$') + 1;

	for (i = 0; i < 10; i++) {
		TO_BINARY(i, i + 11, i + 21);
	}
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) |
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) |
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18);
	out[10] = value >> 16;
	out[31] = value >> 8;

	return (void *)out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		SHA256_CTX ctx;

		SHA256_Init(&ctx);

		/* First the password */
		SHA256_Update(&ctx, saved_key[index], saved_len[index]);

		/* Then the salt, including the $3$ magic */
		SHA256_Update(&ctx, cur_salt, salt_len);

		SHA256_Final((unsigned char*)crypt_out[index], &ctx);
	}

	return count;
}

static void set_salt(void *salt)
{
	salt_len = (int)*(char*)salt;
	cur_salt = (char*)salt + 1;
}

// For 32-bit version of the bug, our magic is "$3$\0" len 4
static void *get_salt_32(char *ciphertext)
{
	static char *out;
	int len;

	if (!out) out = mem_alloc_tiny(SALT_SIZE_32, MEM_ALIGN_WORD);

	memset(out, 0, SALT_SIZE_32);
	ciphertext += FORMAT_TAG_LEN;
	strcpy(&out[1], FORMAT_TAG);
	for (len = 0; ciphertext[len] != '$'; len++);

	memcpy(&out[5], ciphertext, len);
	out[0] = len + 4;

	return out;
}

// For 64-bit version of the bug, our magic is "$3$\0sha5" len 8
static void *get_salt_64(char *ciphertext)
{
	static char *out;
	int len;

	if (!out) out = mem_alloc_tiny(SALT_SIZE_64, MEM_ALIGN_WORD);

	memset(out, 0, SALT_SIZE_64);
	ciphertext += FORMAT_TAG_LEN;
	memcpy(&out[1], "$3$\0sha5", 8);
	for (len = 0; ciphertext[len] != '$'; len++);

	memcpy(&out[9], ciphertext, len);
	out[0] = len + 8;

	return out;
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

// Public domain hash function by DJ Bernstein
static int salt_hash(void *salt)
{
	unsigned char *s = (unsigned char*)salt + 1;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < *(unsigned char*)salt; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_dragonfly3_32 = {
	{
		FORMAT_LABEL_32,
		FORMAT_NAME_32,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE_32,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ FORMAT_TAG },
		tests_32
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt_32,
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
		salt_hash,
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

struct fmt_main fmt_dragonfly3_64 = {
	{
		FORMAT_LABEL_64,
		FORMAT_NAME_64,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE_64,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ NULL },
		tests_64
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt_64,
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
		salt_hash,
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

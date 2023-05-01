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
extern struct fmt_main fmt_dragonfly4_32;
extern struct fmt_main fmt_dragonfly4_64;
#elif FMT_REGISTERS_H
john_register_one(&fmt_dragonfly4_32);
john_register_one(&fmt_dragonfly4_64);
#else

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "sha2.h"

#define FORMAT_LABEL_32			"dragonfly4-32"
#define FORMAT_LABEL_64			"dragonfly4-64"
#define FORMAT_NAME_32			"DragonFly BSD $4$ w/ bugs, 32-bit"
#define FORMAT_NAME_64			"DragonFly BSD $4$ w/ bugs, 64-bit"
#define FORMAT_TAG				"$4$"
#define FORMAT_TAG_LEN			(sizeof(FORMAT_TAG)-1)
#if ARCH_BITS >= 64
#define ALGORITHM_NAME			"SHA512 64/" ARCH_BITS_STR
#else
#define ALGORITHM_NAME			"SHA512 32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		84

#define BINARY_SIZE			64
#define BINARY_ALIGN			4
#define USED_BINARY_SIZE		62	// Due to base64 bug in DragonBSD crypt-sha512.c
#define SALT_SIZE_32			(1+4+8)	// 1st char is length
#define SALT_SIZE_64			(1+8+8)
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		128

#ifndef OMP_SCALE
#define OMP_SCALE			2  // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests_32[] = {
	{"$4$7E48ul$K4u43llx1P184KZBoILl2hnFLBHj6.486TtxWA.EA1pLZuQS7P5k0LQqyEULux47.5vttDbSo/Cbpsez.AUI", "magnum"},
	{"$4$Hz$5U1s18ntUYE24mF3JN44BYZPN34HBCMw57.Yw2JeKoiBkTVSGBDZEPT325hvR7iw8QYHy9kG7WUW8LCM.6UD", ""},
	{"$4$W$79ddF.iDXVPcf/uf8bMFl15leilo1GE8C2KnEAWs3isK930rVy1EZZS2veHgU17NRt4qpKTtZRCA.QC7.68j", "password"},
	{"$4$dw7uRHW$Cs6rbZqAVEEp9dsYOl4w/U84YydqdsEYyxHNvAtd2bcLz2Eem9L7FI/aGD2ayAybmprtYZLq2AtdXBio.cX0", "John the Ripper"},
	{"$4$2tgCi76D$zy7ms.v1Y8HcsasTaR8n/Ng8GH4dhPv4ozihbM4JMNSJUmw7wVKbcqksefn7nVT.WrN18fV8i1yh7Gmq.cXC", "DragonFly BSD"},
	{NULL}
};

static struct fmt_tests tests_64[] = {
	{"$4$7E48ul$9or6.L/T.iChtPIGY4.vIgdYEmMkTW7Ru4OJxtGJtonCQo.wu3.bS4UPlUc2B8CAfGo1Oi5PgQvfhzNQ.A8v", "magnum"},
	{"$4$Hz$Mujq0GrjuRtPhcM/0rOfbr2l9fXGfVwKAuL9oL5IH.RnOO1zcgG/S6rSIrebK4g0BEgKGKc0zmWpnk3O..uR", ""},
	{"$4$W$.eHqh7OeyhVkBG0lCuUFnEShQq3tZt1QOLUx/9vIt3p56rUMCu2w7iQof7HwWa1pJwcBpPG.7KK3Pcce.oFX", "password"},
	{"$4$dw7uRHW$17b2EzV3m0ziCLQoSKzUElTVgkL7cHXQzZzeeuNnkee/bchs0VHGqzjXrMZtWVfK2OW8.GfHvtZgzqGF.IUZ", "John the Ripper"},
	{"$4$2tgCi76D$NL8CBWreQkoaVeGVL/a27ZrwYq6M8mlNt.uqc9E9.OiANu6JHdQy2r6J4uAZuD7wKqAQier1YVL7M0IF.gvi", "DragonFly BSD"},
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

// Don't copy this code without realising it mimics bugs in the original code!
// We are actually missing the last 16 bits with this implementation.
static void *get_binary(char *ciphertext)
{
	static uint32_t outbuf[BINARY_SIZE/4];
	uint32_t value;
	char *pos;
	unsigned char *out = (unsigned char*)outbuf;
	int i;

	memset(outbuf, 0, sizeof(outbuf));
	pos = strrchr(ciphertext, '$') + 1;

	for (i = 0; i < 20; i++) {
		TO_BINARY(i, i + 21, i + 42);
	}
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) |
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) |
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18);
	out[20] = value >> 16;
	out[41] = value >> 8;

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
		SHA512_CTX ctx;

		SHA512_Init(&ctx);

		/* First the password */
		SHA512_Update(&ctx, saved_key[index], saved_len[index]);

		/* Then the salt, including the $4$ magic */
		SHA512_Update(&ctx, cur_salt, salt_len);

		SHA512_Final((unsigned char*)crypt_out[index], &ctx);
	}

	return count;
}

static void set_salt(void *salt)
{
	salt_len = (int)*(char*)salt;
	cur_salt = (char*)salt + 1;
}

// For 32-bit version of the bug, our magic is "$4$\0"
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

// For 64-bit version of the bug, our magic is "$4$\0/etc"
static void *get_salt_64(char *ciphertext)
{
	static char *out;
	int len;

	if (!out) out = mem_alloc_tiny(SALT_SIZE_64, MEM_ALIGN_WORD);

	memset(out, 0, SALT_SIZE_64);
	ciphertext += FORMAT_TAG_LEN;
	memcpy(&out[1], "$4$\0/etc", 8);
	for (len = 0; ciphertext[len] != '$'; len++);

	memcpy(&out[9], ciphertext, len);
	out[0] = len + 8;

	return out;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], USED_BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], USED_BINARY_SIZE);
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

struct fmt_main fmt_dragonfly4_32 = {
	{
		FORMAT_LABEL_32,
		FORMAT_NAME_32,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		USED_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE_32,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
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

struct fmt_main fmt_dragonfly4_64 = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
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

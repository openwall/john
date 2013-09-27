/*
 * This software is Copyright (c) 2012 magnum and Copyright (c) 2013 Dhiru
 * Kholia, and it is hereby released to the general public under the following
 * terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on hmac-md5 by Bartavelle
 *
 * ipmi_dumphashes (metasploit) can dump hashes in JtR format.
 */

#include "sha2.h"

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL			"RAKP"
#define FORMAT_NAME			""
#define FORMAT_TAG			"$rakp$"
#define TAG_LENGTH			6

#define ALGORITHM_NAME			"IPMI 2.0 RAKP (RMCP+) HMAC-SHA1 32/" ARCH_BITS_STR " " SHA2_LIB

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125

#define PAD_SIZE			64
#define BINARY_SIZE			20
#define BINARY_ALIGN			1
#define SALT_SIZE			sizeof(struct custom_salt)
#define SALT_ALIGN			1

#define SALT_MIN_SIZE                   56

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#define HEXCHARS			"0123456789abcdef"

static struct fmt_tests tests[] = {
	{"$rakp$a4a3a2a03f0b000094272eb1ba576450b0d98ad10727a9fb0ab83616e099e8bf5f7366c9c03d36a3000000000000000000000000000000001404726f6f74$0ea27d6d5effaa996e5edc855b944e179a2f2434", "calvin"},
	{"$rakp$c358d2a72f0c00001135f9b254c274629208b22f1166d94d2eba47f21093e9734355a33593da16f2000000000000000000000000000000001404726f6f74$41fce60acf2885f87fcafdf658d6f97db12639a9", "calvin"},
	{"$rakp$b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174$472bdabe2d5d4bffd6add7b3ba79a291d104a9ef", "hashcat"},
	/* dummy hash for testing long salts */
	{"$rakp$787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878$ba4ecc30a0b36a6ba0db862fc95201a81b9252ee", ""},
	{NULL}
};

static struct custom_salt {
	int length;
	unsigned char salt[128];
} *cur_salt;

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static unsigned char (*opad)[PAD_SIZE];
static unsigned char (*ipad)[PAD_SIZE];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	opad = mem_calloc_tiny(sizeof(*opad) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	ipad = mem_calloc_tiny(sizeof(*opad) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}


static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q = NULL;;
	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = strrchr(ciphertext, '$');
	if (!q)
		return 0;
	q = q + 1;
	if (strspn(q, HEXCHARS) != BINARY_SIZE * 2)
		return 0;

	if (strspn(p, HEXCHARS) > SALT_SIZE * 2)
		return 0;

	if ( (q - p) > SALT_SIZE * 2)
		return 0;

	if ( (q - p) < SALT_MIN_SIZE * 2)
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	ctcopy += 6;
	p = strtok(ctcopy, "$");
	cs.length = strlen(p) / 2;
	for (i = 0; i < cs.length; i++) {
		cs.salt[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}


static int get_hash_0(int index) { return crypt_key[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_key[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_key[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void set_key(char *key, int index)
{
	int len;
	int i;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	memset(ipad[index], 0x36, PAD_SIZE);
	memset(opad[index], 0x5C, PAD_SIZE);

	if (len > PAD_SIZE) {
		SHA_CTX ctx;
		unsigned char k0[BINARY_SIZE];

		SHA1_Init( &ctx );
		SHA1_Update( &ctx, key, len);
		SHA1_Final( k0, &ctx);

		len = BINARY_SIZE;

		for(i = 0; i < len; i++) {
			ipad[index][i] ^= k0[i];
			opad[index][i] ^= k0[i];
		}
	}
	else {
		for(i = 0; i < len; i++) {
			ipad[index][i] ^= key[i];
			opad[index][i] ^= key[i];
		}
	}
}

static char *get_key(int index)
{
	return saved_plain[index];
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_key[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_exact(char *source, int count)
{
	return (1);
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		SHA_CTX ctx;

		SHA1_Init( &ctx );
		SHA1_Update( &ctx, ipad[index], PAD_SIZE );
		SHA1_Update( &ctx, cur_salt->salt , cur_salt->length);
		SHA1_Final( (unsigned char*) crypt_key[index], &ctx);

		SHA1_Init( &ctx );
		SHA1_Update( &ctx, opad[index], PAD_SIZE );
		SHA1_Update( &ctx, crypt_key[index], BINARY_SIZE);
		SHA1_Final( (unsigned char*) crypt_key[index], &ctx);
	}
	return count;
}

// Public domain hash function by DJ Bernstein
static int salt_hash(void *salt)
{
	unsigned int hash = 5381;
	struct custom_salt *fck = (struct custom_salt *)salt;
	unsigned char *s = fck->salt;
	int length = fck->length / 4;

	while (length) {
		hash = ((hash << 5) + hash) ^ *s++;
		length--;
	}
	return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_rakp = {
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
		0,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

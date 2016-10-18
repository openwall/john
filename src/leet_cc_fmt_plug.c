/* Cracker for leet.cc hashes.
 *
 * hsh = bin2hex(hash("sha512", $password . $salt, true) ^ hash("whirlpool", $salt . $password, true))
 * $salt == username
 *
 * Input hash format: username:hash
 *
 * This software is Copyright (c) 2016, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_leet;
#elif FMT_REGISTERS_H
john_register_one(&fmt_leet);
#else

#include <string.h>
#include "sph_whirlpool.h"
#include "arch.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               128 // tuned on Core i7-6600U
#endif
static int omp_t = 1;
#endif
#include "memdbg.h"

#define FORMAT_LABEL            "leet"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "SHA-512 + Whirlpool/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             64
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(ARCH_WORD)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests leet_tests[] = {
	{"salt$f86036a85e3ff84e73bf10769011ecdbccbf5aaed9df0240310776b42f5bb8776e612ab15a78bbfc39e867448a08337d97427e182e72922bbaa903ee75b2bfd4", "password"},
	{"salt$f86036a85e3ff84e73bf10769011ecdbccbf5aaed9df0240310776b42f5bb8776e612ab15a78bbfc39e867448a08337d97427e182e72922bbaa903ee75b2bfd4", "password"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int saltlen;
	unsigned char salt[256];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_align(sizeof(*saved_key),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_len));
	crypt_out = mem_calloc_align(sizeof(*crypt_out), self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

// salt (username) is added to the ciphertext in the prepare function
static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	q = strchr(p, '$'); // end of salt
	if (!q)
		return 0;

	if (q - p > 256)
		return 0;

	q = strrchr(ciphertext, '$') + 1;
	if (strlen(q) != BINARY_SIZE * 2)
		goto err;
	if (!ishex(q))
		goto err;

	return 1;

err:
	return 0;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char* cp;

	if (!split_fields[0])
		return split_fields[1];
	if (strlen(split_fields[1]) != BINARY_SIZE * 2)
		return split_fields[1];
	cp = mem_alloc_tiny(strlen(split_fields[0]) + strlen(split_fields[1]) + 2, MEM_ALIGN_NONE);
	sprintf(cp, "%s$%s", split_fields[0], split_fields[1]);
	if (valid(cp, self)) {
		return cp;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p, *q;

	memset(&cs, 0, sizeof(cs));
	p = ciphertext;
	q = strrchr(ciphertext, '$');

	strncpy((char*)cs.salt, p, q - p);
	cs.saltlen = q - p;

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	int i;
	unsigned char *out = buf.c;
	char *p;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		int i;
		SHA512_CTX sctx;
		unsigned char *p;
		sph_whirlpool_context wctx;
		unsigned char output1[64], output2[64];

		SHA512_Init(&sctx);
		SHA512_Update(&sctx, saved_key[index], saved_len[index]);
		SHA512_Update(&sctx, cur_salt->salt, cur_salt->saltlen);
		SHA512_Final(output1, &sctx);

		sph_whirlpool_init(&wctx);
		sph_whirlpool(&wctx, cur_salt->salt, cur_salt->saltlen);
		sph_whirlpool(&wctx, saved_key[index], saved_len[index]);
		sph_whirlpool_close(&wctx, output2);

		p = (unsigned char*)crypt_out[index];
		for (i = 0; i < 16; i++)
			p[i] = output1[i] ^ output2[i];
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], 16); // comparing 16 bytes should be enough
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void leet_set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

// Public domain hash function by DJ Bernstein
static int salt_hash(void *salt)
{
	unsigned int hash = 5381;
	struct custom_salt *fck = (struct custom_salt *)salt;
	unsigned char *s = fck->salt;
	int length = fck->saltlen / 4;

	while (length) {
		hash = ((hash << 5) + hash) ^ *s++;
		length--;
	}
	return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_leet = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			NULL,
		},
		{ NULL },
		leet_tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			NULL
		},
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
		leet_set_key,
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

#endif /* plugin stanza */

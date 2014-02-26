/* SybasePROP cracker. Hacked together during November of 2013 by Dhiru Kholia
 * <dhiru [at] openwall.com>.
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru [at] openwall.com>,
 * Frank Benhamou, Gregory Terrien and Marcel Major and it is hereby released
 * to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * All credits for reversing this algorithm go to Marcel Major, Frank Benhamou
 * and Gregory Terrien. Dhiru Kholia just glued together the bits (as usual!).
 *
 * [1] http://www.nes.fr/securitylab/?p=1128 (in French!)
 *
 * [2] https://hacktivity.com/hu/letoltesek/archivum/57/
 */

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"

#include "syb-prop_repro.h"

#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE           2048 // xxx
static int omp_t = 1;
#endif

#define BLOCK_SIZE 8

#define FORMAT_LABEL        "Sybase-PROP"
#define FORMAT_NAME         ""

#define ALGORITHM_NAME      "salted FEAL-8 32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0

#define PLAINTEXT_LENGTH    64
#define CIPHERTEXT_LENGTH   (6 + 56)

#define PREFIX_VALUE        "0x"
#define PREFIX_LENGTH       2

#define BINARY_SIZE         56 / 2
#define BINARY_ALIGN        4
#define SALT_SIZE           1  // see the definition of generate_hash, note "unsigned char seed" argument
#define SALT_SIZE_HEX       2
#define SALT_ALIGN          1

#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static struct fmt_tests SybasePROP_tests[] = {
	{"0x2905aeb3d00e3b80fb0695cb34c9fa9080f84ae1824b24cc51a3849dcb06", "test11"},
	{"0x3f05fc3d526946d9936c63dd798c5fa1b980747b1d81d0b9b2e8197d2aca", "test12"},
	{NULL}
};

static unsigned char saved_salt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext + PREFIX_LENGTH;

	if (strncmp(ciphertext, PREFIX_VALUE, PREFIX_LENGTH))
		return 0;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;

	while (*p)
		if (atoi16[ARCH_INDEX(*p++)] == 0x7f)
			return 0;
	return 1;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = ciphertext + PREFIX_LENGTH + SALT_SIZE_HEX + 2;  // last 2 bytes always seem to be "05"
		for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}
static void *get_salt(char *ciphertext)
{
	char *p = ciphertext + PREFIX_LENGTH;
	static unsigned char salt;

	salt = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];

	return (void*)&salt;
}

static void set_salt(void *salt)
{
	saved_salt = ((unsigned char*)salt)[0];
}

static void set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
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
		int g_seed = 0x3f;
		struct JtR_FEAL8_CTX ctx;
		generate_hash((unsigned char*)saved_key[index], saved_salt,
				(unsigned char*)crypt_out[index], &g_seed, &ctx);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
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

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

struct fmt_main fmt_sybaseprop = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP, // XXX
		SybasePROP_tests
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
		fmt_default_salt_hash,
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

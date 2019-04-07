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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sybaseprop;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sybaseprop);
#else

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "syb-prop_repro.h"

#ifndef OMP_SCALE
#define OMP_SCALE           4	// MKPC and OMP_SCALE tuned for core i7
#endif

#define BLOCK_SIZE 8

#define FORMAT_LABEL        "Sybase-PROP"
#define FORMAT_NAME         ""

#define ALGORITHM_NAME      "salted FEAL-8 32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    7

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
#define MAX_KEYS_PER_CRYPT  32

static struct fmt_tests SybasePROP_tests[] = {
	{"0x2905aeb3d00e3b80fb0695cb34c9fa9080f84ae1824b24cc51a3849dcb06", "test11"},
	{"0x3f05fc3d526946d9936c63dd798c5fa1b980747b1d81d0b9b2e8197d2aca", "test12"},
	{NULL}
};

static unsigned char saved_salt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext + PREFIX_LENGTH;
	int extra;

	if (strncmp(ciphertext, PREFIX_VALUE, PREFIX_LENGTH))
		return 0;

	if (hexlenl(p, &extra) != CIPHERTEXT_LENGTH-PREFIX_LENGTH || extra)
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
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
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
		generate_hash((unsigned char*)saved_key[index], saved_salt,
		    (unsigned char*)crypt_out[index]);
	}
	return count;
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

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

struct fmt_main fmt_sybaseprop = {
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
		{ NULL },
		{ PREFIX_VALUE },
		SybasePROP_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		fmt_default_salt_hash,
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

/*
 * Whirlpool cracker patch for JtR. Hacked together during April of 2013 by
 * Dhiru Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_whirlpool_0;
extern struct fmt_main fmt_whirlpool_1;
extern struct fmt_main fmt_whirlpool;
#elif FMT_REGISTERS_H
john_register_one(&fmt_whirlpool_0);
john_register_one(&fmt_whirlpool_1);
john_register_one(&fmt_whirlpool);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sph_whirlpool.h"
#include "openssl_local_overrides.h"
#if AC_BUILT
#include "autoconfig.h"
#endif
#if HAVE_LIBCRYPTO
#include <openssl/opensslv.h>
#endif
#if (AC_BUILT && HAVE_WHIRLPOOL) ||	\
   (!AC_BUILT && OPENSSL_VERSION_NUMBER >= 0x10000000 && !HAVE_NO_SSL_WHIRLPOOL)
#include <openssl/whrlpool.h>
#endif

#define FORMAT_LABEL            "Whirpool"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$whirlpool$"
#define TAG_LENGTH              11
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define CIPHERTEXT_LENGTH       128
#define BINARY_SIZE             64
#define BINARY_ALIGN            4
#define SALT_SIZE               0
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT_W    512 // Whirlpool
#define MAX_KEYS_PER_CRYPT_W0   512 // Whirlpool0
#define MAX_KEYS_PER_CRYPT_W1   64  // Whirlpool1

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests whirlpool_0_tests[] = {
	{"B3E1AB6EAF640A34F784593F2074416ACCD3B8E62C620175FCA0997B1BA2347339AA0D79E754C308209EA36811DFA40C1C32F1A2B9004725D987D3635165D3C8", ""},
	// repeat hash in exactly the same form that is used in john.pot
	{FORMAT_TAG "B3E1AB6EAF640A34F784593F2074416ACCD3B8E62C620175FCA0997B1BA2347339AA0D79E754C308209EA36811DFA40C1C32F1A2B9004725D987D3635165D3C8", ""},
	{NULL}
};

static struct fmt_tests whirlpool_1_tests[] = {
	{"470F0409ABAA446E49667D4EBE12A14387CEDBD10DD17B8243CAD550A089DC0FEEA7AA40F6C2AAAB71C6EBD076E43C7CFCA0AD32567897DCB5969861049A0F5A", ""},
	// repeat hash in exactly the same form that is used in john.pot
	{FORMAT_TAG "470F0409ABAA446E49667D4EBE12A14387CEDBD10DD17B8243CAD550A089DC0FEEA7AA40F6C2AAAB71C6EBD076E43C7CFCA0AD32567897DCB5969861049A0F5A", ""},
	{NULL}
};

static struct fmt_tests whirlpool_tests[] = {
	{"19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3", ""},
	// repeat hash in exactly the same form that is used in john.pot
	{FORMAT_TAG "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3", ""},
	{NULL}
};

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
	char *p;
	int extra;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	if (hexlen(p, &extra) != CIPHERTEXT_LENGTH || extra)
		return 0;

	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	strupr(out + TAG_LENGTH);
	return out;
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

	p = ciphertext + TAG_LENGTH;

	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}


#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_0(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		sph_whirlpool0_context ctx;

		sph_whirlpool0_init(&ctx);
		sph_whirlpool0(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_whirlpool0_close(&ctx, (unsigned char*)crypt_out[index]);
	}

	return count;
}

static int crypt_1(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		sph_whirlpool1_context ctx;

		sph_whirlpool1_init(&ctx);
		sph_whirlpool1(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_whirlpool1_close(&ctx, (unsigned char*)crypt_out[index]);
	}

	return count;
}

static int crypt_2(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
#if (AC_BUILT && HAVE_WHIRLPOOL) ||	\
   (!AC_BUILT && OPENSSL_VERSION_NUMBER >= 0x10000000 && !HAVE_NO_SSL_WHIRLPOOL)
		WHIRLPOOL_CTX ctx;

		WHIRLPOOL_Init(&ctx);
		WHIRLPOOL_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		WHIRLPOOL_Final((unsigned char*)crypt_out[index], &ctx);
#else
		sph_whirlpool_context ctx;

		sph_whirlpool_init(&ctx);
		sph_whirlpool(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_whirlpool_close(&ctx, (unsigned char*)crypt_out[index]);
#endif
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

static void whirlpool_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_whirlpool_0 = {
	{
		"whirlpool0",
		"",
		"WHIRLPOOL-0 " ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT_W0,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD |
		FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		whirlpool_0_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
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
		fmt_default_set_salt,
		whirlpool_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_0,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};


struct fmt_main fmt_whirlpool_1 = {
	{
		"whirlpool1",
		"",
		"WHIRLPOOL-1 " ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT_W1,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD |
		FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		whirlpool_1_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{ NULL
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
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		whirlpool_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_1,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_whirlpool = {
	{
		"whirlpool",
		"",
		"WHIRLPOOL " ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT_W,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD |
		FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		whirlpool_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
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
		fmt_default_set_salt,
		whirlpool_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_2,
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

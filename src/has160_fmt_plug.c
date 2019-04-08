/*
 * HAS160-512 cracker patch for JtR. Hacked together during May, 2015
 * by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * Thanks for RHash, http://www.randombit.net/has160.html and
 * https://github.com/maciejczyzewski/retter for the code.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt__HAS160;
#elif FMT_REGISTERS_H
john_register_one(&fmt__HAS160);
#else

#include <string.h>

#include "arch.h"
#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif
#ifdef _OPENMP
#include <omp.h>
#endif

#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "has160.h"

#define FORMAT_LABEL                    "has-160"
#define FORMAT_NAME                     ""
#define ALGORITHM_NAME                  "HAS-160 32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH                0x107

#define PLAINTEXT_LENGTH                125
#define CIPHERTEXT_LENGTH               40
#define BINARY_SIZE                     20
#define SALT_SIZE                       0
#define BINARY_ALIGN                    4
#define SALT_ALIGN                      1

#ifndef OMP_SCALE
#define OMP_SCALE                       4 // Tuned w/ MKPC for core i7
#endif

#define MIN_KEYS_PER_CRYPT              1
#define MAX_KEYS_PER_CRYPT              128

static struct fmt_tests tests[] = {
	{"307964ef34151d37c8047adec7ab50f4ff89762d", ""},
	{"cb5d7efbca2f02e0fb7167cabb123af5795764e5", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
	{"4872bcbc4cd0f0a9dc7c2f7045e5b43b6c830db8", "a"},
	{"975e810488cf2a3d49838478124afce4b1c78804", "abc"},
	{"2338dbc8638d31225f73086246ba529f96710bc6", "message digest"},
	{"596185c9ab6703d0d0dbb98702bc0f5729cd1d3c", "abcdefghijklmnopqrstuvwxyz"},
	{"07f05c8c0773c55ca3a5a695ce6aca4c438911b5", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
	{NULL}
};

static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[(BINARY_SIZE) / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	q = p;

	while (atoi16l[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
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
		has160_ctx ctx;

		rhash_has160_init(&ctx);
		rhash_has160_update(&ctx, (unsigned char*)saved_key[index], saved_len[index]);
		rhash_has160_final(&ctx, (unsigned char*)crypt_out[index]);
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

struct fmt_main fmt__HAS160 = {
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
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

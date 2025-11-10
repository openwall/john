/*
 * Oubliette password manager IDEA format cracker for JtR.
 * Contributed by DavideDG github.com/davidedg
 *
 * This software is Copyright (c) 2025 DavideDG, <delgrande.davide at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if FMT_EXTERNS_H
extern struct fmt_main fmt_oubliette_idea;
#elif FMT_REGISTERS_H
john_register_one(&fmt_oubliette_idea);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "idea-JtR.h"

#define FORMAT_LABEL            "Oubliette-IDEA"
#define FORMAT_NAME             "Oubliette IDEA"
#define FORMAT_TAG              "$oubliette-idea$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "SHA1/IDEA 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        MAX_PLAINTEXT_LENGTH
#define BINARY_SIZE             32
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               0
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      256
#define OMP_SCALE               16

typedef struct {
	// Group frequently accessed data together
	unsigned char padded_sha1[32];
	IDEA_KEY_SCHEDULE ks;
	// Less frequently accessed data
	unsigned char iv[8];
	unsigned char encrypted_iv[8];
} oubliette_state;

static struct fmt_tests tests[] = {
	{"$oubliette-idea$e82bb8b871ed9a2b7d77afce662325a2c522844e0e91bde104b8e4f68044e991", "12345678"},
	{"$oubliette-idea$9c846ab8c1dc703330521e7ca77489beded5d23b3aa821edea8f0324fbdb9f08",
	    "\xd1\xa2\x63\x5e\xac\x4e\x4a\x25\x48\xd5\x45\x73\xae\x79\x53\xb2\xe5\x69\xfc\x59\xce\x40\x21\x6a\x67\x54\x5c\xff\x5c\xfe\x7a\x52\xbe\x77\xd2\x77\xb8\x61\x39\x45\xf0\x2b\x3e\x4a\x3c\xa4\x2e\x53\xd8\xba\x71\xc8\x32\x26\x69\x37\x2f\xfa\x7d\xa1\xff\xdf\xd4\xba\x29\x4d\xd4\x72\x69\x40\xc3\x5c\x22\x2b\x79\x50\x21\x41\x5d\xc7\xdd\x6a\x3f\xed\x26\x7b\x34\x7e\xb9\x21"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_autotune(self, OMP_SCALE);
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(crypt_out);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) &&
	    hexlenl(ciphertext + TAG_LENGTH, NULL) == BINARY_SIZE * 2 &&
	    !*(ciphertext + TAG_LENGTH + BINARY_SIZE * 2);
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		buf.c[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return buf.c;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int get_hash_0(int index)
{
	return crypt_out[index][0] & PH_MASK_0;
}
static int get_hash_1(int index)
{
	return crypt_out[index][0] & PH_MASK_1;
}
static int get_hash_2(int index)
{
	return crypt_out[index][0] & PH_MASK_2;
}
static int get_hash_3(int index)
{
	return crypt_out[index][0] & PH_MASK_3;
}
static int get_hash_4(int index)
{
	return crypt_out[index][0] & PH_MASK_4;
}
static int get_hash_5(int index)
{
	return crypt_out[index][0] & PH_MASK_5;
}
static int get_hash_6(int index)
{
	return crypt_out[index][0] & PH_MASK_6;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		oubliette_state s;
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_key[index], saved_len[index]);
		SHA1_Final(s.padded_sha1, &ctx);

		memset(s.padded_sha1 + 20, 0xFF, 12);
		JtR_idea_set_encrypt_key(s.padded_sha1, &s.ks);
		memset(s.iv, 0xFF, 8);
		JtR_idea_ecb_encrypt(s.iv, s.encrypted_iv, &s.ks);

		JtR_idea_cbc_encrypt(s.padded_sha1, (unsigned char *)crypt_out[index], 32, &s.ks, s.encrypted_iv, IDEA_ENCRYPT);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*(uint32_t *)binary == crypt_out[index][0])
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

struct fmt_main fmt_oubliette_idea = {
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
		{ FORMAT_TAG },
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

/*
 * PostgreSQL MD5 challenge-response cracker patch for JtR. Hacked together
 * during October of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * Use Ettercap to get PostgreSQL MD5 challenge-response pairs in JtR format.
 * E.g. ettercap -Tq -r /home/user/sample.pcap
 *
 * Input format:
 * $postgres$user*salt*hash
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright magnum 2013, and it is hereby released to the general public
 * under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_postgres;
#elif FMT_REGISTERS_H
john_register_one(&fmt_postgres);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "postgres"
#define FORMAT_NAME             "PostgreSQL C/R"
#define FORMAT_TAG              "$postgres$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG2             "$postgre$"
#define FORMAT_TAG2_LEN         (sizeof(FORMAT_TAG2)-1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        32
#define BINARY_SIZE             16
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              MEM_ALIGN_NONE
#define MAX_USERNAME_LEN        64
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      128

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests postgres_tests[] = {
	{"$postgres$postgres*f063f05d*1d586cc8d137e5f1733f234d224393e8",
	 "openwall"},
	{"$postgres$postgres*c31803a2*1c4e11fb51835c3bbe9851ec91ec1375",
	 "password"},
	/* $postgre$ is supported but deprecated */
	{"$postgre$postgres*684697c8*bf2a64f35feba7bf1b633d60393c1356",
	 "openwall"},
	/* $postgres$ with longer user name */
	{"$postgres$Twelve_chars*55393156*c01df9affa7573ef32ec143759f3e005",
	"HookFish__2"},
	{"$postgres$postgres*65687433*b782eca219ad84b58f26d25e19a1bbc9",
	 "thisisalongstring"},
	{"$postgres$postgres*33374273*77e0016f1b92cdea7291ab0ed21798b8",
	 "string with space"},
	{"$postgres$postgres*6f734f37*d5451e93f6ac9a0d30336ec106e91cf5",
	 "123456789"},
	{"$postgres$postgres*3348654b*0f0f46a3dfebf45f4320d2edeabc318f",
	 ""},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	unsigned char user[MAX_USERNAME_LEN + 1];
	unsigned char salt[4];
} *cur_salt;

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
	const char *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	/* Check hash */
	if (!(p = strrchr(ciphertext, '*')))
		return 0;
	if (hexlenl(&p[1], &extra) != 2*BINARY_SIZE || extra)
		return 0;

	/* Check salt */
	p -= 9;
	if (*p != '*')
		return 0;
	if (hexlenl(&p[1], 0) != 8)
		return 0;

	/* Check username length */
	if (p - ciphertext - FORMAT_TAG_LEN > MAX_USERNAME_LEN)
		return 0;

	return 1;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[FORMAT_TAG_LEN + sizeof(struct custom_salt) + 2*BINARY_SIZE +2+1];

	/* Replace deprecated tag */
	if (*split_fields[1] && !strncmp(split_fields[1], FORMAT_TAG2, FORMAT_TAG2_LEN)) {
		snprintf(out, sizeof(out), "%s%s",
		         FORMAT_TAG, &split_fields[1][FORMAT_TAG2_LEN]);
		if (valid(out, self))
			return out;
	}
	return split_fields[1];
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	ctcopy += FORMAT_TAG_LEN;   /* skip over "$postgres$" */
	p = strtokm(ctcopy, "*");
	memset(&cs, 0, sizeof(cs));
	strnzcpy((char*)cs.user, p, MAX_USERNAME_LEN + 1);
	p = strtokm(NULL, "*");
	for (i = 0; i < 4; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
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

	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

inline static void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;

	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		MD5_CTX ctx;
		unsigned char out[32];

		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		MD5_Update(&ctx, cur_salt->user, strlen((char*)cur_salt->user));
		MD5_Final((unsigned char*)crypt_out[index], &ctx);

		hex_encode((unsigned char*)crypt_out[index], 16, out);

		MD5_Init(&ctx);
		MD5_Update(&ctx, out, 32);
		MD5_Update(&ctx, cur_salt->salt, 4);
		MD5_Final((unsigned char*)crypt_out[index], &ctx);
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

static void postgres_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_postgres = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ FORMAT_TAG, FORMAT_TAG2 },
		postgres_tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
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
		postgres_set_key,
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

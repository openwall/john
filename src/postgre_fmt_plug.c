/* PostgreSQL MD5 challenge-response cracker patch for JtR. Hacked together
 * during October of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * Use Ettercap to get PostgreSQL MD5 challenge-response pairs in JtR format.
 * E.g. ettercap -Tq -r /home/user/sample.pcap
 *
 * Input format:
 * $postgres$user*salt*hash
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright magnum 2013,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#include <string.h>
#include <errno.h>
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif

#include "md5.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "postgres"
#define FORMAT_NAME             "PostgreSQL MD5 challenge-response"
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        32
#define BINARY_SIZE             16
#define SALT_SIZE               sizeof(struct custom_salt)
#define MAX_USERNAME_LEN        64
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define HEX                     "0123456789abcdefABCDEF"

static struct fmt_tests postgres_tests[] = {
	{"$postgres$postgres*f063f05d*1d586cc8d137e5f1733f234d224393e8",
	 "openwall"},
	{"$postgres$postgres*c31803a2*1c4e11fb51835c3bbe9851ec91ec1375",
	 "password"},
	/* $postgre$ is supported but deprecated */
	{"$postgre$postgres*684697c8*bf2a64f35feba7bf1b633d60393c1356",
	 "openwall"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	unsigned char user[MAX_USERNAME_LEN + 1];
	unsigned char salt[4];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
	                            self->params.max_keys_per_crypt,
	                            MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
	                            self->params.max_keys_per_crypt,
	                            MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	const char *p;

	if (strncmp(ciphertext, "$postgres$", 10))
		return 0;

	/* Check hash */
	if (!(p = strrchr(ciphertext, '*')))
		return 0;
	if (strspn(&p[1], HEX) != 2*BINARY_SIZE)
		return 0;

	/* Check salt */
	p -= 9;
	if (*p != '*')
		return 0;
	if (strspn(&p[1], HEX) != 8)
		return 0;

	/* Check username length */
	if (p - ciphertext - 10 > MAX_USERNAME_LEN)
		return 0;

	return 1;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[10 + sizeof(struct custom_salt) + 2*BINARY_SIZE +2+1];

	/* Replace deprecated tag */
	if (*split_fields[1] && !strncmp(split_fields[1], "$postgre$", 9)) {
		snprintf(out, sizeof(out), "%s%s",
		         "$postgres$", &split_fields[1][9]);
		if (valid(out, self))
			return out;
	}
	return split_fields[1];
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	ctcopy += 10;   /* skip over "$postgres$" */
	p = strtok(ctcopy, "*");
	strnzcpy((char*)cs.user, p, MAX_USERNAME_LEN + 1);
	p = strtok(NULL, "*");
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

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;

	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static void crypt_all(int count)
{
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index++)
#endif
	{
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
}

static int cmp_all(void *binary, int count)
{
	int index = 0;

#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (; index < count; index++)
#endif
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

static void postgres_set_key(char *key, int index)
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

struct fmt_main fmt_postgres = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		postgres_tests
	}, {
		init,
		prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		postgres_set_key,
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

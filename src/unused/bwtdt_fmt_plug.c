/* bwtdt s.md5(sha1(md5(s.sha1(p)))) cracker patch for JtR. Hacked together
 * during August, 2013 by Dhiru Kholia <dhiru at openwall.com>
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * bwtdt hash ==> s.md5(sha1(md5(s.sha1(p))))
 *
 * JimF, July 2012.
 * Made small change in hex_encode 10x improvement in speed.  Also some other
 * changes.  Should be a thin dyanamic.
 *
 * Apparently, BWTDT stands for "Bad Way To Do This" and was made up just
 * for the CMIYC 2013 contest. magnum thinks it should be moved to unused/
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_zzz_bwtdt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_zzz_bwtdt);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"
#include "sha.h"
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               8 // XXX
#endif

#define FORMAT_LABEL		"bwtdt"
#define FORMAT_NAME		"bwtdt s.md5(sha1(md5(s.sha1(p))))"
#define ALGORITHM_NAME		"MD5+SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1 /* change to 0 once there's any speedup for "many salts" */
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define BINARY_ALIGN		4
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests bwtdt_tests[] = {
	{"00000000c3a62c15bb2275a52308b73706813634", "password"},
	{"b077b5a4140084441ce2f8f3922732f09a34bf9f", "antineoplastic3"},
	{"8365ef6da923f658e74c4a851e625f41db7ffe74", "paramedical7"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	unsigned char salt[8];
} *cur_salt;

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	static int omp_t = 1;
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

// XXX implement me FOR CRYING OUT LOUD!
static int valid(char *ciphertext, struct fmt_main *self)
{
	return (strlen(ciphertext) == 40);
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	unsigned char *out = cs.salt;
	char *p;

	p = ciphertext;

	strncpy((char*)out, p, 8);
	return (void *)&cs;
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
	p = ciphertext + 8;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		// s.md5(sha1(md5(s.sha1(p))))
		unsigned char hexhash[40];
		unsigned char buf[20];

		SHA_CTX sctx;
		MD5_CTX mctx;

		SHA1_Init(&sctx);
		SHA1_Update(&sctx, saved_key[index], strlen(saved_key[index]));
		SHA1_Final(buf, &sctx);
		hex_encode(buf, 20, hexhash);

		MD5_Init(&mctx);
		MD5_Update(&mctx, cur_salt->salt, 8);
		MD5_Update(&mctx, hexhash, 40);
		MD5_Final(buf, &mctx);
		hex_encode(buf, 16, hexhash);

		SHA1_Init(&sctx);
		SHA1_Update(&sctx, hexhash, 32);
		SHA1_Final(buf, &sctx);
		hex_encode(buf, 20, hexhash);

		MD5_Init(&mctx);
		MD5_Update(&mctx, hexhash, 40);
		MD5_Final((unsigned char*)crypt_out[index], &mctx);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (*((ARCH_WORD_32*)binary) == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *((ARCH_WORD_32*)binary) == crypt_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	void *binary = get_binary(source);
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static void bwtdt_set_key(char *key, int index)
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

/*
 * The zzz is a little protection against Dhiru's vandalism,
 * it hopefully makes the format come last in auto-detection.
 */
struct fmt_main fmt_zzz_bwtdt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		bwtdt_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
		bwtdt_set_key,
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

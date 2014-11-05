/*
 * ssha512 support for LDAP style password storage
 *
 * This software is Copyright (c) 2013 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_saltedsha2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_saltedsha2);
#else

#define MAX_SALT_LEN    16      // bytes, the base64 representation is longer

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE                       2048 // i7 not using HT
#endif

#include "misc.h"
#include "formats.h"
#include "arch.h"
#include "options.h"
#include "johnswap.h"
#include "common.h"
#include "sha2.h"
#include "base64.h"
#include "memdbg.h"

#define FORMAT_LABEL                    "SSHA512"
#define FORMAT_NAME                     "LDAP"

#define ALGORITHM_NAME                  "32/" ARCH_BITS_STR " " SHA2_LIB

#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH                0

#define PLAINTEXT_LENGTH                (55-MAX_SALT_LEN)

#define BINARY_SIZE                     (512 / 8)
#define BINARY_ALIGN                    4
#define SALT_SIZE                       (MAX_SALT_LEN + sizeof(unsigned int))
#define SALT_ALIGN                      4

#define CIPHERTEXT_LENGTH               ((BINARY_SIZE + 1 + MAX_SALT_LEN + 2) / 3 * 4)

#define MIN_KEYS_PER_CRYPT              1
#define MAX_KEYS_PER_CRYPT              1

#define NSLDAP_MAGIC "{SSHA512}"
#define NSLDAP_MAGIC_LENGTH (sizeof(NSLDAP_MAGIC) - 1)
#define BASE64_ALPHABET	  \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

struct s_salt
{
	unsigned int len;
	union {
		unsigned char c[MAX_SALT_LEN];
		ARCH_WORD_32 w32;
	} data;
};

static struct s_salt *saved_salt;

static struct fmt_tests tests[] = {
	{"{SSHA512}SCMmLlStPIxVtJc8Y6REiGTMsgSEFF7xVQFoYZYg39H0nEeDuK/fWxxNZCdSYlRgJK3U3q0lYTka3Nre2CjXzeNUjbvHabYP", "password"},
	{"{SSHA512}WucBQuH6NyeRYMz6gHQddkJLwzTUXaf8Ag0n9YM0drMFHG9XCO+FllvvwjXmo5/yFPvs+n1JVvJmdsvX5XHYvSUn9Xw=", "test123"},
	{"{SSHA512}uURShqzuCx/8BKVrc4HkTpYnv2eVfwEzg+Zi2AbsTQaIV7Xo6pDhRAZnp70h5P8MC6XyotrB2f27aLhhRj4GYrkJSFmbKmuF", "testpass"},
	{NULL}
};

static unsigned char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / 4];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_len = mem_calloc_tiny(sizeof(*saved_len) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void * binary(char *ciphertext) {
	static char *realcipher;

	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE + 1 + SALT_SIZE, MEM_ALIGN_WORD);

	ciphertext += NSLDAP_MAGIC_LENGTH;
	memset(realcipher, 0, BINARY_SIZE);
	base64_decode(ciphertext, strlen(ciphertext), realcipher);
	return (void*)realcipher;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int len;

	if (strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH))
		return 0;
	ciphertext += NSLDAP_MAGIC_LENGTH;

	len = strspn(ciphertext, BASE64_ALPHABET);
	if (len < (BINARY_SIZE+1+2)/3*4-2)
		return 0;

	len = strspn(ciphertext, BASE64_ALPHABET "=");
	if (len != strlen(ciphertext))
		return 0;
	if (len & 3 || len > CIPHERTEXT_LENGTH)
		return 0;

	return 1;
}

static void set_key(char *key, int index)
{
	int len = strlen(key);

	saved_len[index] = len;
	memcpy(saved_key[index], key, len + 1);
}

static void * get_salt(char * ciphertext)
{
	static struct s_salt cursalt;
	char *p;
	char realcipher[CIPHERTEXT_LENGTH];
	int len;

	ciphertext += NSLDAP_MAGIC_LENGTH;
	memset(realcipher, 0, sizeof(realcipher));
	memset(&cursalt, 0, sizeof(struct s_salt));
	len = strlen(ciphertext);
	base64_decode(ciphertext, len, realcipher);

	// We now support any salt length up to SALT_SIZE
	cursalt.len = (len + 3) / 4 * 3 - BINARY_SIZE;
	p = &ciphertext[len];
	while (*--p == '=')
		cursalt.len--;

	memcpy(cursalt.data.c, realcipher+BINARY_SIZE, cursalt.len);
	return &cursalt;
}

static char *get_key(int index) {
	return (char*)saved_key[index];
}

static int cmp_all(void *binary, int count) {
	int index;

	for (index = 0; index < count; index++)
		if (((ARCH_WORD_32*)binary)[0] == crypt_key[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int count){
	return 1;
}

static void set_salt(void *salt) {
	saved_salt = salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		SHA512_CTX ctx;

		SHA512_Init(&ctx);
		SHA512_Update(&ctx, saved_key[index], saved_len[index]);
		SHA512_Update(&ctx, saved_salt->data.c, saved_salt->len);
		SHA512_Final((unsigned char*)crypt_key[index], &ctx);
	}
	return count;
}

static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key[index])[0] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key[index])[0] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key[index])[0] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key[index])[0] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key[index])[0] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key[index])[0] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key[index])[0] & 0x7ffffff; }

static int salt_hash(void *salt)
{
	struct s_salt * mysalt = salt;
	return mysalt->data.w32 & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_saltedsha2 = {
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
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
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

#endif /* plugin stanza */

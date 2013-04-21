/* AIX ssha cracker patch for JtR. Hacked together during April of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * Thanks to atom (of hashcat project) and philsmd for discovering and
 * publishing the details of various AIX hashing algorithms.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include <openssl/evp.h>
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               1 // FIXME
#endif

#define FORMAT_LABEL		"aix-ssha"
#define FORMAT_NAME		"AIX ssha - [1 / 256 / 512]"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		20
#define CMP_SIZE 		BINARY_SIZE - 2
#define LARGEST_BINARY_SIZE	64
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define BASE64_ALPHABET	  \
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

static struct fmt_tests aixssha_tests[] = {
	/* hash posted on john-users */
	{"{ssha512}06$aXayEJGxA02Bl4d2$TWfWx34oD.UjrS/Qtco6Ij2XPY1CPYJfdk3CcxEjnMZvQw2p5obHYH7SI2wxcJgaS9.S9Hz948R.GdGwsvR...", "test"},
	/* http://www.ibmsystemsmag.com/aix/administrator/security/password_hash/?page=2 <== partially corrupted hash? */
	{"{ssha512}06$otYx2eSXx.OkEY4F$No5ZvSfhYuB1MSkBhhcKJIjS0.q//awdkcZwF9/TXi3EnL6QeronmS0jCc3P2aEV9WLi5arzN1YjVwkx8bng..", "colorado"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int iterations;
	int type;
	char unsigned salt[17];
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
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	char *ctcopy;
	char *keeptr;
	int len;

	if ((strncmp(ciphertext, "{ssha1}", 7) != 0) && \
			(strncmp(ciphertext, "{ssha256}", 9) != 0) && \
			(strncmp(ciphertext, "{ssha512}", 9) != 0))
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	if ((strncmp(ciphertext, "{ssha1}", 7) ==0))
		ctcopy += 7;
	else
		ctcopy += 9;
	if ((p = strtok(ctcopy, "$")) == NULL)	/* iterations */
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* salt */
		goto err;
	len = strspn(p, BASE64_ALPHABET);
	if (len < 8 || len > 16)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* hash */
		goto err;
	len = strspn(p, BASE64_ALPHABET);
	if (len != 44 && len != 28 && len != 86)
		goto err;
	MEM_FREE(keeptr);
	return 1;
err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;
	keeptr = ctcopy;

	if ((strncmp(ciphertext, "{ssha1}", 7) ==0))
		cs.type = 1;
	else if ((strncmp(ciphertext, "{ssha256}", 9) ==0))
		cs.type = 256;
	else
		cs.type = 512;

	if (cs.type == 1)
		ctcopy += 7;
	else
		ctcopy += 9;

	p = strtok(ctcopy, "$");
	cs.iterations = 1 << atoi(p);
	p = strtok(NULL, "$");
	strncpy((char*)cs.salt, p, 17);

	MEM_FREE(keeptr);
	return (void *)&cs;
}

#define TO_BINARY(b1, b2, b3) {	  \
	value = (ARCH_WORD_32)atoi64[ARCH_INDEX(pos[0])] | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out.c[b1] = value >> 16; \
	out.c[b2] = value >> 8; \
	out.c[b3] = value; }

static void *get_binary(char *ciphertext)
{
	static union {
		ARCH_WORD_32 w[LARGEST_BINARY_SIZE/4];
		unsigned char c[LARGEST_BINARY_SIZE];
	} out;
	ARCH_WORD_32 value;
	char *pos = strrchr(ciphertext, '$') + 1;
	int len = strlen(pos);
	int i;

	for (i = 0; i < len/3*4; i += 3)
		TO_BINARY(i, i + 1, i + 2);

	if (len % 3 == 1) {
		value = (ARCH_WORD_32)atoi64[ARCH_INDEX(pos[0])] |
			((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[1])] << 6);
		out.c[i] = value;
	} else if (len % 3 == 2) { /* sha-1, sha-256 */
		value = (ARCH_WORD_32)atoi64[ARCH_INDEX(pos[0])] |
			((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[1])] << 6) |
			((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[2])] << 12);
		out.c[i++] = value >> 8;
		out.c[i++] = value;
	}

	return (void *)out.c;
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		if (cur_salt->type == 1)
			PKCS5_PBKDF2_HMAC(saved_key[index], strlen(saved_key[index]),
				cur_salt->salt, strlen((char*)cur_salt->salt),
				cur_salt->iterations, EVP_sha1(), BINARY_SIZE,
				(unsigned char*)crypt_out[index]);
		else if (cur_salt->type == 256)
			PKCS5_PBKDF2_HMAC(saved_key[index], strlen(saved_key[index]),
				cur_salt->salt, strlen((char*)cur_salt->salt),
				cur_salt->iterations, EVP_sha256(), BINARY_SIZE,
				(unsigned char*)crypt_out[index]);
		else
			PKCS5_PBKDF2_HMAC(saved_key[index], strlen(saved_key[index]),
				cur_salt->salt, strlen((char*)cur_salt->salt),
				cur_salt->iterations, EVP_sha512(), BINARY_SIZE,
				(unsigned char*)crypt_out[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], CMP_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], CMP_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void aixssha_set_key(char *key, int index)
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

struct fmt_main fmt_aixssha = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		aixssha_tests
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
		aixssha_set_key,
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

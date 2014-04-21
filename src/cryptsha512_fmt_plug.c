/*
 * This file is part of John the Ripper password cracker,
 * based on rawSHA256_fmt.c code and Drepper's spec at
 * http://www.akkadia.org/drepper/SHA-crypt.txt
 *
 * This software is Copyright (c) 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 */

#define _GNU_SOURCE
#include <string.h>
#ifdef _OPENMP
#define OMP_SCALE			16
#include <omp.h>
#endif

#include "arch.h"
#include "sha2.h"
#include "params.h"
#include "common.h"
#include "formats.h"
// these MUST be defined prior to loading cryptsha512_valid.h
#define BINARY_SIZE			64
#define SALT_LENGTH			16
#define CIPHERTEXT_LENGTH		86
#include "cryptsha512_common.h"
#include "memdbg.h"

#define FORMAT_LABEL			"sha512crypt"

#if ARCH_BITS >= 64
#define ALGORITHM_NAME			"64/" ARCH_BITS_STR " " SHA2_LIB
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR " " SHA2_LIB
#endif

#define PLAINTEXT_LENGTH		125

#define BINARY_ALIGN			4
#define SALT_SIZE			sizeof(struct saltstruct)
#define SALT_ALIGN			4

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0", "U*U*U*U*"},
	{"$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1", "U*U***U"},
	{"$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/", "U*U***U*"},
	{"$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330", "*U*U*U*U"},
	{"$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.", ""},
	{NULL}
};

static int (*saved_key_length);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct saltstruct {
	unsigned int len;
	unsigned int rounds;
	unsigned char salt[SALT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt = omp_t * MIN_KEYS_PER_CRYPT;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt = omp_t * MAX_KEYS_PER_CRYPT;
#endif
	saved_key_length = mem_calloc_tiny(sizeof(*saved_key_length) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_key(char *key, int index)
{
	int len = strlen(key);
	saved_key_length[index] = len;
	if (len > PLAINTEXT_LENGTH)
		len = saved_key_length[index] = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
}

static char *get_key(int index)
{
	saved_key[index][saved_key_length[index]] = 0;
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
		// portably align temp_result char * pointer machine word size.
		union xx {
			unsigned char c[BINARY_SIZE];
			ARCH_WORD a[BINARY_SIZE/sizeof(ARCH_WORD)];
		} u;
		unsigned char *temp_result = u.c;
		SHA512_CTX ctx;
		SHA512_CTX alt_ctx;
		size_t cnt;
		char *cp;
		char p_bytes[PLAINTEXT_LENGTH+1];
		char s_bytes[PLAINTEXT_LENGTH+1];

		/* Prepare for the real work.  */
		SHA512_Init(&ctx);

		/* Add the key string.  */
		SHA512_Update(&ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* The last part is the salt string.  This must be at most 16
		   characters and it ends at the first `$' character (for
		   compatibility with existing implementations).  */
		SHA512_Update(&ctx, cur_salt->salt, cur_salt->len);


		/* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The
		   final result will be added to the first context.  */
		SHA512_Init(&alt_ctx);

		/* Add key.  */
		SHA512_Update(&alt_ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* Add salt.  */
		SHA512_Update(&alt_ctx, cur_salt->salt, cur_salt->len);

		/* Add key again.  */
		SHA512_Update(&alt_ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* Now get result of this (64 bytes) and add it to the other
		   context.  */
		SHA512_Final((unsigned char*)crypt_out[index], &alt_ctx);

		/* Add for any character in the key one byte of the alternate sum.  */
		for (cnt = saved_key_length[index]; cnt > BINARY_SIZE; cnt -= BINARY_SIZE)
			SHA512_Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);
		SHA512_Update(&ctx, (unsigned char*)crypt_out[index], cnt);

		/* Take the binary representation of the length of the key and for every
		   1 add the alternate sum, for every 0 the key.  */
		for (cnt = saved_key_length[index]; cnt > 0; cnt >>= 1)
			if ((cnt & 1) != 0)
				SHA512_Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);
			else
				SHA512_Update(&ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* Create intermediate result.  */
		SHA512_Final((unsigned char*)crypt_out[index], &ctx);

		/* Start computation of P byte sequence.  */
		SHA512_Init(&alt_ctx);

		/* For every character in the password add the entire password.  */
		for (cnt = 0; cnt < saved_key_length[index]; ++cnt)
			SHA512_Update(&alt_ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* Finish the digest.  */
		SHA512_Final(temp_result, &alt_ctx);

		/* Create byte sequence P.  */
		cp = p_bytes;
		for (cnt = saved_key_length[index]; cnt >= BINARY_SIZE; cnt -= BINARY_SIZE)
			cp = (char *) memcpy (cp, temp_result, BINARY_SIZE) + BINARY_SIZE;
		memcpy (cp, temp_result, cnt);

		/* Start computation of S byte sequence.  */
		SHA512_Init(&alt_ctx);

		/* For every character in the password add the entire password.  */
		for (cnt = 0; cnt < 16 + ((unsigned char*)crypt_out[index])[0]; ++cnt)
			SHA512_Update(&alt_ctx, cur_salt->salt, cur_salt->len);

		/* Finish the digest.  */
		SHA512_Final(temp_result, &alt_ctx);

		/* Create byte sequence S.  */
		cp = s_bytes;
		for (cnt = cur_salt->len; cnt >= BINARY_SIZE; cnt -= BINARY_SIZE)
			cp = (char *) memcpy (cp, temp_result, BINARY_SIZE) + BINARY_SIZE;
		memcpy (cp, temp_result, cnt);

		/* Repeatedly run the collected hash value through SHA512 to
		   burn CPU cycles.  */
		for (cnt = 0; cnt < cur_salt->rounds; ++cnt)
			{
				/* New context.  */
				SHA512_Init(&ctx);

				/* Add key or last result.  */
				if ((cnt & 1) != 0)
					SHA512_Update(&ctx, p_bytes, saved_key_length[index]);
				else
					SHA512_Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);

				/* Add salt for numbers not divisible by 3.  */
				if (cnt % 3 != 0)
					SHA512_Update(&ctx, s_bytes, cur_salt->len);

				/* Add key for numbers not divisible by 7.  */
				if (cnt % 7 != 0)
					SHA512_Update(&ctx, p_bytes, saved_key_length[index]);

				/* Add key or last result.  */
				if ((cnt & 1) != 0)
					SHA512_Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);
				else
					SHA512_Update(&ctx, p_bytes, saved_key_length[index]);

				/* Create intermediate [SIC] result.  */
				SHA512_Final((unsigned char*)crypt_out[index], &ctx);
			}
	}
	return count;
}

static void set_salt(void *salt)
{
	cur_salt = salt;
}

static void *get_salt(char *ciphertext)
{
	static struct saltstruct out;
	int len;

	out.rounds = ROUNDS_DEFAULT;
	ciphertext += 3;
	if (!strncmp(ciphertext, ROUNDS_PREFIX,
	             sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);
		if (*endp == '$')
		{
			ciphertext = endp + 1;
			srounds = srounds < ROUNDS_MIN ?
				ROUNDS_MIN : srounds;
			out.rounds = srounds > ROUNDS_MAX ?
				ROUNDS_MAX : srounds;
		}
	}

	for (len = 0; ciphertext[len] != '$'; len++);

	memcpy(out.salt, ciphertext, len);
	out.len = len;
	return &out;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
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

// Public domain hash function by DJ Bernstein
// We are hashing the entire struct
static int salt_hash(void *salt)
{
	unsigned char *s = salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < SALT_SIZE; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}

#if FMT_MAIN_VERSION > 11
/* iteration count as tunable cost parameter */
static unsigned int sha512crypt_iterations(void *salt)
{
	struct saltstruct *sha512crypt_salt;

	sha512crypt_salt = salt;
	return (unsigned int)sha512crypt_salt->rounds;
}
#endif

struct fmt_main fmt_cryptsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		"SHA512 " ALGORITHM_NAME,
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
		{
			"iteration count",
		},
#endif
		tests
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
		{
			sha512crypt_iterations,
		},
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

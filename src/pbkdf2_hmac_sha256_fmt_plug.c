/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on hmac-sha512 by magnum.
 *
 * Minor fixes, format unification and OMP support done by Dhiru Kholia
 * <dhiru@openwall.com>.
 *
 * Fixed for supporting $ml$ "dave" format as well as GRUB native format by
 * magnum 2013. Note: We support a binary size of >512 bits (64 bytes / 128
 * chars of hex) but we currently do not calculate it even in cmp_exact(). The
 * chance for a 512-bit hash collision should be pretty dang slim.
 *
 * The pbkdf2_sha256_hmac was so messed up, I simply copied sha512 over the top
 * of it, replacing the code in totality. JimF.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pbkdf2_hmac_sha256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pbkdf2_hmac_sha256);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "base64_convert.h"
#include "sha2.h"
#include "johnswap.h"
#include "pbkdf2_hmac_sha256.h"
#include "pbkdf2_hmac_common.h"

#define FORMAT_LABEL            "PBKDF2-HMAC-SHA256"
#define FORMAT_NAME		""

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME		"PBKDF2-SHA256 " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256 32/" ARCH_BITS_STR
#endif

#define MAX_CIPHERTEXT_LENGTH   1024 /* Bump this and code will adopt */
#define SALT_SIZE               sizeof(struct custom_salt)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      (4 * SSE_GROUP_SZ_SHA256)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               2
#endif


#define PAD_SIZE                128
#define PLAINTEXT_LENGTH        125

static struct custom_salt {
	uint8_t length;
	uint8_t salt[PBKDF2_32_MAX_SALT_SIZE + 3];
	uint32_t rounds;
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[PBKDF2_SHA256_BINARY_SIZE / sizeof(uint32_t)];

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

static void *get_salt(char *ciphertext)
{
	static struct custom_salt salt;
	char *p, *c = ciphertext;
	uint32_t rounds;

	memset(&salt, 0, sizeof(salt));
	c += PBKDF2_SHA256_TAG_LEN;
	rounds = strtol(c, NULL, 10);
	c = strchr(c, '$') + 1;
	p = strchr(c, '$');
	if (p-c==14 && rounds==20000) {
		// for now, assume this is a cisco8 hash
		strnzcpy((char*)(salt.salt), c, 15);
		salt.length = 14;
		salt.rounds = rounds;
		return (void*)&salt;
	}
	salt.length = base64_convert(c, e_b64_mime, p-c, salt.salt, e_b64_raw, sizeof(salt.salt), flg_Base64_MIME_PLUS_TO_DOT, 0);
	salt.rounds = rounds;
	return (void *)&salt;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SSE_GROUP_SZ_SHA256
		int lens[SSE_GROUP_SZ_SHA256], i;
		unsigned char *pin[SSE_GROUP_SZ_SHA256];
		union {
			uint32_t *pout[SSE_GROUP_SZ_SHA256];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA256; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = crypt_out[index+i];
		}
		pbkdf2_sha256_sse((const unsigned char **)pin, lens, cur_salt->salt, cur_salt->length, cur_salt->rounds, &(x.poutc), PBKDF2_SHA256_BINARY_SIZE, 0);
#else
		pbkdf2_sha256((const unsigned char*)(saved_key[index]), strlen(saved_key[index]),
			cur_salt->salt, cur_salt->length,
			cur_salt->rounds, (unsigned char*)crypt_out[index], PBKDF2_SHA256_BINARY_SIZE, 0);
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
	return !memcmp(binary, crypt_out[index], PBKDF2_SHA256_BINARY_SIZE);
}

/* Check the FULL binary, just for good measure. There is no chance we'll
   have a false positive here but this function is not performance sensitive.

   This function not done linke pbkdf2_hmac_sha512. Simply return 1.
   */
static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->rounds;
}

struct fmt_main fmt_pbkdf2_hmac_sha256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		PBKDF2_SHA256_BINARY_SIZE,
		PBKDF2_32_BINARY_ALIGN,
		SALT_SIZE,
		sizeof(ARCH_WORD),
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			"iteration count",
		},
		{ PBKDF2_SHA256_FORMAT_TAG, FORMAT_TAG_CISCO8 },
		pbkdf2_hmac_sha256_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		pbkdf2_hmac_sha256_prepare,
		pbkdf2_hmac_sha256_valid,
		fmt_default_split,
		pbkdf2_hmac_sha256_binary,
		get_salt,
		{
			iteration_count,
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

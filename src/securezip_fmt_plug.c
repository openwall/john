/*
 * JtR format to crack PKWARE's SecureZIP archives. The same archive format is
 * used by "Directory Opus" software.
 *
 * See "APPNOTE-6.3.4.TXT" for more information about SecureZIP.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Big thanks goes to PKWARE for documenting the archive format, and 7-Zip
 * project for implementing the specification.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_securezip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_securezip);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               32  // MKPC and OMP_SCALE tuned on Core i7-6600U

#include "arch.h"
#include "misc.h"
#include "sha.h"
#include "aes.h"
#include "jumbo.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "securezip_common.h"

#define FORMAT_LABEL            "securezip"
#define FORMAT_NAME             "PKWARE SecureZIP"

#define ALGORITHM_NAME          "SHA1 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      32

#ifndef SHA1_SIZE
#define SHA1_SIZE               20
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;
static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(sizeof(*saved_key),  self->params.max_keys_per_crypt);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void securezip_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

// The KDF is not quite HMAC-SHA1
static int securezip_decrypt(struct custom_salt *cur_salt, char *password)
{
	unsigned char digest[SHA1_SIZE];
	unsigned char key[SHA1_SIZE * 2];
	unsigned char buf[64];
	unsigned char ivec[16];
	unsigned char out[ERDLEN];
	SHA_CTX ctx;
	unsigned int i;
	AES_KEY aes_decrypt_key;

	// 1
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, password, strlen(password));
	SHA1_Final(digest, &ctx);

	// 2
	memset(buf, 0x36, 64);
	for (i = 0; i < SHA1_SIZE; i++)
		buf[i] ^= digest[i];
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, buf, 64);
	SHA1_Final(key, &ctx);

	// 3
	memset(buf, 0x5c, 64);
	for (i = 0; i < SHA1_SIZE; i++)
		buf[i] ^= digest[i];
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, buf, 64);
	SHA1_Final(key + SHA1_SIZE, &ctx);

	// Decrypt ERD
	AES_set_decrypt_key(key, cur_salt->bit_length, &aes_decrypt_key);
	memcpy(ivec, cur_salt->iv, 16);
	AES_cbc_encrypt(cur_salt->erd, out, cur_salt->erd_length, &aes_decrypt_key, ivec, AES_DECRYPT);

	// Check padding, 8 bytes out of 16 should be enough.
	return memcmp(out + cur_salt->erd_length - 16, "\x10\x10\x10\x10\x10\x10\x10\x10", 8) == 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		if (securezip_decrypt(cur_salt, saved_key[index])) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_securezip = {
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
		securezip_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		securezip_common_valid,
		fmt_default_split,
		fmt_default_binary,
		securezip_common_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		securezip_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

/*
 * STRIP cracker patch for JtR. Hacked together during September of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if !__s390__

#if FMT_EXTERNS_H
extern struct fmt_main fmt_strip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_strip);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "aes.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "strip_common.h"
#include "pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL            "STRIP"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              1
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA1 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char master[MIN_KEYS_PER_CRYPT][32];
		unsigned char output[24];
		unsigned char *iv_in;
		unsigned char iv_out[16];
		int size,i;
		int page_sz = 1008; /* 1024 - strlen(SQLITE_FILE_HEADER) */
		int reserve_sz = 16; /* for HMAC off case */
		AES_KEY akey;

#ifdef SIMD_COEF_32
		int len[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			len[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, len, cur_salt->salt, 16, ITERATIONS, pout, 32, 0);
#else
		pbkdf2_sha1((unsigned char *)saved_key[index],
		       strlen(saved_key[index]), cur_salt->salt,
		       16, ITERATIONS, master[0], 32, 0);
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			// memcpy(output, SQLITE_FILE_HEADER, FILE_HEADER_SZ);
			size = page_sz - reserve_sz;
			iv_in = cur_salt->data + size + 16;
			memcpy(iv_out, iv_in, 16);

			AES_set_decrypt_key(master[i], 256, &akey);
			/*
			 * Decrypting 8 bytes from offset 16 is enough since the
			 * verify_page function looks at output[16..23] only.
			 */
			AES_cbc_encrypt(cur_salt->data + 16, output + 16, 8, &akey, iv_out, AES_DECRYPT);
			if (strip_verify_page(output) == 0) {
				cracked[index+i] = 1;
			}
			else
				cracked[index+i] = 0;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void strip_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_strip = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		strip_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		strip_valid,
		fmt_default_split,
		fmt_default_binary,
		strip_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		strip_set_key,
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

#else /* __s390__ */

#if !defined(FMT_EXTERNS_H) && !defined(FMT_REGISTERS_H)
#warning ": STRIP: Format disabled on this arch"
#endif

#endif /* __s390__ */

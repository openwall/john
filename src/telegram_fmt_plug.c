/*
 * Format for cracking Telegram Desktop passcodes.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * All credit goes to "TelegramDesktopLocalStorage" project by Miha Zupan for
 * making this work possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_telegram;
#elif FMT_REGISTERS_H
john_register_one(&fmt_telegram);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1  // tuned on Intel Xeon E5-2670

#include "arch.h"
#include "formats.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "sha.h"
#include "pbkdf2_hmac_sha1.h"
#include "pbkdf2_hmac_sha512.h"
#include "telegram_common.h"

#define FORMAT_LABEL            "telegram"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$telegram$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1/SHA512 " SHA1_ALGORITHM_NAME " AES"
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1/SHA512 32/" ARCH_BITS_STR " AES"
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint64_t)
#ifdef SIMD_COEF_32
#define SHA1_LOOP_CNT            (SIMD_COEF_32 * SIMD_PARA_SHA1)
#define SHA512_LOOP_CNT          (SIMD_COEF_64 * SIMD_PARA_SHA512)
#define MIN_KEYS_PER_CRYPT       (SIMD_COEF_32 * SIMD_PARA_SHA1 * SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT       (SIMD_COEF_32 * SIMD_PARA_SHA1 * SIMD_PARA_SHA512)
#else
#define SHA1_LOOP_CNT            1
#define SHA512_LOOP_CNT          1
#define MIN_KEYS_PER_CRYPT       1
#define MAX_KEYS_PER_CRYPT       1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(cracked);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	const int inc = (cur_salt->version == 1) ? SHA1_LOOP_CNT : SHA512_LOOP_CNT;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += inc) {
		unsigned char pkey[MIN_KEYS_PER_CRYPT][256]; /* 2048 bits, yes */
		int i;

		if (cur_salt->version == 1) {
#ifdef SIMD_COEF_32
			int len[MIN_KEYS_PER_CRYPT];
			unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];

			for (i = 0; i < inc; ++i) {
				len[i] = strlen(saved_key[index + i]);
				pin[i] = (unsigned char*)saved_key[index + i];
				pout[i] = pkey[i];
			}
			pbkdf2_sha1_sse((const unsigned char **)pin, len, cur_salt->salt, cur_salt->salt_length,
			                cur_salt->iterations, pout, 136 /* 256 */, 0);
#else
			for (i = 0; i < inc; i++) {
				pbkdf2_sha1((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]),
				            cur_salt->salt, cur_salt->salt_length, cur_salt->iterations,
				            pkey[i], 136, 0);
			}
#endif
		} else {  /* (cur_salt->version == 2) */
#ifdef SIMD_COEF_64
			int len[MIN_KEYS_PER_CRYPT];
			unsigned char pbkdf2_key[MIN_KEYS_PER_CRYPT][64];
			unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];

			for (i = 0; i < inc; i++) {
				SHA512_CTX ctx;

				SHA512_Init(&ctx);
				SHA512_Update(&ctx, (unsigned char*)cur_salt->salt, cur_salt->salt_length);
				SHA512_Update(&ctx, (unsigned char*)saved_key[index + i], strlen(saved_key[index + i]));
				SHA512_Update(&ctx, (unsigned char*)cur_salt->salt, cur_salt->salt_length);
				SHA512_Final(pbkdf2_key[i], &ctx);

				len[i] = 64;
				pin[i] = pbkdf2_key[i];
				pout[i] = pkey[i];
			}
			pbkdf2_sha512_sse((const unsigned char **)pin, len, cur_salt->salt, cur_salt->salt_length,
			                  cur_salt->iterations, pout, 136 /* 256 */, 0);
#else
			for (i = 0; i < inc; i++) {
				unsigned char pbkdf2_key[64];
				SHA512_CTX ctx;

				SHA512_Init(&ctx);
				SHA512_Update(&ctx, (unsigned char*)cur_salt->salt, cur_salt->salt_length);
				SHA512_Update(&ctx, (unsigned char*)saved_key[index + i], strlen(saved_key[index + i]));
				SHA512_Update(&ctx, (unsigned char*)cur_salt->salt, cur_salt->salt_length);
				SHA512_Final(pbkdf2_key, &ctx);

				pbkdf2_sha512(pbkdf2_key, 64, cur_salt->salt, cur_salt->salt_length,
				              cur_salt->iterations, pkey[i], 136, 0);
			}
#endif
		}

		for (i = 0; i < inc; i++) {
			if (telegram_check_password(pkey[i], cur_salt)) {
				cracked[index + i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
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

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_telegram = {
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
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		telegram_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		telegram_valid,
		fmt_default_split,
		fmt_default_binary,
		telegram_get_salt,
		{
			telegram_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
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

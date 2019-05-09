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

#include "formats.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "sha.h"
#include "aes_ige.h"
#include "pbkdf2_hmac_sha1.h"
#include "telegram_common.h"

#define FORMAT_LABEL            "telegram"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$telegram$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME " AES"
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 32/" ARCH_BITS_STR " AES"
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint64_t)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA1 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
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

static int check_password(unsigned char *authkey, struct custom_salt *cs)
{
	AES_KEY aeskey;
	unsigned char data_a[48];
	unsigned char data_b[48];
	unsigned char data_c[48];
	unsigned char data_d[48];
	unsigned char sha1_a[20];
	unsigned char sha1_b[20];
	unsigned char sha1_c[20];
	unsigned char sha1_d[20];
	unsigned char message_key[16];
	unsigned char aes_key[32];
	unsigned char aes_iv[32];
	unsigned char encrypted_data[ENCRYPTED_BLOB_LEN];
	unsigned char decrypted_data[ENCRYPTED_BLOB_LEN];
	int encrypted_data_length = cs->encrypted_blob_length - 16;
	SHA_CTX ctx;

	// setup buffers
	memcpy(message_key, cs->encrypted_blob, 16);
	memcpy(encrypted_data, cs->encrypted_blob + 16, encrypted_data_length);

	memcpy(data_a, message_key, 16);
	memcpy(data_b + 16, message_key, 16);
	memcpy(data_c + 32, message_key, 16);
	memcpy(data_d, message_key, 16);

	memcpy(data_a + 16, authkey + 8, 32);
	memcpy(data_b, authkey + 40, 16);
	memcpy(data_b + 32, authkey + 56, 16);
	memcpy(data_c, authkey + 72, 32);
	memcpy(data_d + 16, authkey + 104, 32);

	// kdf
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_a, 48);
	SHA1_Final(sha1_a, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_b, 48);
	SHA1_Final(sha1_b, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_c, 48);
	SHA1_Final(sha1_c, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_d, 48);
	SHA1_Final(sha1_d, &ctx);

	memcpy(aes_key, sha1_a, 8);
	memcpy(aes_key + 8, sha1_b + 8, 12);
	memcpy(aes_key + 20, sha1_c + 4, 12);

	memcpy(aes_iv, sha1_a + 8, 12);
	memcpy(aes_iv + 12, sha1_b, 8);
	memcpy(aes_iv + 20, sha1_c + 16, 4);
	memcpy(aes_iv + 24, sha1_d, 8);

	// decrypt
	AES_set_decrypt_key(aes_key, 256, &aeskey);
	JtR_AES_ige_encrypt(encrypted_data, decrypted_data, encrypted_data_length, &aeskey, aes_iv, AES_DECRYPT);

	// verify
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, decrypted_data, encrypted_data_length);
	SHA1_Final(sha1_a, &ctx);

	return !memcmp(sha1_a, message_key, 16);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
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
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char pkey[MIN_KEYS_PER_CRYPT][256]; /* 2048 bits, yes */
		int i;
#ifdef SIMD_COEF_32
		int len[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			len[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = pkey[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, len, cur_salt->salt, cur_salt->salt_length, cur_salt->iterations, pout, 136 /* 256 */, 0);
#else
		for (i = 0; i < MIN_KEYS_PER_CRYPT; i++) {
			pbkdf2_sha1((unsigned char *)saved_key[index+i],
					strlen(saved_key[index+i]),
					cur_salt->salt, cur_salt->salt_length, cur_salt->iterations,
					pkey[i], 136, 0);
		}
#endif

		for (i = 0; i < MIN_KEYS_PER_CRYPT; i++) {
			if (check_password(pkey[i], cur_salt)) {
				cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			} else {
				cracked[index+i] = 0;
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
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

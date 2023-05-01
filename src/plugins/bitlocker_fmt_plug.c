/*
 * JtR format to crack BitLocker hashes.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Big thanks to Joachim Metz and Elena Ago for making this format possible.
 *
 * http://jessekornblum.com/publications/di09.pdf (Implementing BitLocker Drive
 * Encryption for Forensic Analysis) by Jesse D. Kornblum is a useful reference.
 *
 * Tested with Windows 8.1 and 10 BitLocker volumes. AES-CBC and XTS-AES modes
 * are supported. BitLocker To Go is supported.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_bitlocker;
#elif FMT_REGISTERS_H
john_register_one(&fmt_bitlocker);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "../arch.h"
#include "../misc.h"
#include "../common.h"
#include "../formats.h"
#include "../params.h"
#include "../unicode.h"
#include "../options.h"
#include "../johnswap.h"
#include "../aes.h"
#include "../aes_ccm.h"
#include "../sha2.h"
#include "../jumbo.h"
#include "../bitlocker_common.h"
#define CPU_FORMAT              1
#include "../bitlocker_variable_code.h"

#ifndef OMP_SCALE
#define OMP_SCALE               1	// MKPC and OMP_SCALE tuned for core i7
#endif

#define FORMAT_LABEL            "BitLocker"
#define ALGORITHM_NAME          "SHA-256 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;
static bitlocker_custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key),  self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (bitlocker_custom_salt *)salt;
}

static void bitlocker_set_key(char *key, int index)
{
	/* Convert key to UTF-16LE (--encoding aware) */
	enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
}

// borrowed from libbde project
struct libbde_password_key_data
{
        // the last calculated SHA256 hash
        uint8_t last_sha256_hash[32];

        // the initial calculated SHA256 hash
        uint8_t initial_sha256_hash[32];

        uint8_t salt[16];

        uint64_t iteration_count;
};

// derived from libbde's libbde_password_calculate_key
static void bitlocker_kdf(unsigned char *password_hash, unsigned char *out)
{
	struct libbde_password_key_data pkd;
	SHA256_CTX ctx;
	uint64_t ic;

	memset(&pkd, 0, sizeof(struct libbde_password_key_data));
	memcpy(pkd.initial_sha256_hash, password_hash, 32);
	memcpy(pkd.salt, cur_salt->salt, cur_salt->salt_length);

	for (ic = 0; ic < cur_salt->iterations; ic++) {
		SHA256_Init(&ctx);
#if ARCH_LITTLE_ENDIAN
		pkd.iteration_count = ic;
#else
		pkd.iteration_count = JOHNSWAP64(ic);
#endif
		SHA256_Update(&ctx, &pkd, sizeof(struct libbde_password_key_data));
		SHA256_Final(pkd.last_sha256_hash, &ctx);
	}

	memcpy(out, pkd.last_sha256_hash, 32); // this is the aes-ccm key
}

#ifdef BITLOCKER_DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
		unsigned char *passwordBuf;
		int passwordBufSize, i;
		unsigned char out[MAX_KEYS_PER_CRYPT][32];
		SHA256_CTX ctx;
		unsigned char output[256] = { 0 };
		uint32_t data_size = 0;
		uint32_t version = 0;
		unsigned char *vmk_blob = NULL; // contains volume master key
		unsigned char v1, v2;

		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			// do double-sha256 of password encoded in "utf-16-le"
			passwordBuf = (unsigned char*)saved_key[index+i];
			passwordBufSize = strlen16((UTF16*)passwordBuf) * 2;
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, passwordBuf, passwordBufSize);
			SHA256_Final(out[i], &ctx);
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, out[i], 32);
			SHA256_Final(out[i], &ctx);
			// run bitlocker kdf
			bitlocker_kdf(out[i], out[i]);
			libcaes_crypt_ccm(out[i], 256, 0, cur_salt->iv, IVLEN, // 0 -> decrypt mode
					cur_salt->data, cur_salt->data_size,
					output, cur_salt->data_size);
			// do known plaintext attack (kpa), version and
			// data_size checks come from libbde, v1 and v2 (vmk_blob)
			// checks come from e-ago
			version = output[20] | (output[21] << 8);
			data_size = output[16] | (output[17] << 8);
			vmk_blob = &output[16]; // the actual volume master key is at offset 28
			v1 = vmk_blob[8];
			v2 = vmk_blob[9];
			if (version == 1 && data_size == 0x2c && v1 <= 0x05 && v2 == 0x20)
				cracked[index+i] = 1;
			else {
				cracked[index+i] = 0;
#ifdef BITLOCKER_DEBUG
				print_hex(output, cur_salt->data_size);
#endif
			}
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

struct fmt_main fmt_bitlocker = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		bitlocker_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		bitlocker_common_valid,
		fmt_default_split,
		fmt_default_binary,
		bitlocker_common_get_salt,
		{
			bitlocker_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		bitlocker_set_key,
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

/*
 * AxCrypt 1.x encrypted files cracker patch for JtR.
 * Written in 2016 by Fist0urs <eddy.maaalou at gmail.com>.
 *
 * This software is Copyright (c) 2016, Fist0urs <eddy.maaalou at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_axcrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_axcrypt);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "dyna_salt.h"
#include "sha.h"
#include "aes.h"
#include "axcrypt_common.h"
#include "memdbg.h"

#define FORMAT_LABEL            "AxCrypt"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "SHA1 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125 /* actual max is 250 */
#define BINARY_SIZE             0
#define SALT_SIZE               sizeof(struct custom_salt *)
#define BINARY_ALIGN            MEM_ALIGN_NONE
#define SALT_ALIGN              sizeof(struct custom_salt *)
/* constant value recommended by FIPS */
#define AES_WRAPPING_IV         "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6"
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

#define PUT_64BITS_XOR_MSB(cp, value) ( \
		(cp)[0] ^= (unsigned char)((value)), \
		(cp)[1] ^= (unsigned char)((value) >> 8), \
		(cp)[2] ^= (unsigned char)((value) >> 16), \
		(cp)[3] ^= (unsigned char)((value) >> 24 ) )

static char (*saved_key) [PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
				sizeof(*saved_key));
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
	cur_salt = *(struct custom_salt **) salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		/*
		 * NUMBER_AES_BLOCKS = 2
		 * AES_BLOCK_SIZE = 16
		 */

		unsigned char KEK[20];
		union {
			unsigned char b[16];
			uint32_t w[4];
		} lsb;

		union {
			unsigned char b[16];
			uint32_t w[4];
		} cipher;

		AES_KEY akey;
		SHA_CTX ctx;

		int i, j, nb_iterations = cur_salt->key_wrapping_rounds;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (unsigned char *)saved_key[index], strlen(saved_key[index]));
		/* if key-file provided */
		if (cur_salt->keyfile != NULL)
			SHA1_Update(&ctx, (unsigned char *) cur_salt->keyfile, strlen(cur_salt->keyfile));
		SHA1_Final(KEK, &ctx);

		/* hash XOR salt => KEK */
		for (i = 0; i < sizeof(cur_salt->salt); i++)
			KEK[i] ^= cur_salt->salt[i];

		memcpy(lsb.b, cur_salt->wrappedkey + 8, 16);

		AES_set_decrypt_key(KEK, 128, &akey);

		/* set msb */
		memcpy(cipher.b, cur_salt->wrappedkey, 8);

		/* custom AES un-wrapping loop */
		for (j = nb_iterations - 1; j >= 0; j--) {

			/* 1st block treatment */
			/* MSB XOR (NUMBER_AES_BLOCKS * j + i) */
			PUT_64BITS_XOR_MSB(cipher.b, 2 * j + 2);
			/* R[i] */
			cipher.w[2] = lsb.w[2];
			cipher.w[3] = lsb.w[3];
			/* AES_ECB(KEK, (MSB XOR (NUMBER_AES_BLOCKS * j + i)) | R[i]) */
			AES_decrypt(cipher.b, cipher.b, &akey);
			lsb.w[2] = cipher.w[2];
			lsb.w[3] = cipher.w[3];

			/* 2nd block treatment */
			PUT_64BITS_XOR_MSB(cipher.b, 2 * j + 1);
			cipher.w[2] = lsb.w[0];
			cipher.w[3] = lsb.w[1];
			AES_decrypt(cipher.b, cipher.b, &akey);
			lsb.w[0] = cipher.w[2];
			lsb.w[1] = cipher.w[3];
		}

		if (!memcmp(cipher.b, AES_WRAPPING_IV, 8)) {
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
	return cracked[index];
}

static void axcrypt_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_axcrypt =
{
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		axcrypt_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		axcrypt_valid,
		fmt_default_split,
		fmt_default_binary,
		axcrypt_get_salt,
		{
			axcrypt_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		NULL,
		set_salt,
		axcrypt_set_key,
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

#endif

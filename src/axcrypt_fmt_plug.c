/*
 * AxCrypt 1.x and 2.x encrypted files cracker patch for JtR.
 * Written in 2016 by Fist0urs <eddy.maaalou at gmail.com>.
 *
 * This software is Copyright (c) 2016, Fist0urs <eddy.maaalou at gmail.com>,
 * Copyright (c) 2018, Dhiru Kholia, and it is hereby released to the general
 * public under the following terms:
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
#include "pbkdf2_hmac_sha512.h"
#define VERSION_1_SUPPORT 1
#define VERSION_2_SUPPORT 1
#include "axcrypt_variable_code.h"

#define FORMAT_LABEL            "AxCrypt"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "PBKDF2-SHA512/SHA1 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125 /* actual max is 250 */
#define BINARY_SIZE             0
#define SALT_SIZE               sizeof(struct custom_salt *)
#define BINARY_ALIGN            MEM_ALIGN_NONE
#define SALT_ALIGN              sizeof(struct custom_salt *)
/* constant value recommended by FIPS */
#define AES_WRAPPING_IV         "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6"

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA512 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

#define PUT_64BITS_XOR_MSB(cp, value) ( \
		(cp)[0] ^= (unsigned char)((value)), \
		(cp)[1] ^= (unsigned char)((value) >> 8), \
		(cp)[2] ^= (unsigned char)((value) >> 16), \
		(cp)[3] ^= (unsigned char)((value) >> 24 ) )

#define PUT_64BITS_XOR_LSB(cp, value) ( \
		(cp)[4] ^= (unsigned char)((value) >> 24), \
		(cp)[5] ^= (unsigned char)((value) >> 16), \
		(cp)[6] ^= (unsigned char)((value) >> 8), \
		(cp)[7] ^= (unsigned char)((value)) )

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

static int axcrypt_valid(char *ciphertext, struct fmt_main *self)
{
	return axcrypt_common_valid(ciphertext, self, 3);
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
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		/*
		 * NUMBER_AES_BLOCKS = 2
		 * AES_BLOCK_SIZE = 16
		 */

		unsigned char KEK[32];
		AES_KEY akey;
		int i;

		if (cur_salt->version == 1) {
			// See axcrypt/AxCryptCommon/CAes.cpp (CAesWrap::UnWrap) and axcrypt/AxCrypt/CSha1.cpp (CSha1::GetKeyHash)
			// from AxCrypt-1.7.3180.0-Source.zip file. V1KeyWrap1HeaderBlock.cs, V1KeyWrap1HeaderBlock.cs and
			// V1AxCryptDocument.cs from https://bitbucket.org/axantum/axcrypt-net are also relevant.
			union {
				unsigned char b[16];
				uint32_t w[4];
			} lsb;

			union {
				unsigned char b[16];
				uint32_t w[4];
			} cipher;

			for (i = 0; i < MIN_KEYS_PER_CRYPT; i++) {
				SHA_CTX ctx;

				int k, j, nb_iterations = cur_salt->key_wrapping_rounds;

				SHA1_Init(&ctx);
				SHA1_Update(&ctx, (unsigned char *)saved_key[index+i], strlen(saved_key[index+i]));
				/* if key-file provided */
				if (cur_salt->keyfile != NULL)
					SHA1_Update(&ctx, (unsigned char *) cur_salt->keyfile, strlen(cur_salt->keyfile));
				SHA1_Final(KEK, &ctx);

				/* hash XOR salt => KEK */
				for (k = 0; k < 16; k++)
					KEK[k] ^= cur_salt->salt[k];

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
					cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
					any_cracked |= 1;
				}
			}
		}
		else if (cur_salt->version == 2) {
			// See V2AxCryptDocument.cs for internal crypto details
			unsigned char seed[MIN_KEYS_PER_CRYPT][64];
			int i;
#ifdef SIMD_COEF_64
			int lens[MIN_KEYS_PER_CRYPT];
			unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				lens[i] = strlen(saved_key[index+i]);
				pin[i] = (unsigned char*)saved_key[index+i];
				pout[i] = seed[i];
			}
			pbkdf2_sha512_sse((const unsigned char**)pin, lens, cur_salt->deriv_salt, 32, cur_salt->deriv_iterations, pout, 64, 0);
#else
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
				pbkdf2_sha512((unsigned char*)saved_key[index+i], strlen(saved_key[index+i]), cur_salt->deriv_salt, 32, cur_salt->deriv_iterations, seed[i], 64, 0);
#endif
			for (i = 0; i < MIN_KEYS_PER_CRYPT; i++) {
				int k, j, nb_iterations = cur_salt->key_wrapping_rounds;
				int halfblocklen = 16 / 2;
				int wrappedkeylen = 56 - halfblocklen;
				unsigned char wrapped[144];
				unsigned char block[16];
				int t;

				/* ByteArrayExtensions -> Reduce */
				memset(KEK, 0, 32);
				for (k = 0; k < 64 ; k++)
					KEK[k % 32] ^= seed[i][k];

				/* hash XOR salt => KEK */
				for (k = 0; k < 32; k++)
					KEK[k] = KEK[k] ^ cur_salt->salt[k];

				AES_set_decrypt_key(KEK, 256, &akey);
				memcpy(wrapped, cur_salt->wrappedkey, 56);

				/* custom AES un-wrapping loop */
				for (j = nb_iterations - 1; j >= 0; j--) {
					for (k = wrappedkeylen / halfblocklen; k >= 1; --k) {
						t = ((wrappedkeylen / halfblocklen) * j) + k;
						// MSB(B) = A XOR t
						memcpy(block, wrapped, halfblocklen);
						PUT_64BITS_XOR_LSB(block, t);
						// LSB(B) = R[i]
						memcpy(block + halfblocklen, wrapped + k * halfblocklen, halfblocklen);
						// B = AESD(K, X xor t | R[i]) where t = (n * j) + i
						AES_decrypt(block, block, &akey);
						// A = MSB(B)
						memcpy(wrapped, block, halfblocklen);
						// R[i] = LSB(B)
						memcpy(wrapped + k * halfblocklen, block + halfblocklen, halfblocklen);
					}
				}
				if (!memcmp(wrapped, AES_WRAPPING_IV, 8)) {
					cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
					any_cracked |= 1;
				}
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

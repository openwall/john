/*
 * JtR format to crack password protected Cardano 128-byte length legacy secret Keys (a.k.a XPrv).
 *
 * This software is Copyright (c) 2022, Pal Dorogi <pal dot dorogi at gmail.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cardano;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cardano);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE 1

#include "../cardano_common.h"
#include "../blake2.h"
#include "../pbkdf2_hmac_sha512.h"
#include "../chacha.h"
#include "../ed25519.h"

#define FORMAT_NAME         "Cardano Encrypted 128-byte Secret Key (a.k.a XPrv)"
#define FORMAT_LABEL        "cardano"
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME      "PBKDF2-SHA512/BLAKE2b/ChaCha20 " SHA512_ALGORITHM_NAME
#else
#if ARCH_BITS >= 64
#define ALGORITHM_NAME      "PBKDF2-SHA512/BLAKE2b/ChaCha20 64/" ARCH_BITS_STR
#else
#define ALGORITHM_NAME      "PBKDF2-SHA512/BLAKE2b/ChaCha20 32/" ARCH_BITS_STR
#endif
#endif
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x107
#define BINARY_SIZE         0
#define BINARY_ALIGN        1
#define SALT_SIZE           sizeof(struct custom_salt)
#define SALT_ALIGN          1
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA512
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1
#endif
#define PLAINTEXT_LENGTH    125

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(cracked);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void cardano_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	// KDF2 params
	static const int kdf_rounds = 15000;
	static const char kdf_salt[] = "encrypted wallet salt";
	static int kdf_salt_len = sizeof(kdf_salt);

	// ChaCha20 params
	static const int chacha_rounds = 20;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		int i;

		unsigned char kdf_out[MIN_KEYS_PER_CRYPT][BUF_SIZE];
		unsigned char blake_out[MIN_KEYS_PER_CRYPT][PWD_HASH_LEN];

#if SIMD_COEF_64
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT]; // blake2b_256 hashed password
		unsigned char *pout[MIN_KEYS_PER_CRYPT]; // 40-byte length KDF
#endif

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			// blake2b_256 hash of the password.
			blake2b(blake_out[i], (unsigned char *)saved_key[index + i], NULL, PWD_HASH_LEN,
			        strlen(saved_key[index + i]), 0);
#if SIMD_COEF_64
			lens[i] = PWD_HASH_LEN;
			pin[i] = (unsigned char *)blake_out[i];
			pout[i] = (unsigned char *)kdf_out[i];
		}

		pbkdf2_sha512_sse((const unsigned char **)pin, lens, (unsigned char *)kdf_salt, kdf_salt_len, kdf_rounds, pout, BUF_SIZE, 0);
#else
			pbkdf2_sha512(blake_out[i], PWD_HASH_LEN,
			              (unsigned char *)kdf_salt, kdf_salt_len, kdf_rounds, kdf_out[i], BUF_SIZE, 0);
		}
#endif

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			struct chacha_ctx ckey;
			ed25519ext_secret_key dsk;
			ed25519_public_key pk;

			// Decrypt the encrypted esk with the retrieved KDFs.
			chacha_keysetup(&ckey, kdf_out[i], KEY_SIZE * 8);
			chacha_ivsetup(&ckey, (unsigned char *)kdf_out[i] + KEY_SIZE, NULL, IV_SIZE);
			chacha_decrypt_bytes(&ckey, cur_salt->esk, dsk, SK_LEN, chacha_rounds);

			// Generate the public key  from candidate decrypted sk and
			// compare it with the stored pk in the secret a.k.a XPrv.
			ed25519ext_publickey(dsk, (unsigned char *)pk);

			if (!memcmp(cur_salt->esk + SK_LEN, pk, PK_LEN)) {
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

struct fmt_main fmt_cardano = {
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
		{ NULL},
		{ FORMAT_TAG},
		cardano_tests
	},
	{
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		cardano_valid,
		fmt_default_split,
		fmt_default_binary,
		cardano_get_salt,
		{ NULL},
		fmt_default_source,
		{ fmt_default_binary_hash},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		cardano_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{ fmt_default_get_hash},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif                          /* plugin stanza */

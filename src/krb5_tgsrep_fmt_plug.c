/*
 * This software is Copyright (c) 2023 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_krb5tgs_aes;
#elif FMT_REGISTERS_H
john_register_one(&fmt_krb5tgs_aes);
#else

#include <stdio.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "common.h"
#include "hmac_sha.h"
#include "pbkdf2_hmac_sha1.h"
#include "krb5_common.h"
#include "krb5_tgsrep_common.h"

#define FORMAT_LABEL            "krb5tgs-sha1"
#define FORMAT_NAME             "Kerberos 5 TGS-REP etype 17/18"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2 HMAC-SHA1 AES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2 HMAC-SHA1 AES 32/" ARCH_BITS_STR
#endif
#define MIN_PLAINTEXT_LENGTH    0
#define PLAINTEXT_LENGTH        125
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA1 * 1)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;
static int new_keys;

static krb5tgsrep_salt *cur_salt;

static unsigned char constant[16];
static unsigned char ke_input[16];
static unsigned char ki_input[16];

static void init(struct fmt_main *self)
{
	unsigned char usage[5];

	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(self->params.max_keys_per_crypt, sizeof(*saved_key), MEM_ALIGN_CACHE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);

	/*
	 * We could have just hard-coded all nfolded constants below (the
	 * OpenCL format does) but placing this here is out of hot code and
	 * keeps some resemblance with reference code.
	 *
	 * Generate 128 bits constant from 64 bits of "kerberos" string:
	 */
	nfold(8 * 8, (unsigned char*)"kerberos", 128, constant);

	/*
	 * The "well-known constant" used for the DK function is the key
	 * usage number, expressed as four octets in big-endian order,
	 * followed by one octet as below.
	 *
	 * Kc = DK(base-key, usage | 0x99);
	 * Ke = DK(base-key, usage | 0xAA);
	 * Ki = DK(base-key, usage | 0x55);
	 */
	memset(usage, 0, sizeof(usage));
	usage[3] = 0x02;        // key number in big-endian format

	usage[4] = 0xAA;        // used to derive Ke
	nfold(sizeof(usage) * 8, usage, sizeof(ke_input) * 8, ke_input);

	usage[4] = 0x55;        // used to derive Ki
	nfold(sizeof(usage) * 8, usage, sizeof(ki_input) * 8, ki_input);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = *(krb5tgsrep_salt**)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	const int key_size = (cur_salt->etype == 17) ? 16 : 32;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT)
	{
		unsigned char tkey[MIN_KEYS_PER_CRYPT][32];
		int i;

#ifdef SIMD_COEF_32
		int len[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			len[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = tkey[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, len, (unsigned char*)cur_salt->salt, strlen(cur_salt->salt), 4096, pout, key_size, 0);
#else
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			pbkdf2_sha1((const unsigned char*)saved_key[index], strlen(saved_key[index+i]),
			            (unsigned char*)cur_salt->salt, strlen(cur_salt->salt),
			            4096, tkey[i], key_size, 0);
		}
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			unsigned char Ki[32];
			unsigned char plaintext[cur_salt->edata2len];
			unsigned char checksum[20];
			unsigned char base_key[32];
			unsigned char Ke[32];

			dk(base_key, tkey[i], key_size, constant, 16);
			dk(Ke, base_key, key_size, ke_input, 16);
			krb_decrypt(cur_salt->edata2, cur_salt->edata2len, plaintext, Ke, key_size);
			// derive checksum of plaintext
			dk(Ki, base_key, key_size, ki_input, 16);
			hmac_sha1(Ki, key_size, plaintext, cur_salt->edata2len, checksum, 20);

			if (!memcmp(checksum, cur_salt->edata1, 12)) {
				cracked[index+i] = 1;
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
	return cracked[index];
}

struct fmt_main fmt_krb5tgs_aes = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		MIN_PLAINTEXT_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"etype"
		},
		{ FORMAT_TAG },
		krb5_tgsrep_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		krb5_tgsrep_valid,
		fmt_default_split,
		fmt_default_binary,
		krb5_tgsrep_get_salt,
		{
			krb5_tgsrep_etype
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
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

#endif
#endif /* HAVE_LIBCRYPTO */

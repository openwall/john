/*
 * MS Office 97-2003 cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2014-2019, magnum
 * Copyright (c) 2009, David Leblanc (http://offcrypto.codeplex.com/)
 *
 * License: Microsoft Public License (MS-PL)
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_oldoffice;
#elif FMT_REGISTERS_H
john_register_one(&fmt_oldoffice);
#else

#ifdef _OPENMP
#include <omp.h>
#endif

#include "oldoffice_common.h"
#include "md5.h"
#include "rc4.h"
#include "sha.h"

#define FORMAT_LABEL            "oldoffice"
#define FORMAT_NAME             "MS Office <= 2003"
#define ALGORITHM_NAME          "MD5/SHA1 RC4 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        64
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif

/* Password encoded in UCS-2 */
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
/* UCS-2 password length, in octets */
static int *saved_len;
/* Last hash with this salt and plain */
static unsigned char (*mitm_key)[16];
static unsigned char (*rc4_key)[16];
static int any_cracked;
static size_t cracked_size;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = 3 * PLAINTEXT_LENGTH > 125 ?
			125 : 3 * PLAINTEXT_LENGTH;
	saved_key = mem_alloc(self->params.max_keys_per_crypt *
	                      sizeof(*saved_key));
	saved_len = mem_alloc(self->params.max_keys_per_crypt *
	                      sizeof(*saved_len));
	mitm_key = mem_alloc(self->params.max_keys_per_crypt *
	                     sizeof(*mitm_key));
	rc4_key = mem_alloc(self->params.max_keys_per_crypt *
	                    sizeof(*rc4_key));
	any_cracked = 0;
	cracked_size = sizeof(*oo_cracked) * self->params.max_keys_per_crypt;
	oo_cracked = mem_calloc(1, cracked_size);
}

static void done(void)
{
	MEM_FREE(oo_cracked);
	MEM_FREE(rc4_key);
	MEM_FREE(mitm_key);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	oo_cur_salt = salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		int i;

		if (oo_cur_salt->type < 3) {
			MD5_CTX ctx;
			unsigned char hashBuf[21 * 16];
			unsigned char key_hash[16];

			MD5_Init(&ctx);
			MD5_Update(&ctx, saved_key[index], saved_len[index]);
			MD5_Final(key_hash, &ctx);
			for (i = 0; i < 16; i++) {
				memcpy(hashBuf + i * 21, key_hash, 5);
				memcpy(hashBuf + i * 21 + 5, oo_cur_salt->salt, 16);
			}
			MD5_Init(&ctx);
			MD5_Update(&ctx, hashBuf, 21 * 16);
			MD5_Final(mitm_key[index], &ctx);
			memset(&mitm_key[index][5], 0, 11); // Truncate to 40 bits

			MD5_Init(&ctx);
			MD5_Update(&ctx, mitm_key[index], 9);
			MD5_Final(rc4_key[index], &ctx);
		}
		else {
			SHA_CTX ctx;
			unsigned char H0[24];
			unsigned char key_hash[20];

			SHA1_Init(&ctx);
			SHA1_Update(&ctx, oo_cur_salt->salt, 16);
			SHA1_Update(&ctx, saved_key[index], saved_len[index]);
			SHA1_Final(H0, &ctx);
			memset(&H0[20], 0, 4);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, H0, 24);
			SHA1_Final(key_hash, &ctx);

			if (oo_cur_salt->type < 4) {
				memcpy(mitm_key[index], key_hash, 5);
				memset(&mitm_key[index][5], 0, 11); // Truncate to 40 bits
			} else
			if (oo_cur_salt->type == 5) {
				memcpy(mitm_key[index], key_hash, 7);
				memset(&mitm_key[index][7], 0, 9); // Truncate to 56 bits
			} else
				memcpy(mitm_key[index], key_hash, 16);

		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	binary_blob *cur_binary = ((fmt_data*)binary)->blob;
	int index;

	if (any_cracked) {
		memset(oo_cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		RC4_KEY key;

		if (oo_cur_salt->type < 3) {
			MD5_CTX ctx;
			unsigned char pwdHash[16];
			unsigned char hashBuf[32];

			if (cur_binary->has_mitm && memcmp(cur_binary->mitm, mitm_key[index], 5))
				continue;

			RC4_set_key(&key, 16, rc4_key[index]); /* rc4Key */
			RC4(&key, 16, cur_binary->verifier, hashBuf); /* encryptedVerifier */
			RC4(&key, 16, cur_binary->verifierHash, hashBuf + 16); /* encryptedVerifierHash */
			/* hash the decrypted verifier */
			MD5_Init(&ctx);
			MD5_Update(&ctx, hashBuf, 16);
			MD5_Final(pwdHash, &ctx);
			if (!memcmp(pwdHash, hashBuf + 16, 16))
#ifdef _OPENMP
#pragma omp critical
#endif
			{
				any_cracked = oo_cracked[index] = 1;
				cur_binary->has_mitm = 1;
				memcpy(cur_binary->mitm, mitm_key[index], 5);
			}
		}
		else {
			SHA_CTX ctx;
			unsigned char Hfinal[20];
			unsigned char DecryptedVerifier[16];
			unsigned char DecryptedVerifierHash[20];

			if (oo_cur_salt->type == 3 && !cur_binary->has_extra &&
			    cur_binary->has_mitm && memcmp(cur_binary->mitm, mitm_key[index], 5))
				continue;

			RC4_set_key(&key, 16, mitm_key[index]); /* dek */
			RC4(&key, 16, cur_binary->verifier, DecryptedVerifier);
			RC4(&key, 16, cur_binary->verifierHash, DecryptedVerifierHash);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, DecryptedVerifier, 16);
			SHA1_Final(Hfinal, &ctx);
			if (memcmp(Hfinal, DecryptedVerifierHash, 16))
				continue;
			if (oo_cur_salt->type == 3 && cur_binary->has_extra) {
				SHA_CTX ctx;
				unsigned char H0[24];
				unsigned char key_hash[20];
				uint8_t data[32];
				int i, num_zero = 0;

				SHA1_Init(&ctx);
				SHA1_Update(&ctx, oo_cur_salt->salt, 16);
				SHA1_Update(&ctx, saved_key[index], saved_len[index]);
				SHA1_Final(H0, &ctx);
				memcpy(&H0[20], "\1\0\0\0", 4);
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, H0, 24);
				SHA1_Final(key_hash, &ctx);

				memset(key_hash + 40/8, 0, sizeof(key_hash) - 40/8);
				RC4_set_key(&key, 16, key_hash);
				RC4(&key, 32, cur_binary->extra, data);
				for (i = 0; i < 32; i++)
					if (data[i] == 0)
						num_zero++;
				if (num_zero < 10)
					continue;
			}
			/* If we got here, looks like we have a candidate */
#ifdef _OPENMP
#pragma omp critical
#endif
			{
				any_cracked = oo_cracked[index] = 1;
				if (oo_cur_salt->type < 4) {
					cur_binary->has_mitm = 1;
					memcpy(cur_binary->mitm, mitm_key[index], 5);
				}
			}
		}
	}

	return any_cracked;
}

static void set_key(char *key, int index)
{
	/* convert key to UTF-16LE */
	saved_len[index] = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
	if (saved_len[index] < 0)
		saved_len[index] = strlen16(saved_key[index]);
	saved_len[index] <<= 1;
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
}

struct fmt_main fmt_oldoffice = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_ENC | FMT_SPLIT_UNIFIES_CASE | FMT_BLOB,
		{
			"hash type [0-1:MD5+RC4-40 3:SHA1+RC4-40 4:SHA1+RC4-128 5:SHA1+RC4-56]",
		},
		{ FORMAT_TAG },
		oldoffice_tests
	}, {
		init,
		done,
		fmt_default_reset,
		oldoffice_prepare,
		oldoffice_valid,
		oldoffice_split,
		oldoffice_get_binary,
		oldoffice_get_salt,
		{
			oldoffice_hash_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		oldoffice_salt_hash,
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
		oldoffice_cmp_one,
		oldoffice_cmp_exact
	}
};

#endif /* plugin stanza */

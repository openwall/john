/*
 * Cracker for Oracle's O5LOGON protocol hashes. Hacked together during
 * September of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * O5LOGON is used since version 11g. CVE-2012-3137 applies to Oracle 11.1
 * and 11.2 databases. Oracle has "fixed" the problem in version 11.2.0.3.
 * Oracle 12 support is now added as well.
 *
 * This software is
 * Copyright (c) 2012-2025 magnum
 * Copyright (c) 2014 Harrison Neal
 * Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_o5logon;
#elif FMT_REGISTERS_H
john_register_one(&fmt_o5logon);
#else

#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha.h"
#include "aes.h"
#include "md5.h"
#include "o5logon_common.h"

#define FORMAT_LABEL            "o5logon"
#define ALGORITHM_NAME          "MD5 SHA1 AES 32/" ARCH_BITS_STR
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      256

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC on super
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int *cracked, any_cracked;
static o5logon_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (o5logon_salt*)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, sizeof(*cracked) * count);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char key[24];
		unsigned char iv[16];
		AES_KEY akey;
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_key[index], saved_len[index]);
		SHA1_Update(&ctx, cur_salt->salt, 10);
		SHA1_Final(key, &ctx);
		memset(key + 20, 0, 4);

		if (cur_salt->pw_len) {
			int i;
			unsigned char s_secret[48];
			unsigned char c_secret[48];
			unsigned char combined_sk[24];
			unsigned char final_key[32];
			unsigned char password[16 + PLAINTEXT_LENGTH + 16];
			char *dec_pw = (char*)password + 16;
			int blen = (saved_len[index] + 15) / 16;
			MD5_CTX ctx;

			if (cur_salt->pw_len == blen) {
				memset(iv, 0, 16);
				AES_set_decrypt_key(key, 192, &akey);
				AES_cbc_encrypt(cur_salt->ct, s_secret, 48, &akey, iv, AES_DECRYPT);

				memset(iv, 0, 16);
				AES_set_decrypt_key(key, 192, &akey);
				AES_cbc_encrypt(cur_salt->csk, c_secret, 48, &akey, iv, AES_DECRYPT);

				for (i = 0; i < 24; i++)
					combined_sk[i] = s_secret[16 + i] ^ c_secret[16 + i];

				MD5_Init(&ctx);
				MD5_Update(&ctx, combined_sk, 16);
				MD5_Final(final_key, &ctx);
				MD5_Init(&ctx);
				MD5_Update(&ctx, combined_sk + 16, 8);
				MD5_Final(final_key + 16, &ctx);

				memset(iv, 0, 16);
				AES_set_decrypt_key(final_key, 192, &akey);
				AES_cbc_encrypt(cur_salt->pw, password, (cur_salt->pw_len + 1) * 16, &akey, iv, AES_DECRYPT);

				if (!memcmp(dec_pw, saved_key[index], saved_len[index])) {
					char *p = dec_pw + 16 * blen - 1;
					int n, pad;
					int res = 1;

					n = pad = *p;
					while (n--) {
						if (*p-- != pad) {
							res = 0;
							break;
						}
					}

					if (res) {
						cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
						any_cracked |= 1;
					}
				}
			}
		} else {
			unsigned char pt[16];

			memcpy(iv, cur_salt->ct + 16, 16);
			AES_set_decrypt_key(key, 192, &akey);
			AES_cbc_encrypt(cur_salt->ct + 32, pt, 16, &akey, iv, AES_DECRYPT);

			if (!memcmp(pt + 8, "\x08\x08\x08\x08\x08\x08\x08\x08", 8)) {
				cracked[index] = 1;
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

static void o5logon_set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_o5logon = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ FORMAT_TAG },
		o5logon_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		o5logon_valid,
		fmt_default_split,
		fmt_default_binary,
		o5logon_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		o5logon_set_key,
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

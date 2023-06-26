/*
 * Based on the work by Tim Medin
 * Port from his Pythonscript to John by Michael Kramer (SySS GmbH)
 *
 * This software is
 * Copyright (c) 2015 Michael Kramer <michael.kramer@uni-konstanz.de>,
 * Copyright (c) 2015-2023 magnum
 * Copyright (c) 2016 Fist0urs <eddy.maaalou@gmail.com>
 *
 * Modified by Fist0urs to improve performances by proceeding known-plain
 * attack, based on defined ASN1 structures (avoiding most large RC4 +
 * hmac-md5 operations).
 *
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_krb5tgs;
#elif FMT_REGISTERS_H
john_register_one(&fmt_krb5tgs);
#else

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "formats.h"
#include "common.h"
#include "dyna_salt.h"
#include "krb5_tgs_common.h"
#include "md4.h"
#include "hmacmd5.h"
#include "rc4.h"
#include "unicode.h"

#define FORMAT_LABEL         "krb5tgs"
#define ALGORITHM_NAME       "MD4 HMAC-MD5 RC4"
#define PLAINTEXT_LENGTH     125
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   64

#ifndef OMP_SCALE
#define OMP_SCALE            4 // Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*saved_K1)[16];
static int any_cracked, *cracked;
static size_t cracked_size;
static int new_keys;

static krb5tgs_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_alloc_align(sizeof(*saved_key) *
			self->params.max_keys_per_crypt,
			MEM_ALIGN_CACHE);
	saved_K1 = mem_alloc_align(sizeof(*saved_K1) *
			self->params.max_keys_per_crypt,
			MEM_ALIGN_CACHE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_K1);
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = *(krb5tgs_salt**)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, strlen(key) + 1);
	new_keys = 1;
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

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char K3[16];
#ifdef _MSC_VER
		unsigned char ddata[65536];
#else
		unsigned char ddata[cur_salt->edata2len + 1];
#endif
		unsigned char checksum[16];
		RC4_KEY rckey;

		if (new_keys) {
			const unsigned char data[4] = {2, 0, 0, 0};

			MD4_CTX ctx;
			unsigned char key[16];
			UTF16 wkey[PLAINTEXT_LENGTH + 1];
			int len;

			len = enc_to_utf16(wkey, PLAINTEXT_LENGTH,
					(UTF8*)saved_key[index],
					strlen(saved_key[index]));
			if (len <= 0) {
				saved_key[index][-len] = 0;
				len = strlen16(wkey);
			}

			MD4_Init(&ctx);
			MD4_Update(&ctx, (char*)wkey, 2 * len);
			MD4_Final(key, &ctx);

			hmac_md5(key, data, 4, saved_K1[index]);
		}

		hmac_md5(saved_K1[index], cur_salt->edata1, 16, K3);

		RC4_set_key(&rckey, 16, K3);
		RC4(&rckey, 32, cur_salt->edata2, ddata);

		 /*
			8 first bytes are nonce, then ASN1 structures
			(DER encoding: type-length-data)

			if length >= 128 bytes:
				length is on 2 bytes and type is
				\x63\x82 (encode_krb5_enc_tkt_part)
				and data is an ASN1 sequence \x30\x82
			else:
				length is on 1 byte and type is \x63\x81
				and data is an ASN1 sequence \x30\x81

			next headers follow the same ASN1 "type-length-data" scheme
		  */

		if (((!memcmp(ddata + 8, "\x63\x82", 2)) && (!memcmp(ddata + 16, "\xA0\x07\x03\x05", 4)))
			||
			((!memcmp(ddata + 8, "\x63\x81", 2)) && (!memcmp(ddata + 16, "\x03\x05\x00", 3)))) {

			/* Early-reject passed, verify checksum */
			RC4(&rckey, cur_salt->edata2len - 32, cur_salt->edata2 + 32, ddata + 32);
			hmac_md5(saved_K1[index], ddata, cur_salt->edata2len, checksum);

			if (!memcmp(checksum, cur_salt->edata1, 16)) {
				cracked[index] = 1;

#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
	}
	new_keys = 0;

	return *pcount;
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

struct fmt_main fmt_krb5tgs = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{NULL},
		{ FORMAT_TAG },
		krb5tgs_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		krb5tgs_valid,
		krb5tgs_split,
		fmt_default_binary,
		krb5tgs_get_salt,
		{NULL},
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

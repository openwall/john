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
#define SALT_ALIGN              sizeof(uint32_t)
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

static struct fmt_tests tests[] = {
	// Telegram Desktop 1.3.9 on Ubuntu 18.04 LTS
	{"$telegram$1*4000*e693c27ff92fe83a5a247cce198a8d6a0f3a89ffedc6bcddbc39586bb1bcb50b*d6fb7ebda06a23a9c42fc57c39e2c3128da4ee1ff394f17c2fc4290229e13d1c9e45c42ef1aee64903e5904c28cffd49498358fee96eb01888f2251715b7a5e71fa130918f46da5a2117e742ad7727700e924411138bb8d4359662da0ebd4f4357d96d1aa62955e44d4acf2e2ac6e0ce057f48fe24209090fd35eeac8a905aca649cafb2aade1ef7a96a7ab44a22bd7961e79a9291b7fea8749dd415f2fcd73d0293cdb533554f396625f669315c2400ebf6f1f30e08063e88b59b2d5832a197b165cdc6b0dc9d5bfa6d5e278a79fa101e10a98c6662cc3d623aa64daada76f340a657c2cbaddfa46e35c60ecb49e8f1f57bc170b8064b70aa2b22bb326915a8121922e06e7839e62075ee045b8c82751defcba0e8fb75c32f8bbbdb8b673258", "openwall123"},
	{"$telegram$1*4000*e693c27ff92fe83a5a247cce198a8d6a0f3a89ffedc6bcddbc39586bb1bcb50b*7c04a5becb2564fe4400c124f5bb5f1896117327d8a21f610bd431171f606fa6e064c088aacc59d8eae4e6dce539abdba5ea552f5855412c26284bc851465d6b31949b276f4890fc212d63d73e2ba132d6098688f2a6408b9d9d69c3db4bcd13dcc3a5f80a7926bb11eb2c99c7f02b5d9fd1ced974d18ed9d667deae4be8df6a4a97ed8fae1da90d5131a7536535a9bfa8094ca7f7465deabef00ab4c715f151d016a879197b328c74dfad5b1f854217c741cf3e0297c63c3fb4d5d672d1e31d797b2c01cb8a254f80a37b6c9a011d864c21c4145091f22839a52b6daf23ed2f350f1deb275f1b0b4146285ada0f0b168ce54234854b19ec6657ad0a92ffb0f3b86547c8b8cc3655a29797c398721e740ed606a71018d16545c78ee240ff3635", "öye"},
	// Newer version, starting with 2.1.14 beta or 2.2.0 major release
	{"$telegram$2*100000*0970f6c043d855aa895703b8a1cc086109cf081f72a77b6504f7f4bf3db06420*129294a5eac3196a4c9a88e556f7507b0957f6dd45d704db8abe607ec6d807270c02635289056256a6044a6408e7ef5d33f98c561f16f8aedd2b3ae33ddffddc63c8584dcb232c9f610953f461adb8d29da83f2b01e32db98101febffae4072703bfbfd492e1dd6abeb0926d3df2ed3b47dee4eb6c9f42ab657f89f19d7314c07e2ffc843e448c6d324e9f8d2c3e877a25b0b153736fddb35f5205737620ba2f96aa47f799366150b4de89a0c6e12caa4f03553d164ce9e2e975aadc83538e6ae3df93acb6026f97ac9f6f017a6bbc6607767e591b2c732e3c0ac844584c69dae89ca3272c996eb83b4e66976e3851cfc89be11dc602bb8c0cdf578d9a0a9dbc2296888fa5ee7e58d985a9bf9a1dbc75d2ddfd6ce222c5ee9f3bb40f6e25c2cd", "0404"},
	{"$telegram$2*100000*77461dcb457ce9539f8e4235d33bd12455b4a38446e63b52ecdf2e7b65af4476*f705dda3247df6d690dfc7f44d8c666979737cae9505d961130071bcc18eeadaef0320ac6985e4a116834c0761e55314464aae56dadb8f80ab8886c16f72f8b95adca08b56a60c4303d84210f75cfd78a3e1a197c84a747988ce2e1b247397b61041823bdb33932714ba16ca7279e6c36b75d3f994479a469b50a7b2c7299a4d7aadb775fb030d3bb55ca77b7ce8ac2f5cf5eb7bdbcc10821b8953a4734b448060246e5bb93f130d6d3f2e28b9e04f2a064820be562274c040cd849f1473d45141559fc45da4c54abeaf5ca40d2d57f8f8e33bdb232c7279872f758b3fb452713b5d91c855383f7cec8376649a53b83951cf8edd519a99e91b8a6cb90153088e35d9fed332c7253771740f49f9dc40c7da50352656395bbfeae63e10f754d24a", "hashcat"},
	{NULL}
};

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
		tests
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

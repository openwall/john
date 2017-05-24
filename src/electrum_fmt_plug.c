/*
 * JtR format to crack password protected Electrum Wallets.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Special thanks goes to Christopher Gurnee for making this work possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_electrum;
#elif FMT_REGISTERS_H
john_register_one(&fmt_electrum);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               128
#endif
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "sha2.h"
#include "jumbo.h"
#include "memdbg.h"

#define FORMAT_NAME             "Electrum Wallet"
#define FORMAT_LABEL            "electrum"
#define FORMAT_TAG              "$electrum$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "SHA256 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        125
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests electrum_tests[] = {
	// Wallets created by Electrum 1.9.8
	{"$electrum$1*d64ac297de09893a03bc540b346d5e97*0af493539c512e3ded466b4879b8a47b", "openwall123"},
	{"$electrum$1*bb7feb604201d0e74135337ca33249c4*090a4001b972c7483116471aa1598a84", "password@12345"}, // 1.x to 2.4.3 upgrade generates same hash
	// Wallet created by Electrum 2.4.3
	{"$electrum$2*ca2a36958ea86cafd91be8f4806f073a*259129742f91f72e14d048fa0a1a0acf", "openwall"},
	// Wallet created by Electrum 2.6.3
	{"$electrum$2*3e37a6b705ea4e61884433c735edd0ff*dbfeaef2ea18df11016be57ed2a66b9d", "openwall"},
	// Electrum 2.8.3 2FA wallet
	{"$electrum$2*af6348b949824312bad6fd6c16363c1c*a645e1f547174ce950884936777b3842", "openwall"},
	// Electrum 1.x wallet upgraded to 2.8.3
	{"$electrum$1*8f664b711d89cba39e1af76928832776*6c563922cf8630d46daeb10f90442499", "openwall123"},
	// Electrum 2.6.4 wallet created by selecting "import keys" option during initialization, wallet_type == "imported"
	{"$electrum$3*390c9a6dea1160f17c263cabaf8e1d74*7edc571ab41253406c9ad18fc925a4ee", "openwall"},
	// Similar wallet as above
	{"$electrum$3*e4a1a7f27bb2df7d0bbf91d769adb29b*9340ec01561bf8bc6240627bee4f84a5", "password@123456789"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;

static struct custom_salt {
	uint32_t type;
	unsigned char iv[16];
	unsigned char seed[64];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_num_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1 && value != 2 && value != 3)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // iv
		goto err;
	if (hexlenl(p, &extra) != 16 * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // encrypted data (seed part)
		goto err;
	if (hexlenl(p, &extra) != 16 * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.iv[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.seed[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);
	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void electrum_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char iv[16];
		unsigned char key[32];
		unsigned char outbuf[48];
		SHA256_CTX ctx;
		AES_KEY aes_decrypt_key;
		int extra;
		int i;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA256_Final(key, &ctx);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, 32);
		SHA256_Final(key, &ctx);
		memcpy(iv, cur_salt->iv, 16);
		AES_set_decrypt_key(key, 128 * 2, &aes_decrypt_key);
		AES_cbc_encrypt(cur_salt->seed, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);

		if (cur_salt->type == 1) {
			// check if 16 bytes of the encrypted seed are all lower-case hex (btcrecover)
			outbuf[16] = 0;
			if (hexlenl((const char*)outbuf, &extra) != 8 * 2 || extra)
				cracked[index] = 0;
			else
				cracked[index] = 1;
		} else if (cur_salt->type == 2) {
			// check if starting 4 bytes are "xprv"
			if (strncmp((const char*)outbuf, "xprv", 4))
				cracked[index] = 0;
			else {
				// check if remaining 12 bytes are in base58 set [1-9A-HJ-NP-Za-km-z]
				for (i = 0; i < 12; i++) {
					unsigned char c = outbuf[4 + i];
					if ((c > 'z') || (c < '1') || ((c > '9') && (c < 'A')) || ((c > 'Z') && (c < 'a'))) {
						cracked[index] = 0;
						break;
					}
				}
				if (i == 12)
					cracked[index] = 1;
			}
		} else if (cur_salt->type == 3) {
			unsigned char padbyte = outbuf[15];
			// check for valid PKCS7 padding for a 52 or 51 byte "WIF" private key, 64 is the original data size
			if (padbyte == 12 || padbyte == 13) {
				if (check_pkcs_pad(outbuf, 16, 16) < 0)
					cracked[index] = 0;
				else
					cracked[index] = 1;
			}
			else {
				cracked[index] = 0;
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

struct fmt_main fmt_electrum = {
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
		{ NULL },
		{ FORMAT_TAG },
		electrum_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash /* Not usable with $SOURCE_HASH$ */
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		electrum_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash /* Not usable with $SOURCE_HASH$ */
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

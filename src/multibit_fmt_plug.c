/*
 * JtR format to crack password protected MultiBit Wallets.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * All credit goes to Christopher Gurnee for making this work possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_multibit;
#elif FMT_REGISTERS_H
john_register_one(&fmt_multibit);
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
#include "md5.h"
#include "escrypt/crypto_scrypt.h"
#include "jumbo.h"
#include "memdbg.h"
#include "unicode.h"

#define FORMAT_NAME             "MultiBit Wallet"
#define FORMAT_LABEL            "multibit"
#define FORMAT_TAG              "$multibit$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1001
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        125
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests multibit_tests[] = {
	// Wallets created by MultiBit Classic 0.5.18
	{"$multibit$1*0908a1bd44147709*c82b6d0409c1e46a4660ea6d4fa9ae12e4e234c98a71a51ced105c7e66a57ca3", "openwall"},
	{"$multibit$1*2043ebb14b6d9670*24284a38a62b6a63fb0912ebc05aa9d26d6fd828134d20b9778d8d841f65f584", "openwall123"},
	// MultiBit HD wallet 0.5.0
	{"$multibit$2*081e3a1252c26731120d0d63783ae46f*8354d5b454e78fb15f81c9e6289ba9b8*081e3a1252c26731120d0d63783ae46f", "openwall"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;

static struct custom_salt {
	uint32_t type;
	unsigned char salt[16];
	unsigned char block[32];
	unsigned char iv[16];
	unsigned char block2[16];

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
	if (value != 1 && value != 2)
		goto err;
	if (value == 1) {
		if ((p = strtokm(NULL, "*")) == NULL) // salt
			goto err;
		if (hexlenl(p, &extra) != 8 * 2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // encrypted blocks
			goto err;
		if (hexlenl(p, &extra) != 32 * 2 || extra)
			goto err;
	} else if (value == 2) {
		if ((p = strtokm(NULL, "*")) == NULL) // iv
			goto err;
		if (hexlenl(p, &extra) != 16 * 2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // encrypted block with iv
			goto err;
		if (hexlenl(p, &extra) != 16 * 2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // encrypted block with hardcoded iv
			goto err;
		if (hexlenl(p, &extra) != 16 * 2 || extra)
			goto err;
	}
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
	if (cs.type == 1) {
		for (i = 0; i < 8; i++)
			cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.block[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	} else if (cs.type == 2) {
		for (i = 0; i < 16; i++)
			cs.iv[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 16; i++)
			cs.block[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 16; i++)
			cs.block2[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	}

	MEM_FREE(keeptr);
	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void multibit_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int is_bitcoinj_protobuf_data(unsigned char *block)
{
	unsigned char c;
	int i;

	// Does it look like a bitcoinj protobuf (newest Bitcoin for Android backup)?
	if ((strncmp((const char*)block + 2, "org.", 4) == 0) && block[0] == '\x0a' && block[1] < 128) {
		// If it doesn't look like a lower alpha domain name of len >= 8 (e.g. 'bitcoin.'), fail (btcrecover)
		for (i = 6; i < 14; i++) {
			c = block[i];
			if ((c > 'z') || ((c < 'a') && ((c != '.'))))
				return 0;
		}
		return 1; // success
	}

	return 0;
}

static int is_base58(unsigned char *buffer, int length)
{
	unsigned char c;
	int i;

	for (i = 0; i < length; i++) {
		c = buffer[i];
		if ((c > 'z') || (c < '1') || ((c > '9') && (c < 'A')) || ((c > 'Z') && (c < 'a'))) {
			return 0;
		}
	}

	return 1; // success
}

static const unsigned char *salt_hardcoded = (unsigned char*)"\x35\x51\x03\x80\x75\xa3\xb0\xc5";
static const unsigned char *iv_hardcoded = (unsigned char*)"\xa3\x44\x39\x1f\x53\x83\x11\xb3\x29\x54\x86\x16\xc4\x89\x72\x3e";

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0]) * cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char iv[16];
		unsigned char key[32];
		unsigned char outbuf[32 + 1];
		AES_KEY aes_decrypt_key;

		if (cur_salt->type == 1) {
			unsigned char c;
			MD5_CTX ctx;

			// key
			MD5_Init(&ctx);
			MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
			MD5_Update(&ctx, cur_salt->salt, 8);
			MD5_Final(key, &ctx);
			// key + 16
			MD5_Init(&ctx);
			MD5_Update(&ctx, key, 16);
			MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
			MD5_Update(&ctx, cur_salt->salt, 8);
			MD5_Final(key + 16, &ctx);
			// iv
			MD5_Init(&ctx);
			MD5_Update(&ctx, key + 16, 16);
			MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
			MD5_Update(&ctx, cur_salt->salt, 8);
			MD5_Final(iv, &ctx);
			outbuf[16] = 0; // NULL terminate
			AES_set_decrypt_key(key, 256, &aes_decrypt_key);
			AES_cbc_encrypt(cur_salt->block, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);
			c = outbuf[0];
			if (c == 'L' || c == 'K' || c == '5' || c == 'Q' || c == '\x0a' || c == '#') {
				// Does it look like a base58 private key (MultiBit, MultiDoge, or oldest-format Android key backup)? (btcrecover)
				if (c == 'L' || c == 'K' || c == '5' || c == 'Q') {
					// check if bytes are in base58 set [1-9A-HJ-NP-Za-km-z]
					if (is_base58(outbuf + 1, 15)) {
						// decrypt second block
						AES_cbc_encrypt(cur_salt->block + 16, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);
						if (is_base58(outbuf, 16))
							cracked[index] = 1;
						else
							cracked[index] = 0;

					} else {
						cracked[index] = 0;
					}
				} else {
					// Does it look like a KnC for Android key backup?
					if (strncmp((const char*)outbuf, "# KEEP YOUR PRIV", 8) == 0) // 8 should be enough
						cracked[index] = 1;
					// Does it look like a bitcoinj protobuf (newest Bitcoin for Android backup)? (btcrecover)
					else if (is_bitcoinj_protobuf_data(outbuf)) {
						cracked[index] = 1;
					}
				}
			}
		} else if (cur_salt->type == 2) {
			unsigned char key[32];
			unsigned char outbuf2[16 + 1];
			unsigned char iv[16];
			UTF16 password[PLAINTEXT_LENGTH * 2 + 1];

			outbuf2[16] = 0;
			cracked[index] = 0;
			enc_to_utf16_be(password, PLAINTEXT_LENGTH, (const unsigned char*)saved_key[index], strlen(saved_key[index]) + 1);
			crypto_scrypt((const unsigned char*)password, (strlen16(password) + 1) * 2, salt_hardcoded, 8, 16384, 8, 1, key, 32);

			// 1
			AES_set_decrypt_key(key, 128 * 2, &aes_decrypt_key);
			memcpy(iv, cur_salt->iv, 16);
			AES_cbc_encrypt(cur_salt->block, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);
			if (is_bitcoinj_protobuf_data(outbuf))
				cracked[index] = 1;
			// 2
			AES_set_decrypt_key(key, 128 * 2, &aes_decrypt_key);
			memcpy(iv, iv_hardcoded, 16);
			AES_cbc_encrypt(cur_salt->block2, outbuf2, 16, &aes_decrypt_key, iv, AES_DECRYPT);
			if (is_bitcoinj_protobuf_data(outbuf2))
				cracked[index] = 1;
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

struct fmt_main fmt_multibit = {
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
		{ NULL },
		{ FORMAT_TAG },
		multibit_tests
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
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		multibit_set_key,
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

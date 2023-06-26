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
#include <errno.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "md5.h"
#include "yescrypt/yescrypt.h"
#include "jumbo.h"
#include "unicode.h"

#define FORMAT_NAME             "MultiBit or Coinomi Wallet"
#define FORMAT_LABEL            "multibit"
#define FORMAT_TAG              "$multibit$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5/scrypt AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        125
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define OMP_SCALE               4 // MKPC and scale tuned for i7

static int max_threads;
static yescrypt_local_t *local;

static struct fmt_tests multibit_tests[] = {
	// Wallets created by MultiBit Classic 0.5.18
	{"$multibit$1*0908a1bd44147709*c82b6d0409c1e46a4660ea6d4fa9ae12e4e234c98a71a51ced105c7e66a57ca3", "openwall"},
	{"$multibit$1*2043ebb14b6d9670*24284a38a62b6a63fb0912ebc05aa9d26d6fd828134d20b9778d8d841f65f584", "openwall123"},
	// MultiBit Classic 0.5.19 .key files
	{"$multibit$1*39eac524fccaf7f2*c325ba3be05990e787904bc9d3603f035c3ed1bd673f87513765eefb5befda7e", "openwall123"},
	{"$multibit$1*21ecedddebcb4ca8*8777067e8109e71ccdcda54817eed8615d8dea85f363829c0c78d61da9e1268e", "\xe4""b"}, // original password is "äb"
	// MultiBit Classic 0.5.19 .wallet files
	{"$multibit$3*16384*8*1*1bf663752dade439*d2a4810673c311f6cdd4cebceadbd564c05d408ba9c74912a187953eabc20bee", "openwall123"},
#if 0
	/* Disabled because it can only work with codepages including this letter */
	{"$multibit$3*16384*8*1*1bf663752dade439*956a6f229c25154832bab8f4ddfe83e985631678fb8df33aad1b5128a55ea0e2", "\xe4""b"}, // original password is "äb"
#endif
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
	uint32_t n;
	uint32_t r;
	uint32_t p;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifdef _OPENMP
	max_threads = omp_get_max_threads();
#else
	max_threads = 1;
#endif

	local = mem_alloc(sizeof(*local) * max_threads);
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_init_local(&local[i]);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_free_local(&local[i]);
	MEM_FREE(local);

	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1 && value != 2 && value != 3)
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
	} else if (value == 3) {
		if ((p = strtokm(NULL, "*")) == NULL) // n
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // r
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // p
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // salt
			goto err;
		if (hexlenl(p, &extra) != 8 * 2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // encrypted blocks
			goto err;
		if (hexlenl(p, &extra) != 32 * 2 || extra)
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
	char *ctcopy = xstrdup(ciphertext);
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
	} else if (cs.type == 3) {
		cs.n = atoi(p);
		p = strtokm(NULL, "*");
		cs.r = atoi(p);
		p = strtokm(NULL, "*");
		cs.p = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < 8; i++)
			cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.block[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
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
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
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
	if (block[0] == '\x0a' && block[1] < 128 &&
	    !memcmp((const char*)block + 2, "org.", 4)) {
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
	int index;
	int failed = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char iv[16];
		unsigned char key[32];
		unsigned char outbuf[16];
		AES_KEY aes_decrypt_key;
		int len = strlen(saved_key[index]);

#ifdef _OPENMP
		if (cracked[index]) /* avoid false sharing of nearby elements */
#endif
			cracked[index] = 0;

		if (cur_salt->type == 1) {
			unsigned char c;
			MD5_CTX ctx;

			// key
			MD5_Init(&ctx);
			MD5_Update(&ctx, saved_key[index], len);
			MD5_Update(&ctx, cur_salt->salt, 8);
			MD5_Final(key, &ctx);
			// key + 16
			MD5_Init(&ctx);
			MD5_Update(&ctx, key, 16);
			MD5_Update(&ctx, saved_key[index], len);
			MD5_Update(&ctx, cur_salt->salt, 8);
			MD5_Final(key + 16, &ctx);
			// iv
			MD5_Init(&ctx);
			MD5_Update(&ctx, key + 16, 16);
			MD5_Update(&ctx, saved_key[index], len);
			MD5_Update(&ctx, cur_salt->salt, 8);
			MD5_Final(iv, &ctx);

			AES_set_decrypt_key(key, 256, &aes_decrypt_key);
			AES_cbc_encrypt(cur_salt->block, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);

			c = outbuf[0];
			if (c == 'L' || c == 'K' || c == '5' || c == 'Q') {
				// Does it look like a base58 private key (MultiBit, MultiDoge, or oldest-format Android key backup)? (btcrecover)
				// check if bytes are in base58 set [1-9A-HJ-NP-Za-km-z]
				if (is_base58(outbuf + 1, 15)) {
					// decrypt second block
					AES_cbc_encrypt(cur_salt->block + 16, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);
					if (is_base58(outbuf, 16))
						cracked[index] = 1;
				}
			} else if (c == '#') {
				// Does it look like a KnC for Android key backup?
				if (memcmp((const char*)outbuf, "# KEEP YOUR PRIV", 8) == 0) // 8 should be enough
					cracked[index] = 1;
			} else if (c == '\x0a') {
				// Does it look like a bitcoinj protobuf (newest Bitcoin for Android backup)? (btcrecover)?
				if (is_bitcoinj_protobuf_data(outbuf))
					cracked[index] = 1;
			}

		} else if (cur_salt->type == 2) {
			UTF16 password[PLAINTEXT_LENGTH * 2 + 1];

			len = enc_to_utf16_be(password, PLAINTEXT_LENGTH, (const unsigned char*)saved_key[index], len + 1);
			if (len < 0)
				len = strlen16(password);

#ifdef _OPENMP
			int t = omp_get_thread_num();
			if (t >= max_threads) {
				failed = -1;
				continue;
			}
#else
			const int t = 0;
#endif
			static const yescrypt_params_t params = { .N = 16384, .r = 8, .p = 1 };
			if (yescrypt_kdf(NULL, &local[t],
			    (const uint8_t *)password, (len + 1) * 2,
			    (const uint8_t *)salt_hardcoded, 8,
			    &params,
			    key, 32)) {
				failed = errno ? errno : EINVAL;
#ifndef _OPENMP
				break;
#endif
			}

			// 1
			AES_set_decrypt_key(key, 128 * 2, &aes_decrypt_key);
			memcpy(iv, cur_salt->iv, 16);
			AES_cbc_encrypt(cur_salt->block, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);

			if (is_bitcoinj_protobuf_data(outbuf))
				cracked[index] = 1;
			else {
				// 2
				AES_set_decrypt_key(key, 128 * 2, &aes_decrypt_key);
				memcpy(iv, iv_hardcoded, 16);
				AES_cbc_encrypt(cur_salt->block2, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);
				if (is_bitcoinj_protobuf_data(outbuf))
					cracked[index] = 1;
			}
		} else if (cur_salt->type == 3) {
			UTF16 password[PLAINTEXT_LENGTH * 2 + 1];

			len = enc_to_utf16_be(password, PLAINTEXT_LENGTH, (const unsigned char*)saved_key[index], len + 1);
			if (len < 0)
				len = strlen16(password);

#ifdef _OPENMP
			int t = omp_get_thread_num();
			if (t >= max_threads) {
				failed = -1;
				continue;
			}
#else
			const int t = 0;
#endif
			yescrypt_params_t params = { .N = cur_salt->n, .r = cur_salt->r, .p = cur_salt->p };
			if (yescrypt_kdf(NULL, &local[t],
			    (const uint8_t *)password, (len + 1) * 2,
			    (const uint8_t *)cur_salt->salt, 8,
			    &params,
			    key, 32)) {
				failed = errno ? errno : EINVAL;
#ifndef _OPENMP
				break;
#endif
			}

			memcpy(iv, cur_salt->block, 16);
			AES_set_decrypt_key(key, 256, &aes_decrypt_key);
			AES_cbc_encrypt(cur_salt->block + 16, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);

			if (!memcmp(outbuf, "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", 16))
				cracked[index] = 1;
		}
	}

	if (failed) {
#ifdef _OPENMP
		if (failed < 0) {
			fprintf(stderr, "OpenMP thread number out of range\n");
			error();
		}
#endif
		fprintf(stderr, "scrypt failed: %s\n", strerror(failed));
		error();
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

unsigned int get_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	if (cs->type == 1)
		return 3;
	else if (cs->type == 2)
		return 16384;
	else
		return (unsigned int)cs->n;
}

unsigned int get_kdf_type(void *salt)
{
	struct custom_salt *cs = salt;

	return cs->type;
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_ENC,
		{
			"iteration count",
			"kdf [1:MD5 2:scrypt hd 3:scrypt classic]",
		},
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
		{
			get_iteration_count,
			get_kdf_type,
		},
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

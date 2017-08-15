/*
 * LastPass CLI cracker patch for JtR.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_lastpass_cli;
#elif FMT_REGISTERS_H
john_register_one(&fmt_lastpass_cli);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE              1
#endif
#endif

#include "arch.h"
#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "sha2.h"
#include "pbkdf2_hmac_sha256.h"
#include "memdbg.h"

#define FORMAT_LABEL            "lpcli"
#define FORMAT_NAME             "LastPass CLI"
#define FORMAT_TAG              "$lpcli$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA256 " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static struct fmt_tests lastpass_cli_tests[] = {
	/* LastPass CLI v1.2.1 */
	{"$lpcli$0$lulu@mailinator.com$1234$3fec6cd2d8c049cbafe9fa6a9343f42f$f21d8e60ad22db53033e431700fb5e0c", "Badpassword098765"},
	{"$lpcli$0$lulu@mailinator.com$1234$fbd97e7e14713363c5567bdc106bb1f4$75ebb9460f9852ccb2382029fe333867", "Password12345"},
	// Special case where iterations == 1
	{"$lpcli$0$lulu@mailinator.com$1$9611651d6cbe6ab1dfb035d3874bd803$68bbe1480410c03cc053662658884f2b", "Password12345"},
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[32 / sizeof(uint32_t)];

static struct custom_salt {
	int iterations;
	int salt_length;
	int type;
	unsigned char iv[32];
	unsigned char salt[32];
} *cur_salt;

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int extra;
	int type = 0;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* type */
		goto err;
	if (!isdec(p))
		goto err;
	type = atoi(p);
	if (type != 0)
		goto err;
	if (strlen(p) > 32)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* email */
		goto err;
	if (strlen(p) > 32)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iv */
		goto err;
	if (hexlenl(p, &extra) != 32 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* hash */
		goto err;
	if (hexlenl(p, &extra) != 32 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;
	int i;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;

	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	strncpy((char*)cs.salt, p, 32);
	cs.salt_length = strlen((char*)p);
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	if (cs.iterations < 1)
		cs.iterations = 1;
	p = strtokm(NULL, "$");
	for (i = 0; i < 16; i++)
		cs.iv[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#define AGENT_VERIFICATION_STRING "`lpass` was written by LastPass.\n"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
		uint32_t key[MAX_KEYS_PER_CRYPT][8];
		int i;

		if (cur_salt->iterations != 1) {
#ifdef SIMD_COEF_32
			int lens[MAX_KEYS_PER_CRYPT];
			unsigned char *pin[MAX_KEYS_PER_CRYPT];
			union {
				uint32_t *pout[MAX_KEYS_PER_CRYPT];
				unsigned char *poutc;
			} x;
			for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
				lens[i] = strlen(saved_key[i+index]);
				pin[i] = (unsigned char*)saved_key[i+index];
				x.pout[i] = key[i];
			}
			pbkdf2_sha256_sse((const unsigned char **)pin, lens, cur_salt->salt, cur_salt->salt_length, cur_salt->iterations, &(x.poutc), 32, 0);

#else
			for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
				pbkdf2_sha256((unsigned char*)saved_key[i+index], strlen(saved_key[i+index]), cur_salt->salt, cur_salt->salt_length, cur_salt->iterations, (unsigned char*)key[i], 32, 0);
			}
#endif
		} else {
			for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
				SHA256_CTX ctx;

				SHA256_Init(&ctx);
				SHA256_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
				SHA256_Update(&ctx, saved_key[i+index], strlen(saved_key[i+index]));
				SHA256_Final((unsigned char*)key[i], &ctx);
			}
		}
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			unsigned char iv[16];
			AES_KEY akey;

			memcpy(iv, cur_salt->iv, 16);
			AES_set_encrypt_key((unsigned char*)key[i], 256, &akey);
			AES_cbc_encrypt((const unsigned char*)AGENT_VERIFICATION_STRING, (unsigned char*)crypt_out[i+index], BINARY_SIZE, &akey, iv, AES_ENCRYPT);
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void lastpass_cli_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int lastpass_iteration_count(void *salt)
{
        return ((struct custom_salt*)salt)->iterations;
}

struct fmt_main fmt_lastpass_cli = {
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
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		lastpass_cli_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			lastpass_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		lastpass_cli_set_key,
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

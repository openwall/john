/* JtR format to crack iWork '13 + '14 files.
 *
 * This software is Copyright (c) 2015, Dhiru Kholia <kholia at kth.se> and
 * Maxime Hulliger <hullger at kth.se>, and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This code may be freely used and modified for any purpose.
 *
 * Big thanks to Sean Patrick O'Brien for making this format possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_iwork;
#elif FMT_REGISTERS_H
john_register_one(&fmt_iwork);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#include <openssl/des.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               64
#endif
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "pbkdf2_hmac_sha1.h"
#include "jumbo.h"
#include "sha2.h"
#include "aes.h"
#include "memdbg.h"

#define FORMAT_LABEL            "iwork"
#define FORMAT_NAME             "Apple iWork '13 / '14"
#define FORMAT_TAG              "$iwork$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*fctx)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#define SALTLEN                 16
#define IVLEN                   16
#define BLOBLEN                 64

static struct fmt_tests iwork_tests[] = {
	{"$iwork$1$2$1$100000$d77ce46a68697e08b76ac91de9117541$e7b72b2848dc27efed883963b00b1ac7$e794144cd2f04bd50e23957b30affb2898554a99a3accb7506c17132654e09c04bbeff45dc4f8a8a1db5fd1592f699eeff2f9a8c31b503e9631a25a344b517f7" ,"12345678"},
	{FORMAT_TAG "1$2$1$100000$c773f06bcd580e4afa35618a7d0bee39$8b241504af92416f226d0eea4bf26443$18358e736a0401061f2dca103fceb29e88606d3ec80d09841360cbb8b9dc1d2908c270d3ff4c05cf7a46591e02ff3c9d75f4582f631721a3257dc087f98f523e", "password"},
	// iWork '09 Keynote file
	{"$iwork$2$1$1$4000$736f6d6553616c74$a9d975f8b3e1bf0c388944b457127df4$09eb5d093584376001d4c94e9d0a41eb8a2993132849c5aed8e56e7bd0e8ed50ba38aced793e3480675990c828c01d25fe245cc6aa603c6cb1a0425988f1d3dc", "openwall"},
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;

static struct format_context {
	int salt_length;
	unsigned char salt[SALTLEN];
	int iv_length;
	unsigned char iv[IVLEN];
	int iterations;
	int blob_length;
	unsigned char blob[BLOBLEN];
} *fctx;

static void init(struct fmt_main *self)
{

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(sizeof(*saved_key),  self->params.max_keys_per_crypt);
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
	int value;
	int file_version;
	int salt_length; // this is "someSalt" for iWork '09 files

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // internal (to JtR) format version
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1 && value !=2)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // file version
		goto err;
	if (!isdec(p))
		goto err;
	file_version = atoi(p);
	if (file_version != 1 && file_version != 2) // iWork '09, iWork 2013
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // format
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (file_version == 1)
		salt_length = 8;
	else
		salt_length = SALTLEN;
	if(hexlenl(p) != salt_length * 2)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iv
		goto err;
	if(hexlenl(p) != IVLEN * 2)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // blob
		goto err;
	if(hexlenl(p) != BLOBLEN * 2)
		goto err;
	if ((p = strtokm(NULL, "$")) != NULL)
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
	int i;
	char *p;
	int file_version;

	fctx = mem_calloc_tiny(sizeof(struct format_context), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // internal version
	p = strtokm(NULL, "$"); // version
	file_version = atoi(p);
	if (file_version == 1)
		fctx->salt_length = 8;
	else
		fctx->salt_length = SALTLEN;
	p = strtokm(NULL, "$"); // fmt
	p = strtokm(NULL, "$"); // iterations
	fctx->iterations = atoi(p);
	p = strtokm(NULL, "$"); // salt
	for (i = 0; i < SALTLEN; i++)
		fctx->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // iv
	for (i = 0; i < IVLEN; i++)
		fctx->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // blob
	for (i = 0; i < BLOBLEN; i++)
		fctx->blob[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)fctx;
}

static void set_salt(void *salt)
{
	fctx = (struct format_context *)salt;
}

static void iwork_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int iwork_decrypt(unsigned char *key, unsigned char *iv, unsigned char *data)
{
	unsigned char out[BLOBLEN] = {0};
	unsigned char ivec[IVLEN];
	uint8_t hash[32];
	SHA256_CTX ctx;

	AES_KEY aes_decrypt_key;
	AES_set_decrypt_key(key, 128, &aes_decrypt_key);
	memcpy(ivec, iv, 16);
	AES_cbc_encrypt(fctx->blob, out, BLOBLEN, &aes_decrypt_key, ivec, AES_DECRYPT);

	// The last 32 bytes should be equal to the SHA256 of the first 32 bytes (IWPasswordVerifier.m)
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, out, 32);
	SHA256_Final(hash, &ctx);

	return memcmp(hash, &out[32], 32) == 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		unsigned char master[MAX_KEYS_PER_CRYPT][32];
		int i;
#ifdef SIMD_COEF_32
		int lens[MAX_KEYS_PER_CRYPT];
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char**)pin, lens, fctx->salt, fctx->salt_length, fctx->iterations, pout, 16, 0);
#else
		pbkdf2_sha1((unsigned char *)saved_key[index], strlen(saved_key[index]), fctx->salt, fctx->salt_length, fctx->iterations, master[0], 16, 0);
#if !ARCH_LITTLE_ENDIAN
		{
			int i;
			for (i = 0; i < 16/sizeof(ARCH_WORD_32); ++i) {
				((ARCH_WORD_32*)master[0])[i] = JOHNSWAP(((ARCH_WORD_32*)master[0])[i]);
			}
		}
#endif
#endif
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			cracked[index+i] = iwork_decrypt(master[i], fctx->iv, fctx->blob);
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

static unsigned int iteration_count(void *salt)
{
	struct format_context *my_fctx;

	my_fctx = salt;
	return (unsigned int) my_fctx->iterations;
}

struct fmt_main fmt_iwork = {
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
		iwork_tests
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
			iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		iwork_set_key,
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

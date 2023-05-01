/*
 * GNOME Keyring cracker patch for JtR. Hacked together during Monsoon of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_keyring;
#elif FMT_REGISTERS_H
john_register_one(&fmt_keyring);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "md5.h"
#include "sha2.h"
#include "aes.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL            "keyring"
#define FORMAT_NAME             "GNOME Keyring"
#define FORMAT_TAG              "$keyring$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "SHA256 AES " SHA256_ALGORITHM_NAME
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_32
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#else
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#endif
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif

#define SALTLEN                 8

typedef unsigned char guchar;
typedef unsigned int guint;
typedef int gint;

static struct fmt_tests keyring_tests[] = {
	{"$keyring$db1b562e453a0764*3221*16*0*02b5c084e4802369c42507300f2e5e56", "openwall"},
	{"$keyring$4f3f1557a7da17f5*2439*144*0*12215fabcff6782aa23605ab2cd843f7be9477b172b615eaa9130836f189d32ffda2e666747378f09c6e76ad817154daae83a36c0a0a35f991d40bcfcba3b7807ef57a0ce4c7f835bf34c6e358f0d66aa048d73dacaaaf6d7fa4b3510add6b88cc237000ff13cb4dbd132db33be3ea113bedeba80606f86662cc226af0dad789c703a7df5ad8700542e0f7a5e1f10cf0", "password"},
	{NULL}
};

static struct custom_salt {
	unsigned int iterations;
	unsigned char salt[SALTLEN];
	unsigned int crypto_size;
	unsigned int inlined;
	unsigned char ct[LINE_BUFFER_SIZE / 2]; /* after hex conversion */
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static int any_cracked;
static size_t cracked_size;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int looks_like_nice_int(char *p)
{
	// reasonability check + avoids atoi's UB
	if (strlen(p) > 9)
		return 0;
	for (; *p; p++)
		if (*p < '0' || *p > '9')
			return 0;
	return 1;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int ctlen, extra;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	if (keeptr == NULL)
		goto err;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;
	while (*p)
		if (atoi16[ARCH_INDEX(*p++)] == 0x7f)
			goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!looks_like_nice_int(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* crypto size */
		goto err;
	if (!looks_like_nice_int(p))
		goto err;
	ctlen = atoi(p);
	if (ctlen > sizeof(cur_salt->ct))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* inlined - unused? TODO */
		goto err;
	if (!looks_like_nice_int(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if (ctlen > LINE_BUFFER_SIZE)
		goto err;
	if (hexlenl(p, &extra) != ctlen * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

      err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$keyring$" */
	cur_salt = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	p = strtokm(ctcopy, "*");
	for (i = 0; i < SALTLEN; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.crypto_size = atoi(p);
	p = strtokm(NULL, "*");
	cs.inlined = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.crypto_size; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#ifdef SIMD_COEF_32
static void symkey_generate_simple(int index, unsigned char *salt, int n_salt, int iterations,
	                               unsigned char key[MIN_KEYS_PER_CRYPT][32],
								   unsigned char iv[MIN_KEYS_PER_CRYPT][32])
{
	SHA256_CTX ctx;
	unsigned char digest[32], _IBuf[64*MIN_KEYS_PER_CRYPT+MEM_ALIGN_SIMD], *keys;
	uint32_t *keys32;
	unsigned int i, j;

	keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_SIMD);
	memset(keys, 0, 64*MIN_KEYS_PER_CRYPT);
	keys32 = (uint32_t*)keys;

	// use oSSL to do first crypt, and marshal into SIMD buffers.
	for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[index+i], strlen(saved_key[index+i]));
		SHA256_Update(&ctx, salt, n_salt);
		SHA256_Final(digest, &ctx);
		for (j = 0; j < 32; ++j)
			keys[GETPOS(j, i)] = digest[j];
		keys[GETPOS(j, i)] = 0x80;
		// 32 bytes is 256 bits (0x100, simply put a 1 into offset 62)
		keys[GETPOS(62, i)] = 1;
	}

	// the 'simple' inner loop in SIMD.
	for (i = 1; i < iterations; ++i)
		SIMDSHA256body(keys, keys32, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

	// marshal data back into flat buffers.
	for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
		uint32_t *Optr32 = (uint32_t*)(key[i]);
		uint32_t *Iptr32 = &keys32[(i/SIMD_COEF_32)*SIMD_COEF_32*16 + (i%SIMD_COEF_32)];
		for (j = 0; j < 4; ++j)
#if ARCH_LITTLE_ENDIAN==1
			Optr32[j] = JOHNSWAP(Iptr32[j*SIMD_COEF_32]);
#else
			Optr32[j] = Iptr32[j*SIMD_COEF_32];
#endif
		Optr32 = (uint32_t*)(iv[i]);
		for (j = 0; j < 4; ++j)
#if ARCH_LITTLE_ENDIAN==1
			Optr32[j] = JOHNSWAP(Iptr32[(j+4)*SIMD_COEF_32]);
#else
			Optr32[j] = Iptr32[(j+4)*SIMD_COEF_32];
#endif
	}
}
#else
static void symkey_generate_simple(int index, unsigned char *salt, int n_salt, int iterations,
	                               unsigned char key[MIN_KEYS_PER_CRYPT][32],
								   unsigned char iv[MIN_KEYS_PER_CRYPT][32])
{
	SHA256_CTX ctx;
	unsigned char digest[32];
	int i;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, saved_key[index], strlen(saved_key[index]));
	SHA256_Update(&ctx, salt, n_salt);
	SHA256_Final(digest, &ctx);

	for (i = 1; i < iterations; ++i) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, digest, 32);
		SHA256_Final(digest, &ctx);
	}
	memcpy(key[0], digest, 16);
	memcpy(iv[0], &digest[16], 16);
}
#endif
static void decrypt_buffer(unsigned char buffers[MIN_KEYS_PER_CRYPT][sizeof(cur_salt->ct)], int index)
{
	unsigned char key[MIN_KEYS_PER_CRYPT][32];
	unsigned char iv[MIN_KEYS_PER_CRYPT][32];
	AES_KEY akey;
	unsigned int i, len = cur_salt->crypto_size;
	unsigned char *salt = cur_salt->salt;
	int iterations = cur_salt->iterations;

	symkey_generate_simple(index, salt, 8, iterations, key, iv);

	for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
		AES_set_decrypt_key(key[i], 128, &akey);
		AES_cbc_encrypt(cur_salt->ct, buffers[i], len, &akey, iv[i], AES_DECRYPT);
	}
}

static int verify_decrypted_buffer(unsigned char *buffer, int len)
{
	guchar digest[16];
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, buffer + 16, len - 16);
	MD5_Final(digest, &ctx);
	return memcmp(buffer, digest, 16) == 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index+=MIN_KEYS_PER_CRYPT)
	{
		int i;
		unsigned char (*buffers)[sizeof(cur_salt->ct)];

		// This is too big to be on stack. See #1292.
		buffers = mem_alloc(MIN_KEYS_PER_CRYPT * sizeof(*buffers));

		decrypt_buffer(buffers, index);

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			if (verify_decrypted_buffer(buffers[i], cur_salt->crypto_size)) {
				cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
		MEM_FREE(buffers);
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

static void keyring_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return my_salt->iterations;
}

struct fmt_main fmt_keyring = {
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
		keyring_tests
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
		keyring_set_key,
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

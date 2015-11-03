/*
 * This software is Copyright (c) 2015 JimF, <jfoug at openwall.com>, and
 * it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Azure ActiveDirectory, V1 cracker patch for JtR.
 *
 *  Algorithm:  https://www.dsinternals.com/en/how-azure-active-directory-connect-syncs-passwords/
 *
 * PBKDF2(UTF-16(uc(hex(MD4(UTF-16(password))))), rnd_salt(10), 100, HMAC-SHA256, 32)
 */


#if FMT_EXTERNS_H
extern struct fmt_main fmt_AzureAD;
#elif FMT_REGISTERS_H
john_register_one(&fmt_AzureAD);
#else

#include <string.h>

#include "arch.h"

#include "md4.h"
#include "pbkdf2_hmac_sha256.h"
#include "common.h"
#include "formats.h"
#include "base64_convert.h"
#include "AzureAD_common.h"
#include "unicode.h"
#include "johnswap.h"

//#undef SIMD_COEF_32
//#undef SIMD_PARA_SHA256

#ifdef _OPENMP
#ifdef SIMD_COEF_32
#ifndef OMP_SCALE
#define OMP_SCALE               64  // FIXME
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               64  // FIXME
#endif
#endif
#include <omp.h>
#endif
#include "simd-intrinsics.h"
#include "memdbg.h"

#define FORMAT_LABEL             "AzureAD"
#define FORMAT_NAME              ""
#define ALGORITHM_NAME           "SHA256 " SHA256_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS                   (SIMD_COEF_32 * SIMD_PARA_SHA256)
#else
#define NBKEYS                   1
#endif

#define BENCHMARK_COMMENT        ""
#define BENCHMARK_LENGTH         0

#define BINARY_SIZE              DIGEST_SIZE
#define BINARY_ALIGN             4

// For now, I will do md4() oSSL type for all passwords. There is so much
// other overhead that adding the complexity to do SIMD md4 will gain us
// almost nothing
#define PLAINTEXT_LENGTH         125
#define MIN_KEYS_PER_CRYPT       NBKEYS
#define MAX_KEYS_PER_CRYPT       NBKEYS

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static char (*saved_nt)[64];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt,
	                             sizeof(*saved_key), MEM_ALIGN_WORD);
	saved_nt = mem_calloc_align(self->params.max_keys_per_crypt,
	                             sizeof(*saved_nt), MEM_ALIGN_WORD);
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt,
	                             sizeof(*crypt_out), MEM_ALIGN_WORD);
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_nt);
	MEM_FREE(saved_key);
}

static void *salt(char *ciphertext) {
	char Buf[120], *ctcopy=Buf;
	char *p;
	static struct AzureAD_custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	strncpy(Buf, ciphertext, 119);
	Buf[119] = 0;
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, ",");
	cs.salt_len = strlen(p)/2;
	base64_convert(p, e_b64_hex, cs.salt_len*2, cs.salt, e_b64_raw, cs.salt_len, 0);
	p = strtokm(NULL, ",");
	cs.iterations = atoi(p);
	p = strtokm(Buf, ",");
	strncpy(cs.version, p, 8);
	cs.version[7] = 0;

	return (void *)&cs;
}

static void set_salt(void *salt) {
	AzureAD_cur_salt = (struct AzureAD_custom_salt *)salt;
}

static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }

static void set_key(char *key, int index) {
	UTF16 Buf[PLAINTEXT_LENGTH+1];
	unsigned char hash[16], hex[33];
	int len;
	MD4_CTX ctx;

	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH+1);
	// * PBKDF2(UTF-16(uc(hex(MD4(UTF-16(password))))), rnd_salt(10), 100, HMAC-SHA256, 32)

	// Trivial for now.  Can optimized later.
	len = enc_to_utf16(Buf, PLAINTEXT_LENGTH, (UTF8*)saved_key[index], strlen(saved_key[index]));
	if (len < 0) len = 0;
	MD4_Init(&ctx);
	MD4_Update(&ctx, Buf, len*2);
	MD4_Final(hash, &ctx);
	base64_convert(hash, e_b64_raw, 16, hex, e_b64_hex, 32, flg_Base64_HEX_UPCASE);
	for (len = 0; len < 32; ++len)
		saved_nt[index][len<<1] = hex[len];
}

static char *get_key(int index) {
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt) {
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
#ifdef SIMD_COEF_32
		int lens[MAX_KEYS_PER_CRYPT], i;
		unsigned char *pin[MAX_KEYS_PER_CRYPT];
		union {
			ARCH_WORD_32 *pout[MAX_KEYS_PER_CRYPT];
			unsigned char *poutc;
		} x;
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = 64;
			pin[i] = (unsigned char*)saved_nt[i+index];
			x.pout[i] = crypt_out[i+index];
		}
		pbkdf2_sha256_sse((const unsigned char **)pin, lens, AzureAD_cur_salt->salt, AzureAD_cur_salt->salt_len, AzureAD_cur_salt->iterations, &(x.poutc), 32, 0);
#else
		pbkdf2_sha256((unsigned char *)saved_nt[index], 64,
			AzureAD_cur_salt->salt, AzureAD_cur_salt->salt_len,
			AzureAD_cur_salt->iterations, (unsigned char*)crypt_out[index], 32, 0);
#if !ARCH_LITTLE_ENDIAN
		{
			int i;
			for (i = 0; i < 32/sizeof(ARCH_WORD_32); ++i)
				((ARCH_WORD_32*)crypt_out[index])[i] = JOHNSWAP(((ARCH_WORD_32*)crypt_out[index])[i]);
		}
#endif
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (!memcmp(binary, crypt_out[index], 4))
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

struct fmt_main fmt_AzureAD = {
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
#ifdef _OPENMP
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_UNICODE | FMT_UTF8,
		{ NULL },
		AzureAD_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		AzureAD_common_valid,
		AzureAD_common_split,
		AzureAD_common_get_binary,
		salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

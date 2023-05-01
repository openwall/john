/*
 * ssha512 support for LDAP style password storage
 *
 * This software is Copyright (c) 2013 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_saltedsha2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_saltedsha2);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "options.h"
#include "johnswap.h"
#include "common.h"
#include "sha2.h"
#include "base64_convert.h"
#include "simd-intrinsics.h"
#include "rawSHA512_common.h"

#define FORMAT_LABEL                    "SSHA512"
#define FORMAT_NAME                     "LDAP"

#ifdef SIMD_COEF_64
#define ALGORITHM_NAME					"SHA512 " SHA512_ALGORITHM_NAME
#else
#if ARCH_BITS >= 64
#define ALGORITHM_NAME					"SHA512 64/" ARCH_BITS_STR
#else
#define ALGORITHM_NAME					"SHA512 32/" ARCH_BITS_STR
#endif
#endif

#define PLAINTEXT_LENGTH                (111-NSLDAP_SALT_LEN)
#define SALT_ALIGN                      4

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512 * 128)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      128
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               16 // Tuned w/ MKPC for core i7
#endif

struct s_salt
{
	unsigned int len;
	union {
		unsigned char c[NSLDAP_SALT_LEN];
		uint32_t w32;
	} data;
};

static struct s_salt *saved_salt;

#ifdef SIMD_COEF_64
#define FMT_IS_64BIT
#define FMT_IS_BE
#include "common-simd-getpos.h"
static uint64_t (*saved_key)[SHA_BUF_SIZ*SIMD_COEF_64];
static uint64_t (*crypt_out)[8*SIMD_COEF_64];
static uint64_t (**len_ptr64);
static int max_count;
#else
static uint32_t (*crypt_out)[DIGEST_SIZE / 4];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
#endif
static int *saved_len;

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_64
	unsigned int i, j;
#endif

	omp_autotune(self, OMP_SCALE);

	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
#ifndef SIMD_COEF_64
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
#else
	len_ptr64 = mem_calloc_align(self->params.max_keys_per_crypt,
	                             sizeof(*len_ptr64), MEM_ALIGN_SIMD);
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt /
	                             SIMD_COEF_64,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt /
	                             SIMD_COEF_64,
	                             sizeof(*crypt_out), MEM_ALIGN_SIMD);
	for (i = 0; i < self->params.max_keys_per_crypt; i += SIMD_COEF_64) {
		uint64_t *keybuffer = &((uint64_t *)saved_key)[(i&(SIMD_COEF_64-1)) + (i/SIMD_COEF_64)*SHA_BUF_SIZ*SIMD_COEF_64];
		for (j = 0; j < SIMD_COEF_64; ++j) {
			len_ptr64[i+j] = &keybuffer[15*SIMD_COEF_64];
			++keybuffer;
		}
	}
	max_count = self->params.max_keys_per_crypt;
#endif
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
#ifdef SIMD_COEF_64
	MEM_FREE(len_ptr64);
#endif
	MEM_FREE(saved_len);
}

#define SET_SAVED_LEN
#include "common-simd-setkey64.h"

static void * get_salt(char * ciphertext)
{
	static struct s_salt cursalt;
	char *p;
	char realcipher[CIPHERTEXT_LENGTH];
	int len;

	ciphertext += NSLDAP_TAG_LENGTH;
	memset(realcipher, 0, sizeof(realcipher));
	memset(&cursalt, 0, sizeof(struct s_salt));
	len = strlen(ciphertext);
	base64_convert(ciphertext, e_b64_mime, len, realcipher, e_b64_raw, sizeof(realcipher), flg_Base64_DONOT_NULL_TERMINATE, 0);

	// We now support any salt length up to NSLDAP_SALT_LEN
	cursalt.len = (len + 3) / 4 * 3 - DIGEST_SIZE;
	p = &ciphertext[len];
	while (*--p == '=')
		cursalt.len--;

	memcpy(cursalt.data.c, realcipher+DIGEST_SIZE, cursalt.len);
	return &cursalt;
}

static int cmp_all(void *binary, int count) {
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_64
        if (((uint64_t *) binary)[0] == crypt_out[index/SIMD_COEF_64][index&(SIMD_COEF_64-1)])
#else
		if ( ((uint32_t*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_64
    int i;
	for (i = 0; i < DIGEST_SIZE/sizeof(uint64_t); i++)
        if (((uint64_t *) binary)[i] != crypt_out[index/SIMD_COEF_64][(index&(SIMD_COEF_64-1))+i*SIMD_COEF_64])
            return 0;
	return 1;
#else
	return !memcmp(binary, crypt_out[index], DIGEST_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_salt(void *salt) {
	saved_salt = salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index+=MIN_KEYS_PER_CRYPT) {
#ifndef SIMD_COEF_64
		SHA512_CTX ctx;
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, saved_key[index], saved_len[index]);
		SHA512_Update(&ctx, saved_salt->data.c, saved_salt->len);
		SHA512_Final((unsigned char*)crypt_out[index], &ctx);
#else
		// We have to append salt (and re-clean buffer if it is dirty),
		// then append final length of password.salt
		int i, j;
		unsigned char *sk = (unsigned char*)saved_key;
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			int idx = i+index;
			int x = saved_len[idx];
			for (j = 0; j < saved_salt->len; ++j)
				sk[GETPOS(x+j,idx)] = saved_salt->data.c[j];
			x += j;
			sk[GETPOS(x,idx)] = 0x80;
			++x;
			while (sk[GETPOS(x,idx)]) {
				sk[GETPOS(x,idx)] = 0;
				++x;
			}
			*(len_ptr64[idx]) = (saved_len[idx]+saved_salt->len)<<3;
		}
		SIMDSHA512body(&saved_key[index/SIMD_COEF_64], crypt_out[index/SIMD_COEF_64], NULL, SSEi_MIXED_IN);
#endif
	}
	return count;
}

#ifdef SIMD_COEF_64
static int get_hash_0 (int index) { return crypt_out[(unsigned int)index/SIMD_COEF_64][index&(SIMD_COEF_64-1)] & PH_MASK_0; }
static int get_hash_1 (int index) { return crypt_out[(unsigned int)index/SIMD_COEF_64][index&(SIMD_COEF_64-1)] & PH_MASK_1; }
static int get_hash_2 (int index) { return crypt_out[(unsigned int)index/SIMD_COEF_64][index&(SIMD_COEF_64-1)] & PH_MASK_2; }
static int get_hash_3 (int index) { return crypt_out[(unsigned int)index/SIMD_COEF_64][index&(SIMD_COEF_64-1)] & PH_MASK_3; }
static int get_hash_4 (int index) { return crypt_out[(unsigned int)index/SIMD_COEF_64][index&(SIMD_COEF_64-1)] & PH_MASK_4; }
static int get_hash_5 (int index) { return crypt_out[(unsigned int)index/SIMD_COEF_64][index&(SIMD_COEF_64-1)] & PH_MASK_5; }
static int get_hash_6 (int index) { return crypt_out[(unsigned int)index/SIMD_COEF_64][index&(SIMD_COEF_64-1)] & PH_MASK_6; }
static int binary_hash_0 (void *p) { return *((uint64_t*)p) & PH_MASK_0; }
static int binary_hash_1 (void *p) { return *((uint64_t*)p) & PH_MASK_1; }
static int binary_hash_2 (void *p) { return *((uint64_t*)p) & PH_MASK_2; }
static int binary_hash_3 (void *p) { return *((uint64_t*)p) & PH_MASK_3; }
static int binary_hash_4 (void *p) { return *((uint64_t*)p) & PH_MASK_4; }
static int binary_hash_5 (void *p) { return *((uint64_t*)p) & PH_MASK_5; }
static int binary_hash_6 (void *p) { return *((uint64_t*)p) & PH_MASK_6; }
#else
static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }
#endif

static int salt_hash(void *salt)
{
	struct s_salt * mysalt = salt;
	return mysalt->data.w32 & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_saltedsha2 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		NSLDAP_BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		DIGEST_SIZE,
		BINARY_ALIGN,
		NSLDAP_SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ NSLDAP_FORMAT_TAG },
		sha512_common_tests_ssha512
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		sha512_common_valid_nsldap,
		fmt_default_split,
		sha512_common_binary_nsldap,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
#ifdef SIMD_COEF_64
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
#else
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
#endif
		},
		salt_hash,
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

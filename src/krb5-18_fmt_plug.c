/*
 * KRB5 - Enctype 18 (aes256-cts-hmac-sha1-96) cracker patch for JtR
 * Created on August of 2012 by Mougey Camille (CEA/DAM) & Lalet Pierre (CEA/DAM)
 *
 * This format is one of formats saved in KDC database and used during the authentication part
 *
 * This software is Copyright (c) 2012, Mougey Camille (CEA/DAM)
 * Lalet Pierre (CEA/DAM)
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format :
 * - user:$krb18$REALMname$hash
 * - user:REALMname$hash
 *
 * Format rewritten Dec, 2014, without use of -lkrb5, by JimF.  Now we use 'native' JtR
 * pbkdf2-hmac-sha1() and simple call to 2 AES limb encrypt for entire process. Very
 * simple, and 10x faster, and no obsure -lkrb5 dependency
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if FMT_EXTERNS_H
extern struct fmt_main fmt_krb5_18;
#elif FMT_REGISTERS_H
john_register_one(&fmt_krb5_18);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"
#include "sse-intrinsics.h"
#include "pbkdf2_hmac_sha1.h"
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#ifdef SIMD_COEF_32
#ifndef OMP_SCALE
#define OMP_SCALE               8
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               32
#endif
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"krb5-18"
#define FORMAT_NAME		"Kerberos 5 db etype 18"

#define FORMAT_TAG		"$krb18$"
#define TAG_LENGTH		7

#if SIMD_COEF_32
#define ALGORITHM_NAME    "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME " AES"
#else
#define ALGORITHM_NAME    "PBKDF2-SHA1 32/" ARCH_BITS_STR " AES"
#endif

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	64
#define CIPHERTEXT_LENGTH	64
#define BINARY_SIZE		32
#define BINARY_ALIGN		4
#define SALT_SIZE		CIPHERTEXT_LENGTH
#define SALT_ALIGN		1
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static struct fmt_tests kinit_tests[] = {
  {"OLYMPE.OLtest$214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26", "password"},
  {FORMAT_TAG "OLYMPE.OLtest$214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26",
   "password"},
  {NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static char saved_salt[SALT_SIZE+1];
static ARCH_WORD_32 (*crypt_out)[16];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	p = strstr(p, "$");
	if(p == NULL)
		return 0;

	q = ciphertext;

	if(p - q > SALT_SIZE) /* check salt length */
		return 0;
	q = ++p;

	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
	        if (*q >= 'A' && *q <= 'F') /* support lowercase only */
			return 0;
		q++;
	}

	return !*q && q - p == CIPHERTEXT_LENGTH;
}


static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + SALT_SIZE + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	strnzcpyn(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + SALT_SIZE + 1);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static char out[SALT_SIZE+1];
	char *p, *q;

	memset(&out, 0, sizeof(out));
	p = ciphertext + TAG_LENGTH;
	q = strstr(p, "$");
	strncpy(out, p, q-p);
	out[q-p] = 0;

	return out;
}

static void set_salt(void *salt)
{
	strcpy(saved_salt, salt);
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i = 0;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	p = strstr(p, "$") + 1;

	for (; i < BINARY_SIZE; i++) {
	        out[i] =
		        (atoi16[ARCH_INDEX(*p)] << 4) |
		        atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

static int crypt_all(int *pcount, struct db_salt *_salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		unsigned char key[32], i;
		AES_KEY aeskey;
#ifdef SSE_GROUP_SZ_SHA1
		ARCH_WORD_32 Key[SSE_GROUP_SZ_SHA1][32/4];
		int lens[SSE_GROUP_SZ_SHA1];
		unsigned char *pin[SSE_GROUP_SZ_SHA1];
		union {
			ARCH_WORD_32 *pout[SSE_GROUP_SZ_SHA1];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA1; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = Key[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens, (const unsigned char*)saved_salt, strlen(saved_salt), 4096, &(x.poutc), 32, 0);
#else
		pbkdf2_sha1((const unsigned char*)saved_key[index], strlen(saved_key[index]), (const unsigned char*)saved_salt, strlen(saved_salt), 4096, key, 32, 0);
#endif
		i=0;
#ifdef SSE_GROUP_SZ_SHA1
		for (; i < SSE_GROUP_SZ_SHA1; ++i) {
			memcpy(key, Key[i], 32);
#endif
#if (ARCH_LITTLE_ENDIAN==0)
		for (i = 0; i < 8; ++i)
			((ARCH_WORD_32*)key)[i] = JOHNSWAP(((ARCH_WORD_32*)key)[i]);
		i = 0;
#endif
		AES_set_encrypt_key(key, 256, &aeskey);
		AES_encrypt((unsigned char*)"kerberos{\x9b[+\x93\x13+\x93", (unsigned char*)(crypt_out[index+i]), &aeskey);
		AES_encrypt((unsigned char*)(crypt_out[index+i]), (unsigned char*)&crypt_out[index+i][4], &aeskey);
#ifdef SSE_GROUP_SZ_SHA1
		}
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;

#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (; index < count; index++)
#endif
	        if (crypt_out[index][0] == *(ARCH_WORD_32*)binary)
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

static void set_key(char *key, int index)
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

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

struct fmt_main fmt_krb5_18 = {
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		kinit_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
		cmp_exact,
	}
};

#endif /* plugin stanza */

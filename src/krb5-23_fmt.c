/*
 * KRB5 - Enctype 23 (arcfour-hmac) cracker patch for JtR
 * Created on August of 2012 by Mougey Camille (CEA/DAM)
 *
 * This format is one of formats saved in KDC database and used during the authentication part
 *
 * This software is Copyright (c) 2012, Mougey Camille (CEA/DAM)
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format :
 * - user:$krb23$hash
 * - user:hash
 */
#ifdef HAVE_KRB5
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include <krb5.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"krb5-23"
#define FORMAT_NAME		"KRB5 arcfour-hmac"

#define FORMAT_TAG		"$krb23$"
#define TAG_LENGTH		7

#if !defined(USE_GCC_ASM_IA32) && defined(USE_GCC_ASM_X64)
#define ALGORITHM_NAME		"64/64"
#else
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define CIPHERTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		0
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#if defined(__APPLE__) && defined(__MACH__)
#ifdef __MAC_OS_X_VERSION_MIN_REQUIRED
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
#define USE_HEIMDAL
#endif
#endif
#endif


extern krb5_error_code KRB5_CALLCONV
krb5_c_string_to_key_with_params(krb5_context context, krb5_enctype enctype,
                                 const krb5_data *string,
                                 const krb5_data *salt,
                                 const krb5_data *params, krb5_keyblock *key);

static struct fmt_tests kinit_tests[] = {
  {"1667b5ee168fc31fba85ffb8f925fb70", "aqzsedrf"},
  {"8846f7eaee8fb117ad06bdd830b7586c", "password"},
  {FORMAT_TAG "1667b5ee168fc31fba85ffb8f925fb70", "aqzsedrf"},
  {NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[8];

static krb5_data salt;
static krb5_enctype enctype;

static void init(struct fmt_main *pFmt)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	salt.data = "";
	salt.length = 0;
	enctype = 23; /* arcfour-hmac */

	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *p, *q;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
	        if (*q >= 'A' && *q <= 'F') /* support lowercase only */
			return 0;
		q++;
	}

	return !*q && q - p == CIPHERTEXT_LENGTH;
}


#if FMT_MAIN_VERSION > 9
static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
#else
static char *split(char *ciphertext, int index)
#endif
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i = 0;
	p = ciphertext;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	for (; i < BINARY_SIZE; i++) {
	        out[i] =
		        (atoi16[ARCH_INDEX(*p)] << 4) |
		        atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void crypt_all(int count)
{
  int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
  for (index = 0; index < count; index++)
#endif
    {
      int i = 0;
      krb5_data string;
      krb5_keyblock key;
      memset(&key, 0, sizeof(krb5_keyblock));

      string.data = saved_key[index];
      string.length = strlen(saved_key[index]);
#ifdef USE_HEIMDAL
      krb5_c_string_to_key (NULL, ENCTYPE_ARCFOUR_HMAC, &string, &salt, &key);
#else
      krb5_c_string_to_key_with_params(NULL, enctype, &string, &salt, NULL, &key);

#endif
      for(i=0; i < key.length / 4; i++) {
	      crypt_out[index][i] = (key.contents[4 * i]) |
		      (key.contents[4 * i + 1] << 8) |
		      (key.contents[4 * i + 2] << 16) |
		      (key.contents[4 * i + 3] << 24);
      }
    }
}

static int cmp_all(void *binary, int count)
{
	int index = 0;

	for (; index < count; index++)
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
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_KRB5_kinit = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		sizeof(ARCH_WORD_32),
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		sizeof(ARCH_WORD_32),
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		kinit_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
		        fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
		        fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact,
	}
};
#else
#ifdef __GNUC__
#warning Note: krb5-23 format disabled, un-comment HAVE_KRB5 in Makefile if you have MIT Kerberos 5 libs and headers installed.
#endif
#endif

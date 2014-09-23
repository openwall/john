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
 */

#if AC_BUILT
/* need to know if HAVE_KRB5 is set, for autoconfig build */
#include "autoconfig.h"
#endif

#if HAVE_KRB5

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
#include "params.h"
#include "options.h"
#include <krb5.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               4
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"krb5-18"
#define FORMAT_NAME		"Kerberos 5 db etype 18 aes256-cts-hmac-sha1-96"

#define FORMAT_TAG		"$krb18$"
#define TAG_LENGTH		7

#if !defined(USE_GCC_ASM_IA32) && defined(USE_GCC_ASM_X64)
#define ALGORITHM_NAME		"64/64"
#else
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	64
#define CIPHERTEXT_LENGTH	64
#define BINARY_SIZE		32
#define BINARY_ALIGN		4
#define SALT_SIZE		CIPHERTEXT_LENGTH
#define SALT_ALIGN		1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#if !AC_BUILT && defined(__APPLE__) && defined(__MACH__)
#ifdef __MAC_OS_X_VERSION_MIN_REQUIRED
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
#define HAVE_MKSHIM
#endif
#endif
#endif

/* Does some system not declare this in krb5.h? */
extern krb5_error_code KRB5_CALLCONV
krb5_c_string_to_key_with_params(krb5_context context, krb5_enctype enctype,
                                 const krb5_data *string,
                                 const krb5_data *salt,
                                 const krb5_data *params, krb5_keyblock *key);

static struct fmt_tests kinit_tests[] = {
  {"OLYMPE.OLtest$214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26", "password"},
  {FORMAT_TAG "OLYMPE.OLtest$214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26",
   "password"},
  {NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static char saved_salt[SALT_SIZE];
static ARCH_WORD_32 (*crypt_out)[16];

static krb5_data salt;
static krb5_enctype enctype;

static void init(struct fmt_main *pFmt)
{
#ifdef _OPENMP
	if (krb5_is_thread_safe()) {
		int omp_t = omp_get_max_threads();
		pFmt->params.min_keys_per_crypt *= omp_t;
		omp_t *= OMP_SCALE;
		pFmt->params.max_keys_per_crypt *= omp_t;
	} else
		omp_set_num_threads(1);
#endif
	salt.data = "";
	salt.length = 0;
	enctype = 18; /* AES256_CTS_HMAC_SHA1 */

	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
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


static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
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
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index++)
#endif
	{
		int i;
		krb5_data string;
		krb5_keyblock key;

		memset(&key, 0, sizeof(krb5_keyblock));

		salt.data = saved_salt;
		salt.length = strlen(salt.data);
		string.data = saved_key[index];
		string.length = strlen(saved_key[index]);
#ifdef HAVE_MKSHIM
		krb5_c_string_to_key (NULL, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
		                      &string, &salt, &key);
#else
		krb5_c_string_to_key_with_params(NULL, enctype, &string, &salt,
		                                 NULL, &key);
#endif
		for(i = 0; i < key.length / 4; i++){
			crypt_out[index][i] = (key.contents[4 * i]) |
				(key.contents[4 * i + 1] << 8) |
				(key.contents[4 * i + 2] << 16) |
				(key.contents[4 * i + 3] << 24);
		}
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

static int get_hash_0(int index) { return *((ARCH_WORD_32*)&crypt_out[index]) & 0xf; }
static int get_hash_1(int index) { return *((ARCH_WORD_32*)&crypt_out[index]) & 0xff; }
static int get_hash_2(int index) { return *((ARCH_WORD_32*)&crypt_out[index]) & 0xfff; }
static int get_hash_3(int index) { return *((ARCH_WORD_32*)&crypt_out[index]) & 0xffff; }
static int get_hash_4(int index) { return *((ARCH_WORD_32*)&crypt_out[index]) & 0xfffff; }
static int get_hash_5(int index) { return *((ARCH_WORD_32*)&crypt_out[index]) & 0xffffff; }
static int get_hash_6(int index) { return *((ARCH_WORD_32*)&crypt_out[index]) & 0x7ffffff; }

struct fmt_main fmt_krb5_18 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
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
		fmt_default_done,
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

#endif /* HAVE_KRB5 */

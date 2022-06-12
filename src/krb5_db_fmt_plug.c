/*
 * KRB5 - Enctype 18 (aes256-cts-hmac-sha1-96) cracker patch for JtR
 * Created on August of 2012 by Mougey Camille (CEA/DAM) & Lalet Pierre (CEA/DAM)
 *
 * This format is one of formats saved in KDC database and used during the authentication part.
 *
 * This software is Copyright (c) 2012, Mougey Camille (CEA/DAM), and Lalet
 * Pierre (CEA/DAM) and it is hereby released to the general public under the
 * following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format :
 * - user:$krb18$REALMname$hash
 * - user:REALMname$hash
 *
 * Format rewritten Dec, 2014, without use of -lkrb5, by JimF.  Now we use 'native' JtR
 * pbkdf2-hmac-sha1() and simple call to 2 AES limb encrypt for entire process. Very
 * simple, and 10x faster, and no obsure -lkrb5 dependency.
 *
 * Added support for etype 17 and etype 2/3 in October, 2017 by Dhiru Kholia.
 *
 * Note: Both etype 2 and 3 share the same hashing scheme!
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_krb5_18;
extern struct fmt_main fmt_krb5_17;
extern struct fmt_main fmt_krb5_3;
#elif FMT_REGISTERS_H
john_register_one(&fmt_krb5_18);
john_register_one(&fmt_krb5_17);
john_register_one(&fmt_krb5_3);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"
#include "simd-intrinsics.h"
#include "pbkdf2_hmac_sha1.h"
#include "aes.h"
#include "krb5_common.h"

#define FORMAT_LABEL            "krb5-18"
#define FORMAT_LABEL_17         "krb5-17"
#define FORMAT_LABEL_3          "krb5-3"
#define FORMAT_NAME             "Kerberos 5 DB etype 18"
#define FORMAT_NAME_17          "Kerberos 5 DB etype 17"
#define FORMAT_NAME_3           "Kerberos 5 DB etype 3"
#define FORMAT_TAG_18           "$krb18$"
#define FORMAT_TAG_17           "$krb17$"
#define FORMAT_TAG_3            "$krb3$"
#define TAG_LENGTH_18           (sizeof(FORMAT_TAG_18)-1)
#define TAG_LENGTH_17           (sizeof(FORMAT_TAG_17)-1)
#define TAG_LENGTH_3            (sizeof(FORMAT_TAG_3)-1)
#if SIMD_COEF_32
#define ALGORITHM_NAME          "DES / PBKDF2-SHA1 " SHA1_ALGORITHM_NAME " AES"
#else
#define ALGORITHM_NAME          "DES / PBKDF2-SHA1 32/" ARCH_BITS_STR " AES"
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BENCHMARK_LENGTH_3      7
#define PLAINTEXT_LENGTH        64
#define CIPHERTEXT_LENGTH_18    64
#define CIPHERTEXT_LENGTH_17    32
#define CIPHERTEXT_LENGTH_3     16
#define BINARY_SIZE_18          32
#define BINARY_SIZE_17          16
#define BINARY_SIZE_3           8
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define MAX_SALT_SIZE           128
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA1 * 2)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      16
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               128 // Tuned w/ MKPC for super
#endif

static struct fmt_tests kinit_tests_18[] = {
	{"OLYMPE.OLtest$214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26", "password"},
	{FORMAT_TAG_18 "OLYMPE.OLtest$214bb89cf5b8330112d52189ab05d9d05b03b5a961fe6d06203335ad5f339b26", "password"},
	{NULL}
};

static struct fmt_tests kinit_tests_17[] = {
	// bare hashes are not supported for etype 17
	{FORMAT_TAG_17 "TEST.LOCALtest$6fb8b78e20ad3df6591cabb9cacf4594", "password"},
	{FORMAT_TAG_17 "TEST.LOCALtest$b7dc1cf2b403cf5f27ea9b2ea526dc5a", "password@123"},
	{NULL}
};

static struct fmt_tests kinit_tests_3[] = {
	{FORMAT_TAG_3 "INTERNAL.CORP1user3$eafdc79b7620584a", "password"},
	{FORMAT_TAG_3 "EXAMPLE.COMlulu$25bfb33132c11346", "password"},
	{FORMAT_TAG_3 "EXAMPLE.COMluluaaaa$97076894ae025738", "password"},
	{"$krb3$EXAMPLE.COMluluaaaa$79850e6e9e5e92d0", "password@123"},
	// etype 2 hash
	{"$krb3$EXAMPLE.COMluluaaaa$cbb5616879c26df8", "12345678"},
	{NULL},
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[8];

static struct custom_salt {
	uint32_t etype;
	char saved_salt[MAX_SALT_SIZE+1];  // XXX is this enough?
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

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

static int valid(char* ciphertext, int pos)
{
	char *p, *q;

	p = ciphertext + pos;
	p = strstr(p, "$");
	if (p == NULL)
		return 0;

	q = ciphertext;

	if (p - q > MAX_SALT_SIZE) /* check salt length */
		return 0;
	q = ++p;

	while (atoi16l[ARCH_INDEX(*q)] != 0x7F) {
		q++;
	}

	return !*q && (q - p == CIPHERTEXT_LENGTH_18 || q - p == CIPHERTEXT_LENGTH_17 || q - p == CIPHERTEXT_LENGTH_3);
}

static int valid_18(char* ciphertext, struct fmt_main *self)
{
	if (!strncmp(ciphertext, FORMAT_TAG_18, TAG_LENGTH_18))
		return valid(ciphertext, TAG_LENGTH_18);
	else
		return valid(ciphertext, 0);
}

static int valid_17(char* ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, FORMAT_TAG_17, TAG_LENGTH_17))
		return 0;
	return valid(ciphertext, TAG_LENGTH_17);
}

static int valid_3(char* ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, FORMAT_TAG_3, TAG_LENGTH_3))
		return 0;
	return valid(ciphertext, TAG_LENGTH_3);
}

// Only supports bare hashes for etype 18
static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH_18 + CIPHERTEXT_LENGTH_18 + SALT_SIZE + 1];

	if (!strncmp(ciphertext, FORMAT_TAG_18, TAG_LENGTH_18) || !strncmp(ciphertext, FORMAT_TAG_17, TAG_LENGTH_17) || !strncmp(ciphertext, FORMAT_TAG_3, TAG_LENGTH_3))
		return ciphertext;

	memcpy(out, FORMAT_TAG_18, TAG_LENGTH_18);
	strnzcpy(out + TAG_LENGTH_18, ciphertext, CIPHERTEXT_LENGTH_18 + SALT_SIZE + 1);

	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p, *q;

	memset(&cs, 0, SALT_SIZE);
	if (!strncmp(ciphertext, FORMAT_TAG_18, TAG_LENGTH_18)) {
		cs.etype = 18;
		p = ciphertext + TAG_LENGTH_18;
	} else if (!strncmp(ciphertext, FORMAT_TAG_17, TAG_LENGTH_17)) {
		cs.etype = 17;
		p = ciphertext + TAG_LENGTH_17;
	} else {
		cs.etype = 3;
		p = ciphertext + TAG_LENGTH_3;
	}
	q = strstr(p, "$");
	strncpy(cs.saved_salt, p, q-p);
	cs.saved_salt[MAX_SALT_SIZE] = 0;

	return (void*)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i = 0;
	unsigned int binary_size = 0;

	p = ciphertext;
	if (!strncmp(ciphertext, FORMAT_TAG_18, TAG_LENGTH_18)) {
		binary_size = 32;
		p = ciphertext + TAG_LENGTH_18;
	} else if (!strncmp(ciphertext, FORMAT_TAG_17, TAG_LENGTH_17)) {
		binary_size = 16;
		p = ciphertext + TAG_LENGTH_17;
	} else {
		binary_size = 8;
		p = ciphertext + TAG_LENGTH_3;
	}

	/* 32 is max possible binary_size above */
	if (!out) out = mem_alloc_tiny(32, MEM_ALIGN_WORD);
	p = strstr(p, "$") + 1;

	for (; i < binary_size; i++) {
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
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char key[32], i;
		AES_KEY aeskey;
		int key_size;

		if (cur_salt->etype == 18 || cur_salt->etype == 17) {
#ifdef SSE_GROUP_SZ_SHA1
			uint32_t Key[SSE_GROUP_SZ_SHA1][32/4];
			int lens[SSE_GROUP_SZ_SHA1];
			unsigned char *pin[SSE_GROUP_SZ_SHA1];
			union {
				uint32_t *pout[SSE_GROUP_SZ_SHA1];
				unsigned char *poutc;
			} x;
			for (i = 0; i < SSE_GROUP_SZ_SHA1; ++i) {
				lens[i] = strlen(saved_key[index+i]);
				pin[i] = (unsigned char*)saved_key[index+i];
				x.pout[i] = Key[i];
			}
			if (cur_salt->etype == 18) {
				key_size = 32;
			} else {
				key_size = 16;
			}
			pbkdf2_sha1_sse((const unsigned char **)pin, lens, (const unsigned char*)cur_salt->saved_salt, strlen(cur_salt->saved_salt), 4096, &(x.poutc), key_size, 0);
#else
			if (cur_salt->etype == 18) {
				key_size = 32;
			} else {
				key_size = 16;
			}
			pbkdf2_sha1((const unsigned char*)saved_key[index], strlen(saved_key[index]), (const unsigned char*)cur_salt->saved_salt, strlen(cur_salt->saved_salt), 4096, key, key_size, 0);
#endif
			i = 0;
#ifdef SSE_GROUP_SZ_SHA1
			for (; i < SSE_GROUP_SZ_SHA1; ++i) {
				memcpy(key, Key[i], key_size);
#endif
				AES_set_encrypt_key(key, key_size * 8, &aeskey);
				AES_encrypt((unsigned char*)"kerberos{\x9b[+\x93\x13+\x93", (unsigned char*)(crypt_out[index+i]), &aeskey); // the weird constant string comes from "nfold" function
				AES_encrypt((unsigned char*)(crypt_out[index+i]), (unsigned char*)&crypt_out[index+i][4], &aeskey);
#ifdef SSE_GROUP_SZ_SHA1
			}
#endif
		} else if (cur_salt->etype == 3) {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				des_string_to_key_shishi(saved_key[index+i], strlen(saved_key[index+i]), cur_salt->saved_salt, strlen(cur_salt->saved_salt), (unsigned char*)(crypt_out[index+i]));
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (crypt_out[index][0] == *(uint32_t*)binary)
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE_3);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_krb5_18 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE_18,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG_18 },
		kinit_tests_18
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_18,
		split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact,
	}
};

struct fmt_main fmt_krb5_17 = {
	{
		FORMAT_LABEL_17,
		FORMAT_NAME_17,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE_17,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG_17 },
		kinit_tests_17
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_17,
		split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact,
	}
};

struct fmt_main fmt_krb5_3 = {
	{
		FORMAT_LABEL_3,
		FORMAT_NAME_3,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH_3,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE_3,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG_3 },
		kinit_tests_3
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_3,
		split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact,
	}
};


#endif /* plugin stanza */
#endif /* HAVE_LIBCRYPTO */

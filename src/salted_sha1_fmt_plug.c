/*
 * generic salted-sha1 support for LDAP style password storage
 *
 * Copyright (c) 2003 Simon Marechal, salt length fixes (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_saltedsha;
#elif FMT_REGISTERS_H
john_register_one(&fmt_saltedsha);
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
#include "salted_sha1_common.h"
#include "simd-intrinsics.h"
#include "common.h"
#include "sha.h"
#include "base64_convert.h"

#define FORMAT_LABEL			"Salted-SHA1"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		(55-MAX_SALT_LEN)

#define BINARY_ALIGN			4
#define SALT_SIZE			(MAX_SALT_LEN + sizeof(unsigned int))
#define SALT_ALIGN			4

#ifdef SIMD_COEF_32
#define NBKEYS  (SIMD_COEF_32 * SIMD_PARA_SHA1)
#define FMT_IS_BE
#include "common-simd-getpos.h"
#define MIN_KEYS_PER_CRYPT      NBKEYS
#define MAX_KEYS_PER_CRYPT      (NBKEYS * 512)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      512
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

struct s_salt
{
	unsigned int len;
	union {
		unsigned char c[MAX_SALT_LEN+1];
		uint32_t w32;
	} data;
};

static struct s_salt *saved_salt;


#ifdef SIMD_COEF_32
static uint32_t (*saved_key)[SHA_BUF_SIZ*NBKEYS];
static uint32_t (*crypt_key)[BINARY_SIZE/4*NBKEYS];
static unsigned int *saved_len;
static int last_salt_size;
#else
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_key)[BINARY_SIZE / 4];
static unsigned int *saved_len;
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifndef SIMD_COEF_32
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#else
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*crypt_key), MEM_ALIGN_SIMD);
#endif
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static void * get_binary(char *ciphertext) {
	static char *realcipher;

	if (!realcipher) realcipher = mem_alloc_tiny(CIPHERTEXT_LENGTH, MEM_ALIGN_WORD);

	ciphertext += NSLDAP_MAGIC_LENGTH;
	memset(realcipher, 0, BINARY_SIZE);
	base64_convert(ciphertext, e_b64_mime, strlen(ciphertext), realcipher, e_b64_raw, CIPHERTEXT_LENGTH, flg_Base64_DONOT_NULL_TERMINATE, 0);
#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN==1
	alter_endianity((unsigned char *)realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

#define SET_SAVED_LEN
#include "common-simd-setkey32.h"

static void * get_salt(char * ciphertext)
{
	static struct s_salt cursalt;
	char realcipher[BINARY_SIZE + MAX_SALT_LEN];
	int len;

	ciphertext += NSLDAP_MAGIC_LENGTH;
	memset(realcipher, 0, sizeof(realcipher));
	memset(&cursalt, 0, sizeof(struct s_salt));
	len = strlen(ciphertext);
	cursalt.len = base64_convert(ciphertext, e_b64_mime, len, realcipher, e_b64_raw, BINARY_SIZE+MAX_SALT_LEN, flg_Base64_DONOT_NULL_TERMINATE, 0) - BINARY_SIZE;

	memcpy(cursalt.data.c, realcipher+BINARY_SIZE, cursalt.len);
	return &cursalt;
}

static int cmp_all(void *binary, int count) {
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
		if (((uint32_t *) binary)[0] == ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + index/SIMD_COEF_32*5*SIMD_COEF_32])
#else
		if ( ((uint32_t*)binary)[0] == ((uint32_t*)&(crypt_key[index][0]))[0] )
#endif
			return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int cmp_one(void * binary, int index)
{
#ifdef SIMD_COEF_32
	int i;

	for (i = 0; i < BINARY_SIZE/sizeof(uint32_t); i++)
		if (((uint32_t *) binary)[i] != ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32+i*SIMD_COEF_32])
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static void set_salt(void *salt) {
	saved_salt = salt;
}

#ifdef SIMD_COEF_32
inline static void set_onesalt(int index)
{
	unsigned int i, idx=index%NBKEYS;
	unsigned char *sk = (unsigned char*)&saved_key[index/NBKEYS];

	for (i=0;i<saved_salt->len;++i)
		sk[GETPOS(i+saved_len[index], idx)] = saved_salt->data.c[i];
	sk[GETPOS(i+saved_len[index], idx)] = 0x80;

	while (++i <= last_salt_size)
		sk[GETPOS(i+saved_len[index], idx)] = 0;

	((unsigned int*)sk)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + idx/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = (saved_salt->len + saved_len[index])<<3;
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	int inc = 1;

#ifdef SIMD_COEF_32
	inc = NBKEYS;
#endif

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += inc) {
#ifdef SIMD_COEF_32
		unsigned int i;

		for (i=0;i<NBKEYS;i++)
			set_onesalt(i+index);
		SIMDSHA1body(saved_key[index/NBKEYS], crypt_key[index/NBKEYS], NULL, SSEi_MIXED_IN);
#else
		SHA_CTX ctx;
		SHA1_Init( &ctx );
		SHA1_Update( &ctx, (unsigned char *) saved_key[index], strlen( saved_key[index] ) );
		SHA1_Update( &ctx, (unsigned char *) saved_salt->data.c, saved_salt->len);
		SHA1_Final( (unsigned char *)crypt_key[index], &ctx);
#endif
	}
#ifdef SIMD_COEF_32
	last_salt_size = saved_salt->len;
#endif
	return count;
}

#define COMMON_GET_HASH_SIMD32 5
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	struct s_salt *mysalt = salt;

	return mysalt->data.w32 & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_saltedsha = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ NSLDAP_MAGIC },
		salted_sha1_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		salted_sha1_common_valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

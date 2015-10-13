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

#define MAX_SALT_LEN    16      // bytes, the base64 representation is longer

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "options.h"
#include "johnswap.h"
#include "common.h"
#include "sha2.h"
#include "base64.h"
#include "simd-intrinsics.h"
#include <string.h>

#ifdef _OPENMP
#ifdef SIMD_COEF_64
#ifndef OMP_SCALE
#define OMP_SCALE               1024
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE				2048
#endif
#endif
#include <omp.h>
#endif

#include "memdbg.h"

#define FORMAT_LABEL                    "SSHA512"
#define FORMAT_NAME                     "LDAP"

#ifdef SIMD_COEF_64
#define ALGORITHM_NAME					"SHA512 " SHA512_ALGORITHM_NAME
#else
#if ARCH_BITS >= 64
#define ALGORITHM_NAME					"SHA512 64/" ARCH_BITS_STR " " SHA2_LIB
#else
#define ALGORITHM_NAME					"SHA512 32/" ARCH_BITS_STR " " SHA2_LIB
#endif
#endif

#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH                0

#define PLAINTEXT_LENGTH                (111-MAX_SALT_LEN)

#define BINARY_SIZE                     (512 / 8)
#define BINARY_ALIGN                    8
#define SALT_SIZE                       (MAX_SALT_LEN + sizeof(unsigned int))
#define SALT_ALIGN                      4

#define CIPHERTEXT_LENGTH               ((BINARY_SIZE + 1 + MAX_SALT_LEN + 2) / 3 * 4)

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT		(SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{SSHA512}"
#define NSLDAP_MAGIC_LENGTH (sizeof(NSLDAP_MAGIC) - 1)
#define BASE64_ALPHABET	  \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

struct s_salt
{
	unsigned int len;
	union {
		unsigned char c[MAX_SALT_LEN];
		ARCH_WORD_32 w32;
	} data;
};

static struct s_salt *saved_salt;

static struct fmt_tests tests[] = {
	{"{SSHA512}SCMmLlStPIxVtJc8Y6REiGTMsgSEFF7xVQFoYZYg39H0nEeDuK/fWxxNZCdSYlRgJK3U3q0lYTka3Nre2CjXzeNUjbvHabYP", "password"},
	{"{SSHA512}WucBQuH6NyeRYMz6gHQddkJLwzTUXaf8Ag0n9YM0drMFHG9XCO+FllvvwjXmo5/yFPvs+n1JVvJmdsvX5XHYvSUn9Xw=", "test123"},
	{"{SSHA512}uURShqzuCx/8BKVrc4HkTpYnv2eVfwEzg+Zi2AbsTQaIV7Xo6pDhRAZnp70h5P8MC6XyotrB2f27aLhhRj4GYrkJSFmbKmuF", "testpass"},
	{NULL}
};

#ifdef SIMD_COEF_64
#define GETPOS(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
static ARCH_WORD_64 (*saved_key)[SHA_BUF_SIZ*SIMD_COEF_64];
static ARCH_WORD_64 (*crypt_out)[8*SIMD_COEF_64];
static ARCH_WORD_64 (**len_ptr64);
static int max_count;
#else
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / 4];
static ARCH_WORD_64 (*saved_key)[PLAINTEXT_LENGTH + 1];
#endif
static int *saved_len;

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_64
	unsigned int i, j;
#endif
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
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
		ARCH_WORD_64 *keybuffer = &((ARCH_WORD_64 *)saved_key)[(i&(SIMD_COEF_64-1)) + (i/SIMD_COEF_64)*SHA_BUF_SIZ*SIMD_COEF_64];
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

static void * get_binary(char *ciphertext) {
	static char *realcipher;

	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE + 1 + SALT_SIZE, 8);

	ciphertext += NSLDAP_MAGIC_LENGTH;
	memset(realcipher, 0, BINARY_SIZE);
	base64_decode(ciphertext, strlen(ciphertext), realcipher);
#ifdef SIMD_COEF_64
	alter_endianity_to_BE64 (realcipher, BINARY_SIZE/8);
#endif
	return (void*)realcipher;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int len;

	if (strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH))
		return 0;
	ciphertext += NSLDAP_MAGIC_LENGTH;

	len = strspn(ciphertext, BASE64_ALPHABET);
	if (len < (BINARY_SIZE+1+2)/3*4-2)
		return 0;

	len = strspn(ciphertext, BASE64_ALPHABET "=");
	if (len != strlen(ciphertext))
		return 0;
	if (len & 3 || len > CIPHERTEXT_LENGTH)
		return 0;

	return 1;
}

#ifdef SIMD_COEF_64
static void set_key(char *key, int index) {
#if ARCH_ALLOWS_UNALIGNED
	const ARCH_WORD_64 *wkey = (ARCH_WORD_64*)key;
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint64_t));
	const ARCH_WORD_64 *wkey = is_aligned(key, sizeof(uint64_t)) ?
			(ARCH_WORD_64*)key : (ARCH_WORD_64*)strcpy(buf_aligned, key);
#endif
	ARCH_WORD_64 *keybuffer = &((ARCH_WORD_64 *)saved_key)[(index&(SIMD_COEF_64-1)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64];
	ARCH_WORD_64 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_64 temp;

	len = 0;
	while((unsigned char)(temp = *wkey++)) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = JOHNSWAP64(temp & 0xff);
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = JOHNSWAP64(temp & 0xffff);
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = JOHNSWAP64(temp & 0xffffff);
			len+=3;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000ULL))
		{
			*keybuf_word = JOHNSWAP64(temp & 0xffffffff);
			len+=4;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000000000ULL))
		{
			*keybuf_word = JOHNSWAP64(temp & 0xffffffffffULL);
			len+=5;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000000000ULL))
		{
			*keybuf_word = JOHNSWAP64(temp & 0xffffffffffffULL);
			len+=6;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000000000ULL))
		{
			*keybuf_word = JOHNSWAP64(temp & 0xffffffffffffffULL);
			len+=7;
			goto key_cleaning;
		}
		*keybuf_word = JOHNSWAP64(temp);
		len += 8;
		keybuf_word += SIMD_COEF_64;
	}

key_cleaning:
	saved_len[index] = len;
	keybuf_word += SIMD_COEF_64;
	while(*keybuf_word && keybuf_word < &keybuffer[15*SIMD_COEF_64]) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_64;
	}
}
#else
static void set_key(char *key, int index)
{
	int len = strlen(key);

	saved_len[index] = len;
	memcpy(saved_key[index], key, len + 1);
}
#endif

static void * get_salt(char * ciphertext)
{
	static struct s_salt cursalt;
	char *p;
	char realcipher[CIPHERTEXT_LENGTH];
	int len;

	ciphertext += NSLDAP_MAGIC_LENGTH;
	memset(realcipher, 0, sizeof(realcipher));
	memset(&cursalt, 0, sizeof(struct s_salt));
	len = strlen(ciphertext);
	base64_decode(ciphertext, len, realcipher);

	// We now support any salt length up to SALT_SIZE
	cursalt.len = (len + 3) / 4 * 3 - BINARY_SIZE;
	p = &ciphertext[len];
	while (*--p == '=')
		cursalt.len--;

	memcpy(cursalt.data.c, realcipher+BINARY_SIZE, cursalt.len);
	return &cursalt;
}

#ifdef SIMD_COEF_64
static char *get_key(int index) {
	unsigned i;
	ARCH_WORD_64 s;
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned char *wucp = (unsigned char*)saved_key;

	s = saved_len[index];
	for(i=0;i<(unsigned)s;i++)
		out[i] = wucp[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*) out;
}
#else
static char *get_key(int index) {
	return (char*)saved_key[index];
}
#endif

static int cmp_all(void *binary, int count) {
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_64
        if (((ARCH_WORD_64 *) binary)[0] == crypt_out[index/SIMD_COEF_64][index&(SIMD_COEF_64-1)])
#else
		if ( ((ARCH_WORD_32*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_64
    int i;
	for (i = 0; i < BINARY_SIZE/sizeof(ARCH_WORD_64); i++)
        if (((ARCH_WORD_64 *) binary)[i] != crypt_out[index/SIMD_COEF_64][(index&(SIMD_COEF_64-1))+i*SIMD_COEF_64])
            return 0;
	return 1;
#else
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
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
	for (index = 0; index < count; index+=MAX_KEYS_PER_CRYPT) {
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
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
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
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
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

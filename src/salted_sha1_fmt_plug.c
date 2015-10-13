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

#include "misc.h"
#include "formats.h"
#include "arch.h"
#include "options.h"
#include "johnswap.h"
#include "salted_sha1_common.h"

#ifdef SIMD_COEF_32
#define NBKEYS	(SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif
#include "simd-intrinsics.h"

#include "common.h"

#include "sha.h"
#include "base64.h"

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

#define FORMAT_LABEL			"Salted-SHA1"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		(55-MAX_SALT_LEN)

#define BINARY_ALIGN			4
#define SALT_SIZE			(MAX_SALT_LEN + sizeof(unsigned int))
#define SALT_ALIGN			4

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

struct s_salt
{
	unsigned int len;
	union {
		unsigned char c[MAX_SALT_LEN];
		ARCH_WORD_32 w32;
	} data;
};

static struct s_salt *saved_salt;


#ifdef SIMD_COEF_32
static ARCH_WORD_32 (*saved_key)[SHA_BUF_SIZ*NBKEYS];
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE/4*NBKEYS];
static unsigned int *saved_len;
static unsigned char out[PLAINTEXT_LENGTH + 1];
static int last_salt_size;
#else
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / 4];
#endif

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifndef SIMD_COEF_32
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#else
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*crypt_key), MEM_ALIGN_SIMD);
#endif
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
#ifdef SIMD_COEF_32
	MEM_FREE(saved_len);
#endif
}

static void * get_binary(char *ciphertext) {
	static char *realcipher;

	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE + 1 + SALT_SIZE, MEM_ALIGN_WORD);

	ciphertext += NSLDAP_MAGIC_LENGTH;
	memset(realcipher, 0, BINARY_SIZE);
	base64_decode(ciphertext, strlen(ciphertext), realcipher);
#ifdef SIMD_COEF_32
	alter_endianity((unsigned char *)realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

static void set_key(char *key, int index)
{
#ifdef SIMD_COEF_32
#if ARCH_ALLOWS_UNALIGNED
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint32_t));
	const ARCH_WORD_32 *wkey = (uint32_t*)(is_aligned(key, sizeof(uint32_t)) ?
	                                       key : strcpy(buf_aligned, key));
#endif
	ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32*)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32];
	ARCH_WORD_32 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_32 temp;

	len = 0;
	while((unsigned char)(temp = *wkey++)) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = JOHNSWAP((temp & 0xff) | (0x80 << 8));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = JOHNSWAP((temp & 0xffff) | (0x80 << 16));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = JOHNSWAP(temp | (0x80 << 24));
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = JOHNSWAP(temp);
		len += 4;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80000000;

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}

	saved_len[index] = len;
#else
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
#endif
}

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

static char *get_key(int index) {
#ifdef SIMD_COEF_32
	unsigned int i,s;

	s = saved_len[index];
	for(i=0;i<s;i++)
		out[i] = ((char*)saved_key)[GETPOS(i, index)];
	out[i] = 0;
	return (char *) out;
#else
	return saved_key[index];
#endif
}

static int cmp_all(void *binary, int count) {
	unsigned int index;
	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
        if (((ARCH_WORD_32 *) binary)[0] == ((ARCH_WORD_32*)crypt_key)[(index&(SIMD_COEF_32-1)) + index/SIMD_COEF_32*5*SIMD_COEF_32])
#else
		if ( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)&(crypt_key[index][0]))[0] )
#endif
			return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	return (1);
}

static int cmp_one(void * binary, int index)
{
#ifdef SIMD_COEF_32
    int i;
	for (i = 0; i < BINARY_SIZE/sizeof(ARCH_WORD_32); i++)
        if (((ARCH_WORD_32 *) binary)[i] != ((ARCH_WORD_32*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32+i*SIMD_COEF_32])
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
static inline void set_onesalt(int index)
{
	unsigned int i, idx=index%NBKEYS;
	unsigned char *sk = (unsigned char*)&saved_key[index/NBKEYS];

	for(i=0;i<saved_salt->len;++i)
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
	int index = 0;

#ifdef _OPENMP
#ifdef SIMD_COEF_32
	int inc = NBKEYS;
#else
	int inc = 1;
#endif

#pragma omp parallel for
	for (index=0; index < count; index += inc)
#endif
	{
#ifdef SIMD_COEF_32
		unsigned int i;

		for(i=0;i<NBKEYS;i++)
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

#ifdef SIMD_COEF_32
#define HASH_OFFSET	(index&(SIMD_COEF_32-1))+(((unsigned int)index%NBKEYS)/SIMD_COEF_32)*SIMD_COEF_32*5
static int get_hash_0(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return crypt_key[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_key[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_key[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_key[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_key[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_key[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_key[index][0] & PH_MASK_6; }
#endif

static int salt_hash(void *salt)
{
	struct s_salt * mysalt = salt;
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

/*
 * This software is Copyright (c) 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * Based on hmac-md5 by Bartavelle
 *
 * SIMD added Feb, 2015, JimF.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_hmacSHA384;
#elif FMT_REGISTERS_H
john_register_one(&fmt_hmacSHA384);
#else

#include "sha2.h"

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "aligned.h"
#include "johnswap.h"
#include "sse-intrinsics.h"

#ifdef _OPENMP
#include <omp.h>
#ifdef SIMD_COEF_64
#ifndef OMP_SCALE
#define OMP_SCALE               1024 // scaled on core i7-quad HT
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               512 // scaled K8-dual HT
#endif
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL			"HMAC-SHA384"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"password is key, SHA384 " SHA512_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125

#define PAD_SIZE			128
#define BINARY_SIZE			(384/8)
#define BINARY_SIZE_512			(512/8)
#define BINARY_ALIGN			8

#ifndef SIMD_COEF_64
#define SALT_LENGTH			1024
#else
#define SALT_LENGTH			111
#endif
#define SALT_ALIGN			1
#define CIPHERTEXT_LENGTH		(SALT_SIZE + 1 + BINARY_SIZE * 2)

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define GETPOS(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static struct fmt_tests tests[] = {
	{"what do ya want for nothing?#af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649", "Jefe"},
	{"Beppe#Grillo#8361922C63506E53714F8A8491C6621A76CF0FD6DFEAD91BF59B420A23DFF2745C0A0D5E142D4F937E714EA8C228835B", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	{NULL}
};

#ifdef SIMD_COEF_64
#define cur_salt hmacsha384_cur_salt
static unsigned char *crypt_key;
static unsigned char *ipad, *prep_ipad;
static unsigned char *opad, *prep_opad;
JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char cur_salt[SALT_LENGTH * 8 * MAX_KEYS_PER_CRYPT];
static int bufsize;
#else
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static unsigned char (*opad)[PAD_SIZE];
static unsigned char (*ipad)[PAD_SIZE];
static unsigned char cur_salt[SALT_LENGTH+1];
static SHA512_CTX *ipad_ctx;
static SHA512_CTX *opad_ctx;
#endif

#define SALT_SIZE               sizeof(cur_salt)

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int new_keys;

#ifdef SIMD_COEF_64
static void clear_keys(void)
{
	memset(ipad, 0x36, bufsize);
	memset(opad, 0x5C, bufsize);
}
#endif

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_64
	int i;
#endif
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef SIMD_COEF_64
	bufsize = sizeof(ARCH_WORD_64) * self->params.max_keys_per_crypt * SHA_BUF_SIZ;
	crypt_key = mem_calloc_tiny(bufsize, MEM_ALIGN_SIMD);
	ipad = mem_calloc_tiny(bufsize, MEM_ALIGN_SIMD);
	opad = mem_calloc_tiny(bufsize, MEM_ALIGN_SIMD);
	prep_ipad = mem_calloc_tiny(self->params.max_keys_per_crypt * BINARY_SIZE_512, MEM_ALIGN_SIMD);
	prep_opad = mem_calloc_tiny(self->params.max_keys_per_crypt * BINARY_SIZE_512, MEM_ALIGN_SIMD);
	for (i = 0; i < self->params.max_keys_per_crypt; ++i) {
		crypt_key[GETPOS(BINARY_SIZE, i)] = 0x80;
		((ARCH_WORD_64*)crypt_key)[15 * SIMD_COEF_64 + (i & (SIMD_COEF_64-1)) + (i/SIMD_COEF_64) * SHA_BUF_SIZ * SIMD_COEF_64] = (BINARY_SIZE + PAD_SIZE) << 3;
	}
	clear_keys();
#else
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	ipad = mem_calloc_tiny(sizeof(*ipad) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	opad = mem_calloc_tiny(sizeof(*opad) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	ipad_ctx = mem_calloc_tiny(sizeof(*ipad_ctx) * self->params.max_keys_per_crypt, 8);
	opad_ctx = mem_calloc_tiny(sizeof(*opad_ctx) * self->params.max_keys_per_crypt, 8);
#endif
	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}


static int valid(char *ciphertext, struct fmt_main *self)
{
	int pos, i;
	char *p;

	p = strrchr(ciphertext, '#'); // allow # in salt
	if (!p || p > &ciphertext[strlen(ciphertext)-1]) return 0;
	i = (int)(p - ciphertext);
#if SIMD_COEF_64
	if(i > 111) return 0;
#else
	if(i > SALT_LENGTH) return 0;
#endif
	pos = i+1;
	if (strlen(ciphertext+pos) != BINARY_SIZE*2) return 0;
	for (i = pos; i < BINARY_SIZE*2+pos; i++)
	{
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
		        (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		        || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(strrchr(out, '#'));

	return out;
}

static void set_salt(void *salt)
{
	memcpy(cur_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	int len;

#ifdef SIMD_COEF_64
	ARCH_WORD_64 *ipadp = (ARCH_WORD_64*)&ipad[GETPOS(7, index)];
	ARCH_WORD_64 *opadp = (ARCH_WORD_64*)&opad[GETPOS(7, index)];
	const ARCH_WORD_64 *keyp = (ARCH_WORD_64*)key;
	ARCH_WORD_64 temp;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

#if PAD_SIZE < PLAINTEXT_LENGTH
	if (len > PAD_SIZE) {
		unsigned char k0[BINARY_SIZE];
		SHA512_CTX ctx;
		int i;

		SHA384_Init(&ctx);
		SHA384_Update(&ctx, key, len);
		SHA384_Final(k0, &ctx);

		keyp = (ARCH_WORD_64*)k0;
		for(i = 0; i < BINARY_SIZE / 8; i++, ipadp += SIMD_COEF_64, opadp += SIMD_COEF_64)
		{
			temp = JOHNSWAP64(*keyp++);
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	}
	else
#endif
	while(((temp = JOHNSWAP64(*keyp++)) & 0xff00000000000000)) {
		if (!(temp & 0x00ff000000000000) || !(temp & 0x0000ff0000000000))
		{
			((unsigned short*)ipadp)[3] ^=
				(unsigned short)(temp >> 48);
			((unsigned short*)opadp)[3] ^=
				(unsigned short)(temp >> 48);
			break;
		}
		if (!(temp & 0x00ff00000000) || !(temp & 0x0000ff000000))
		{
			((ARCH_WORD_32*)ipadp)[1] ^=
				(ARCH_WORD_32)(temp >> 32);
			((ARCH_WORD_32*)opadp)[1] ^=
				(ARCH_WORD_32)(temp >> 32);
			break;
		}
		if (!(temp & 0x00ff0000) || !(temp & 0x0000ff00))
		{
			((ARCH_WORD_32*)ipadp)[1] ^=
				(ARCH_WORD_32)(temp >> 32);
			((ARCH_WORD_32*)opadp)[1] ^=
				(ARCH_WORD_32)(temp >> 32);
			((unsigned short*)ipadp)[1] ^=
				(unsigned short)(temp >> 16);
			((unsigned short*)opadp)[1] ^=
				(unsigned short)(temp >> 16);
			break;
		}
		*ipadp ^= temp;
		*opadp ^= temp;
		if (!(temp & 0xff))
			break;
		ipadp += SIMD_COEF_64;
		opadp += SIMD_COEF_64;
	}
#else
	int i;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	memset(ipad[index], 0x36, PAD_SIZE);
	memset(opad[index], 0x5C, PAD_SIZE);

#if PAD_SIZE < PLAINTEXT_LENGTH
	if (len > PAD_SIZE) {
		SHA512_CTX ctx;
		unsigned char k0[BINARY_SIZE];

		SHA384_Init( &ctx );
		SHA384_Update( &ctx, key, len);
		SHA384_Final( k0, &ctx);

		len = BINARY_SIZE;

		for(i=0;i<len;i++)
		{
			ipad[index][i] ^= k0[i];
			opad[index][i] ^= k0[i];
		}
	}
	else
#endif
	for(i=0;i<len;i++)
	{
		ipad[index][i] ^= key[i];
		opad[index][i] ^= key[i];
	}
#endif
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_plain[index];
}

static int cmp_all(void *binary, int count)
{
#ifdef SIMD_COEF_64
	unsigned int index;

	for(index = 0; index < count; index++) {
		// NOTE crypt_key is in input format (8 * SHA_BUF_SIZ * SIMD_COEF_64)
		if(((ARCH_WORD_64*)binary)[0] == ((ARCH_WORD_64*)crypt_key)[(index&(SIMD_COEF_64-1))+index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64])
			return 1;
	}
	return 0;
#else
	int index = 0;

#if defined(_OPENMP) || (MAX_KEYS_PER_CRYPT > 1)
	for (; index < count; index++)
#endif
		if (((ARCH_WORD_32*)binary)[0] == crypt_key[index][0])
			return 1;
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_64
	int i;
	for(i = 0; i < (BINARY_SIZE/8); i++)
		// NOTE crypt_key is in input format (8 * SHA_BUF_SIZ * SIMD_COEF_64)
		if (((ARCH_WORD_64*)binary)[i] != ((ARCH_WORD_64*)crypt_key)[i * SIMD_COEF_64 + (index & (SIMD_COEF_64-1)) + (index/SIMD_COEF_64) * SHA_BUF_SIZ * SIMD_COEF_64])
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return (1);
}

static int crypt_all(int *pcount, struct db_salt *salt)
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
#ifdef SIMD_COEF_64
		ARCH_WORD_64 *pclear;
		unsigned int i;

		if (new_keys) {
			SSESHA512body(&ipad[index * SHA_BUF_SIZ * 8],
			            (ARCH_WORD_64*)&prep_ipad[index * BINARY_SIZE_512],
			            NULL, SSEi_MIXED_IN|SSEi_CRYPT_SHA384);
			SSESHA512body(&opad[index * SHA_BUF_SIZ * 8],
			            (ARCH_WORD_64*)&prep_opad[index * BINARY_SIZE_512],
			            NULL, SSEi_MIXED_IN|SSEi_CRYPT_SHA384);
		}
		SSESHA512body(cur_salt,
		            (ARCH_WORD_64*)&crypt_key[index * SHA_BUF_SIZ * 8],
		            (ARCH_WORD_64*)&prep_ipad[index * BINARY_SIZE_512],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT|SSEi_CRYPT_SHA384);
		// NOTE, SSESHA384 will output 64 bytes. We need the first 48 (plus the 0x80 padding).
		// so we are forced to 'clean' this crap up, before using the crypt as the input.
		pclear = (ARCH_WORD_64*)&crypt_key[index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; i++) {
			pclear[48/8*SIMD_COEF_64+(i&(SIMD_COEF_64-1))+i/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64] = 0x8000000000000000ULL;
			pclear[48/8*SIMD_COEF_64+(i&(SIMD_COEF_64-1))+i/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64+SIMD_COEF_64] = 0;
		}
		SSESHA512body(&crypt_key[index * SHA_BUF_SIZ * 8],
		            (ARCH_WORD_64*)&crypt_key[index * SHA_BUF_SIZ * 8],
		            (ARCH_WORD_64*)&prep_opad[index * BINARY_SIZE_512],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT|SSEi_CRYPT_SHA384);
#else
		SHA512_CTX ctx;

		if (new_keys) {
			SHA384_Init(&ipad_ctx[index]);
			SHA384_Update(&ipad_ctx[index], ipad[index], PAD_SIZE);
			SHA384_Init(&opad_ctx[index]);
			SHA384_Update(&opad_ctx[index], opad[index], PAD_SIZE);
		}

		memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
		SHA384_Update( &ctx, cur_salt, strlen( (char*) cur_salt) );
		SHA384_Final( (unsigned char*) crypt_key[index], &ctx);
		memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
		SHA384_Update( &ctx, crypt_key[index], BINARY_SIZE);
		SHA384_Final( (unsigned char*) crypt_key[index], &ctx);
#endif
	}
	new_keys = 0;
	return count;
}

static void *get_binary(char *ciphertext)
{
	JTR_ALIGN(BINARY_ALIGN) static unsigned char realcipher[BINARY_SIZE];
	int i,pos;

	for(i=strlen(ciphertext);ciphertext[i]!='#';i--); // allow # in salt
	pos=i+1;
	for(i=0;i<BINARY_SIZE;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];

#ifdef SIMD_COEF_64
	alter_endianity_w64(realcipher, BINARY_SIZE/8);
#endif
	return (void*)realcipher;
}

static void *get_salt(char *ciphertext)
{
	static unsigned char salt[SALT_LENGTH+1];
#ifdef SIMD_COEF_64
	int i = 0;
	unsigned total_len = 0;
#endif
	// allow # in salt
	int len = strrchr(ciphertext, '#') - ciphertext;
	memset(salt, 0, SALT_LENGTH+1);
	memcpy(salt, ciphertext, len);
	salt[len] = 0;
#ifdef SIMD_COEF_64
	memset(cur_salt, 0, sizeof(cur_salt));
	while(((unsigned char*)salt)[total_len])
	{
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
			cur_salt[GETPOS(total_len, i)] = ((unsigned char*)salt)[total_len];
		++total_len;
	}
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
		cur_salt[GETPOS(total_len, i)] = 0x80;
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
		((ARCH_WORD_64*)cur_salt)[15 * SIMD_COEF_64 + (i & (SIMD_COEF_64-1)) + (i/SIMD_COEF_64) * SHA_BUF_SIZ * SIMD_COEF_64] = (total_len + 128) << 3;
	return cur_salt;
#else
	return salt;
#endif
}

#ifdef SIMD_COEF_64
// NOTE crypt_key is in input format (8 * SHA_BUF_SIZ * SIMD_COEF_64)
#define HASH_OFFSET (index & (SIMD_COEF_64 - 1)) + ((unsigned int)index / SIMD_COEF_64) * SIMD_COEF_64 * SHA_BUF_SIZ
static int get_hash_0(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return crypt_key[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_key[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_key[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[index][0] & 0x7ffffff; }
#endif

struct fmt_main fmt_hmacSHA384 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
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
		NULL,
		set_salt,
		set_key,
		get_key,
#ifdef SIMD_COEF_64
		clear_keys,
#else
		fmt_default_clear_keys,
#endif
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

/*
 * Drupal 7 phpass variant using SHA-512 and hashes cut at 258 bits.
 *
 * This software is Copyright (c) 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * These are 8 byte salted hashes with a loop count that defines the number
 * of loops to compute. Drupal uses 258 bits of the hash, this is a multiple of
 * 6 but not 8. I presume this is for getting unpadded base64. Anyway we store
 * an extra byte but for now we will only compare 256 bits. I doubt that will
 * pose any problems. Actually I'm not quite sure the last bits end up correct
 * from the current version of get_binary().
 *
 * Based on [old thick] phpass-md5.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_drupal7;
#elif FMT_REGISTERS_H
john_register_one(&fmt_drupal7);
#else

#include "sha2.h"

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE			8
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL			"Drupal7"
#define FORMAT_NAME			"$S$"
#define FORMAT_TAG			"$S$"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)

#define ALGORITHM_NAME			"SHA512 " SHA512_ALGORITHM_NAME


#define BENCHMARK_COMMENT		" (x16385)"
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		47
#define CIPHERTEXT_LENGTH		55

#define DIGEST_SIZE			(512/8)

#define BINARY_SIZE			(258/8) // ((258+7)/8)
#define BINARY_ALIGN			4
#define SALT_SIZE			8
#define SALT_ALIGN			4

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#if ARCH_LITTLE_ENDIAN
#define GETPOS(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#else
#define GETPOS(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + ((i)&7) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#endif
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests tests[] = {
	{"$S$CwkjgAKeSx2imSiN3SyBEg8e0sgE2QOx4a/VIfCHN0BZUNAWCr1X", "virtualabc"},
	{"$S$CFURCPa.k6FAEbJPgejaW4nijv7rYgGc4dUJtChQtV4KLJTPTC/u", "password"},
	{"$S$C6x2r.aW5Nkg7st6/u.IKWjTerHXscjPtu4spwhCVZlP89UKcbb/", "NEW_TEMP_PASSWORD"},
	{NULL}
};

/*
 * NOTE, due to the 0x4000 iteration count, I am not wasting time pre-loading
 * keys/salts.  We will simply add SIMD code to the crypt_all.  We could only
 * gain < .1% worrying about all the extra stuff from set_key, get_key, the
 * hashes, etc needed to split out SIMD.  We just keep all input data in 'flat'
 * format, switch to SIMD, do the 0x4000 loops, and put output back into 'flat'
 * layout again.  So we have no 'static' SIMD objects.
 */
static unsigned char *cursalt;
static unsigned loopCnt;
static unsigned char (*EncKey)[PLAINTEXT_LENGTH + 1];
static unsigned int *EncKeyLen;
static char (*crypt_key)[DIGEST_SIZE];

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_autotune(self, OMP_SCALE);
#endif
	EncKey    = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*EncKey));
	EncKeyLen = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*EncKeyLen));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(EncKeyLen);
	MEM_FREE(EncKey);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	unsigned count_log2;

	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) != CIPHERTEXT_LENGTH)
		return 0;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	for (i = FORMAT_TAG_LEN; i < CIPHERTEXT_LENGTH; ++i)
		if (atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
	if (count_log2 < 7 || count_log2 > 31)
		return 0;

	return 1;
}

static void set_salt(void *salt)
{
	loopCnt = (1 << (atoi64[ARCH_INDEX(((char*)salt)[8])]));
	cursalt = salt;
}

static void set_key(char *key, int index)
{
	EncKeyLen[index] = strnzcpyn((char*)EncKey[index], key, sizeof(*EncKey));
}

static char *get_key(int index)
{
	return (char*)EncKey[index];
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index+=MAX_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_64
		unsigned char _IBuf[128*MAX_KEYS_PER_CRYPT+MEM_ALIGN_CACHE], *keys;
		uint64_t *keys64;
		unsigned i, j, len, Lcount = loopCnt;

		keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_CACHE);
		keys64 = (uint64_t*)keys;
		memset(keys, 0, 128*MAX_KEYS_PER_CRYPT);
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			len = EncKeyLen[index+i];
			for (j = 0; j < 8; ++j)
				keys[GETPOS(j, i)] = cursalt[j];
			for (j = 0; j < len; ++j)
				keys[GETPOS(j+8, i)] = EncKey[index+i][j];
			keys[GETPOS(j+8, i)] = 0x80;
			keys64[15*SIMD_COEF_64+(i&(SIMD_COEF_64-1))+i/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64] = (len+8) << 3;
		}
		SIMDSHA512body(keys, keys64, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			len = EncKeyLen[index+i];
			for (j = 0; j < len; ++j)
				keys[GETPOS(j+64, i)] = EncKey[index+i][j];
			keys[GETPOS(j+64, i)] = 0x80;
			keys64[15*SIMD_COEF_64+(i&(SIMD_COEF_64-1))+i/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64] = (len+64) << 3;
		}
		while (--Lcount)
			SIMDSHA512body(keys, keys64, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

		// Last one with FLAT_OUT
		SIMDSHA512body(keys, (uint64_t*)crypt_key[index], NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT|SSEi_FLAT_OUT);
#else
		SHA512_CTX ctx;
		unsigned char tmp[DIGEST_SIZE + PLAINTEXT_LENGTH];
		int len = EncKeyLen[index];
		unsigned Lcount = loopCnt - 1;

		SHA512_Init( &ctx );
		SHA512_Update( &ctx, cursalt, 8 );
		SHA512_Update( &ctx, EncKey[index], len );
		memcpy(&tmp[DIGEST_SIZE], (char *)EncKey[index], len);
		SHA512_Final( tmp, &ctx);
		len += DIGEST_SIZE;

		do {
			SHA512_Init( &ctx );
			SHA512_Update( &ctx, tmp, len);
			SHA512_Final( tmp, &ctx);
		} while (--Lcount);
		SHA512_Init( &ctx );
		SHA512_Update( &ctx, tmp, len);
		SHA512_Final( (unsigned char *) crypt_key[index], &ctx);
#endif
	}
	return count;
}

static void * get_binary(char *ciphertext)
{
	int i;
	unsigned sixbits;
	static union {
		unsigned char u8[BINARY_SIZE + 1];
		uint32_t u32;
	} out;
	int bidx=0;
	char *pos;

	pos = &ciphertext[FORMAT_TAG_LEN + 1 + 8];
	for (i = 0; i < 10; ++i) {
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out.u8[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out.u8[bidx++] |= (sixbits<<6);
		sixbits >>= 2;
		out.u8[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out.u8[bidx++] |= (sixbits<<4);
		sixbits >>= 4;
		out.u8[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out.u8[bidx++] |= (sixbits<<2);
	}
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	out.u8[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	out.u8[bidx++] |= (sixbits<<6);
	sixbits >>= 2;
	out.u8[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	out.u8[bidx++] |= (sixbits<<4);
	return out.u8;
}

static void * get_salt(char *ciphertext)
{
	static union {
		unsigned char u8[SALT_SIZE + 1];
		uint32_t u32;
	} salt;
	// store off the 'real' 8 bytes of salt
	memcpy(salt.u8, &ciphertext[FORMAT_TAG_LEN+1], 8);
	// append the 1 byte of loop count information.
	salt.u8[8] = ciphertext[FORMAT_TAG_LEN];
	return salt.u8;
}

#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	return *((uint32_t *)salt) & 0x3FF;
}

static unsigned int iteration_count(void *salt)
{
	return (unsigned int) 1 << (atoi64[ARCH_INDEX(((char*)salt)[8])]);
}
struct fmt_main fmt_drupal7 = {
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
		// true salt is SALT_SIZE but we add the loop count
		SALT_SIZE + 1,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
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
		{
			iteration_count,
		},
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

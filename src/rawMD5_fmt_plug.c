/*
 * Raw-MD5 (thick) based on Raw-MD4 w/ mmx/sse/intrinsics
 * This software is Copyright (c) 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * OMP added May 2013, JimF
 * BE SIMD logic added 2017, JimF
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawMD5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawMD5);
#else

#include <string.h>

#include "arch.h"
#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif
#ifdef _OPENMP
#include <omp.h>
#endif

#include "md5.h"
#include "common.h"
#include "johnswap.h"
#include "formats.h"
#include "base64_convert.h"
#define REVERSE_STEPS
#include "simd-intrinsics.h"

#ifndef OMP_SCALE
#define OMP_SCALE				16 // Tuned after MKPC for core i7 incl non-SIMD
#endif

#define FORMAT_LABEL			"Raw-MD5"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"MD5 " MD5_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_MD5)
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107
#ifndef MD5_BUF_SIZ
#define MD5_BUF_SIZ				16
#endif

#define CIPHERTEXT_LENGTH		32

#define DIGEST_SIZE				16
#define BINARY_SIZE				DIGEST_SIZE
#define BINARY_ALIGN			4
#define SALT_SIZE				0
#define SALT_ALIGN				1

#define FORMAT_TAG				"$dynamic_0$"
#define TAG_LENGTH				(sizeof(FORMAT_TAG) - 1)
#define FORMAT_TAG2				"{MD5}"
#define FORMAT_TAG2_LEN			(sizeof(FORMAT_TAG2) - 1)

static struct fmt_tests tests[] = {
	{"5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{FORMAT_TAG "5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{"098f6bcd4621d373cade4e832627b4f6", "test"},
	{"098F6BCD4621D373CADE4E832627B4F6", "test"},
	{FORMAT_TAG "378e2c4a07968da2eca692320136433d", "thatsworking"},
	{FORMAT_TAG "8ad8757baa8564dc136c1e07507f4a98", "test3"},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"c4ca4238a0b923820dcc509a6f75849b", "1"},
	{"c20ad4d76fe97759aa27a0c99bff6710", "12"},
	{"202cb962ac59075b964b07152d234b70", "123"},
	{"81dc9bdb52d04dc20036dbd8313ed055", "1234"},
	{"827ccb0eea8a706c4c34a16891f84e7b", "12345"},
#ifdef DEBUG
	{FORMAT_TAG "c9ccf168914a1bcfc3229f1948e67da0","1234567890123456789012345678901234567890123456789012345"},
#if PLAINTEXT_LENGTH >= 80
	{FORMAT_TAG "57edf4a22be3c955ac49da2e2107b67a","12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
#endif
	{"{MD5}CY9rzUYh03PK3k6DJie09g==", "test"},
	{NULL}
};

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH		55
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		(NBKEYS * 16)
#include "common-simd-getpos.h"
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		256
#endif

#ifdef SIMD_COEF_32
static uint32_t (*saved_key)[MD5_BUF_SIZ*NBKEYS];
static uint32_t (*crypt_key)[DIGEST_SIZE/4*NBKEYS];
#else
static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_key)[4];
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
#ifndef SIMD_COEF_32
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
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
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
#ifndef SIMD_COEF_32
	MEM_FREE(saved_len);
#endif
}

/* Convert {MD5}CY9rzUYh03PK3k6DJie09g== to 098f6bcd4621d373cade4e832627b4f6 */
static char *prepare(char *fields[10], struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	if (!strncmp(fields[1], FORMAT_TAG2, FORMAT_TAG2_LEN) && strlen(fields[1]) == FORMAT_TAG2_LEN+24) {
		int res;

		res = base64_convert(&fields[1][FORMAT_TAG2_LEN], e_b64_mime, 24,
		                     out, e_b64_hex, sizeof(out),
		                     flg_Base64_HEX_LOCASE, 0);
		if (res >= 0)
			return out;
	}

	return fields[1];
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (*p == '$' && !strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1] = FORMAT_TAG;

	if (ciphertext[0] == '$' &&
			!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpylwr(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);

	return out;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned long dummy;
		unsigned int i[DIGEST_SIZE/sizeof(unsigned int)];
	} _out;
	unsigned int *out = _out.i;
	unsigned int i;
	unsigned int temp;

	ciphertext += TAG_LENGTH;
	for (i=0; i<4; i++)
	{
		temp  = ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+0])]))<<4;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+1])]));

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+2])]))<<12;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+3])]))<<8;

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+4])]))<<20;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+5])]))<<16;

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+6])]))<<28;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+7])]))<<24;

#if ARCH_LITTLE_ENDIAN || defined(SIMD_COEF_32)
		out[i] = temp;
#else
		out[i] = JOHNSWAP(temp);
#endif
	}

#if defined(SIMD_COEF_32) && defined(REVERSE_STEPS)
	md5_reverse(out);
#endif

	return out;
}

static char *source(char *source, void *binary)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1] = FORMAT_TAG;
	uint32_t b[4];
	char *p;
	int i, j;

	memcpy(b, binary, sizeof(b));

#if SIMD_COEF_32 && defined(REVERSE_STEPS)
	md5_unreverse(b);
#endif

#if !ARCH_LITTLE_ENDIAN && !defined(SIMD_COEF_32)
	alter_endianity(b, 16);
#endif

	p = &out[TAG_LENGTH];
	for (i = 0; i < 4; i++)
		for (j = 0; j < 8; j++)
			*p++ = itoa16[(b[i] >> ((j ^ 1) * 4)) & 0xf];

	return out;
}

#define NON_SIMD_SET_SAVED_LEN
#include "common-simd-setkey32.h"

#ifndef REVERSE_STEPS
#undef SSEi_REVERSE_STEPS
#define SSEi_REVERSE_STEPS SSEi_NO_OP
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	int loops = (count + MIN_KEYS_PER_CRYPT - 1) / MIN_KEYS_PER_CRYPT;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < loops; index++) {
#if SIMD_COEF_32
		SIMDmd5body(saved_key[index], crypt_key[index], NULL, SSEi_REVERSE_STEPS | SSEi_MIXED_IN);
#else
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[index], saved_len[index]);
		MD5_Final((unsigned char *)crypt_key[index], &ctx);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x, y;
	const unsigned int c = (count + SIMD_COEF_32 - 1) / SIMD_COEF_32;
	for (y = 0; y < c; y++)
		for (x = 0; x < SIMD_COEF_32; x++)
		{
			if ( ((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[y*SIMD_COEF_32*4+x] )
				return 1;
		}
	return 0;
#else
	unsigned int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key[index], BINARY_SIZE))
			return 1;
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x = index&(SIMD_COEF_32-1);
	unsigned int y = (unsigned int)index/SIMD_COEF_32;

	return ((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[x+y*SIMD_COEF_32*4];
#else
	return !memcmp(binary, crypt_key[index], DIGEST_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
#ifdef SIMD_COEF_32
	uint32_t crypt_key[DIGEST_SIZE / 4];
	MD5_CTX ctx;
	char *key = get_key(index);

	MD5_Init(&ctx);
	MD5_Update(&ctx, key, strlen(key));
	MD5_Final((void*)crypt_key, &ctx);

#if !ARCH_LITTLE_ENDIAN
	alter_endianity(crypt_key, 16);
#endif
#if defined(REVERSE_STEPS)
	md5_reverse(crypt_key);
#endif
	return !memcmp(get_binary(source), crypt_key, DIGEST_SIZE);
#else
	return 1;
#endif
}

#define COMMON_GET_HASH_SIMD32 4
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

struct fmt_main fmt_rawMD5 = {
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG, FORMAT_TAG2 },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{ NULL },
		source,
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
		fmt_default_set_salt,
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

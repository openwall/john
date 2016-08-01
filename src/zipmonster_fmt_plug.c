/* This format is reverse engineered from InsidePro Hash Manager!
 *
 * This software is Copyright (c) 2016, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_zipmonster;
#elif FMT_REGISTERS_H
john_register_one(&fmt_zipmonster);
#else

#include "arch.h"
#include "sha.h"
#include "md5.h"
#include <string.h>
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "simd-intrinsics.h"

//#undef SIMD_COEF_32

#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL            "ZipMonster"
#define FORMAT_NAME             "MD5(ZipMonster)"
#define ALGORITHM_NAME          "MD5-" MD5_ALGORITHM_NAME " x 50000"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define SALT_SIZE               0
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#ifdef SIMD_COEF_32
#define MAX_KEYS_PER_CRYPT      (SIMD_PARA_MD5*SIMD_COEF_32)
#else
#define MAX_KEYS_PER_CRYPT      1
#endif
#define FORMAT_TAG              "$zipmonster$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

static struct fmt_tests zipmonster_tests[] = {
	{"$zipmonster$e0f68d6f40c5f157c169e9ca0a6f09fe", "!"},
	{"4dac447f100ee85327db2b47e295e50d", "1"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static unsigned short itoa16u_w[256];

#ifdef SIMD_COEF_32
#define GETPOS(i,index) ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#endif

static void init(struct fmt_main *self)
{
	int i;
	char buf[3];
#ifdef _OPENMP
	static int omp_t = 1;
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*crypt_out));
	for (i = 0; i < 256; ++i) {
		sprintf(buf, "%X%X", i>>4, i&0xF);
		memcpy(&(itoa16u_w[i]), buf, 2);
	}
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext;
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;

	if(!p)
		return 0;
	if (!ishexlc(p))
		return 0;

	if (strlen(p) != BINARY_SIZE * 2)
		return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p = ciphertext;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;
	for (i = 0; i < BINARY_SIZE && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static inline void hex_encode_uppercase(unsigned char *str, unsigned char *_out)
{
	int i;
	unsigned short *out = (unsigned short*)_out;

	for (i = 0; i < BINARY_SIZE; ++i) {
		out[i] = itoa16u_w[str[i]];
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
	int inc = 1;
#ifdef SIMD_COEF_32
	inc = SIMD_COEF_32*SIMD_PARA_MD5;
#endif

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += inc)
	{
		unsigned char buffer[BINARY_SIZE];
		MD5_CTX ctx;
		int n = 49999;
#ifdef SIMD_COEF_32
		int j, k;
		uint32_t *p, t;
		JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char md5[64*SIMD_COEF_32*SIMD_PARA_MD5];
		JTR_ALIGN(MEM_ALIGN_SIMD) uint32_t crypt_buf[4*SIMD_COEF_32*SIMD_PARA_MD5];
		memset(md5,0,sizeof(md5));

		for (j = 0; j < SIMD_COEF_32*SIMD_PARA_MD5; ++j) {
			uint16_t *op = (uint16_t*)&md5[GETPOS(0, j)];
			MD5_Init(&ctx);
			MD5_Update(&ctx, saved_key[index+j], strlen(saved_key[index+j]));
			MD5_Final(buffer, &ctx);

			for (k = 0; k < 16; ++k) {
				op[0] = itoa16u_w[buffer[k++]];
				op[1] = itoa16u_w[buffer[k]];
				op += ((SIMD_COEF_32) << 1);
			}
			md5[GETPOS(32,j)] = 0x80;
			md5[GETPOS(57,j)] = 1;
		}
#else
		unsigned char hex_buffer[BINARY_SIZE * 2];

		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		MD5_Final(buffer, &ctx);
		hex_encode_uppercase(buffer, hex_buffer);
#endif

		do {
#ifdef SIMD_COEF_32
			SIMDmd5body(md5, crypt_buf, NULL, SSEi_MIXED_IN);
			// upper case hex encode into the next input buffer.
			for (j = 0; j < SIMD_PARA_MD5*SIMD_COEF_32; ++j) {
				int i;
				uint16_t *op = (uint16_t*)&md5[GETPOS(0, j)];
				p = &crypt_buf[(j&(SIMD_COEF_32-1))+(4*SIMD_COEF_32*(j/SIMD_COEF_32))];
				for (i = 0; i < 4; ++i) {
					t = *p;
					p += SIMD_COEF_32;
					op[0] = itoa16u_w[t&0xFF];
					op[1] = itoa16u_w[(t>>8)&0xFF];
					t >>= 16;
					op += ((SIMD_COEF_32) << 1);
					op[0] = itoa16u_w[t&0xFF];
					op[1] = itoa16u_w[(t>>8)&0xFF];
					op += ((SIMD_COEF_32) << 1);
				}
			}
#else
			MD5_Init(&ctx);
			MD5_Update(&ctx, hex_buffer, BINARY_SIZE * 2);
			MD5_Final(buffer, &ctx);
			hex_encode_uppercase(buffer, hex_buffer);
#endif
			--n;
		} while (n);
#ifdef SIMD_COEF_32
		p = crypt_buf;
		for (j = 0; j < SIMD_PARA_MD5*SIMD_COEF_32; j+=SIMD_COEF_32) {
			for (k = 0; k < SIMD_COEF_32*4; ++k) {
				uint32_t J = j+(k&(SIMD_COEF_32-1)), K = (k/SIMD_COEF_32);
				crypt_out[index+J][K] = *p++;
			}
		}
#else
		memcpy((unsigned char*)crypt_out[index], buffer, BINARY_SIZE);
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
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
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

static void zipmonster_set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_zipmonster = {
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
		zipmonster_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
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
		fmt_default_set_salt,
		zipmonster_set_key,
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

/*
 * This format is reverse engineered from InsidePro Hash Manager!
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

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha.h"
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL            "ZipMonster"
#define FORMAT_NAME             "MD5(ZipMonster)"
#define ALGORITHM_NAME          "MD5-" MD5_ALGORITHM_NAME " x 50000"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define SALT_SIZE               0
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      (SIMD_PARA_MD5*SIMD_COEF_32)
#define MAX_KEYS_PER_CRYPT      (SIMD_PARA_MD5*SIMD_COEF_32)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      2
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
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
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
static unsigned short itoa16u_w[256];

#ifdef SIMD_COEF_32
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i,index) ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#else
#define GETPOS(i,index) ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#endif
#endif

static void init(struct fmt_main *self)
{
	int i;
	char buf[3];

	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*crypt_out));
	for (i = 0; i < 256; ++i) {
#if !ARCH_LITTLE_ENDIAN && defined(SIMD_COEF_32)
		sprintf(buf, "%X%X", i&0xF, i>>4);
#else
		sprintf(buf, "%X%X", i>>4, i&0xF);
#endif
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
	if (!p)
		return 0;
	if (!ishexlc(p))
		return 0;

	if (strlen(p) != BINARY_SIZE * 2)
		return 0;

	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + 2 * BINARY_SIZE + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	strcpy(out, FORMAT_TAG);
	strcpy(&out[TAG_LENGTH], ciphertext);

	return out;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p = ciphertext + TAG_LENGTH;
	int i;

	for (i = 0; i < BINARY_SIZE && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if defined(SIMD_COEF_32) && !ARCH_LITTLE_ENDIAN
	alter_endianity(out, BINARY_SIZE);
#endif
	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

#ifndef SIMD_COEF_32
inline static void hex_encode_uppercase(unsigned char *str, unsigned char *_out)
{
	int i;
	unsigned short *out = (unsigned short*)_out;

	for (i = 0; i < BINARY_SIZE; ++i) {
		out[i] = itoa16u_w[str[i]];
	}
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char buffer[BINARY_SIZE];
		MD5_CTX ctx;
		int n = 49999;
#ifdef SIMD_COEF_32
		int j, k;
		uint32_t *p, t;
		uint8_t ib[64 * SIMD_COEF_32 * SIMD_PARA_MD5 + MEM_ALIGN_SIMD];
		uint8_t ob[16 * SIMD_COEF_32 * SIMD_PARA_MD5 + MEM_ALIGN_SIMD];
		uint8_t *md5 = mem_align(ib, MEM_ALIGN_SIMD);
		uint32_t *crypt_buf = mem_align(ob, MEM_ALIGN_SIMD);

		memset(md5, 0, 64 * SIMD_COEF_32 * SIMD_PARA_MD5);

		for (j = 0; j < SIMD_COEF_32*SIMD_PARA_MD5; ++j) {
#if ARCH_LITTLE_ENDIAN==1
			uint16_t *op = (uint16_t*)&md5[GETPOS(0, j)];
#else
			uint16_t *op = (uint16_t*)&md5[GETPOS(3, j)];
#endif
			MD5_Init(&ctx);
			MD5_Update(&ctx, saved_key[index+j], strlen(saved_key[index+j]));
			MD5_Final(buffer, &ctx);

			for (k = 0; k < 16; ++k) {
#if ARCH_LITTLE_ENDIAN==1
				op[0] = itoa16u_w[buffer[k++]];
				op[1] = itoa16u_w[buffer[k]];
#else
				op[1] = itoa16u_w[buffer[k++]];
				op[0] = itoa16u_w[buffer[k]];
#endif
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
#if ARCH_LITTLE_ENDIAN==1
				uint16_t *op = (uint16_t*)&md5[GETPOS(0, j)];
#else
				uint16_t *op = (uint16_t*)&md5[GETPOS(3, j)];
#endif
				p = &crypt_buf[(j&(SIMD_COEF_32-1))+(4*SIMD_COEF_32*(j/SIMD_COEF_32))];
				for (i = 0; i < 4; ++i) {
					t = *p;
					p += SIMD_COEF_32;
#if ARCH_LITTLE_ENDIAN==1
					op[0] = itoa16u_w[t&0xFF];
					op[1] = itoa16u_w[(t>>8)&0xFF];
					t >>= 16;
					op += ((SIMD_COEF_32) << 1);
					op[0] = itoa16u_w[t&0xFF];
					op[1] = itoa16u_w[(t>>8)&0xFF];
#else
					op[1] = itoa16u_w[t&0xFF];
					op[0] = itoa16u_w[(t>>8)&0xFF];
					t >>= 16;
					op += ((SIMD_COEF_32) << 1);
					op[1] = itoa16u_w[t&0xFF];
					op[0] = itoa16u_w[(t>>8)&0xFF];
#endif
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
	int index;

	for (index = 0; index < count; index++)
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
		{ FORMAT_TAG },
#endif
		zipmonster_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
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
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

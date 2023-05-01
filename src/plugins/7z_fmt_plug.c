/*
 * 7-Zip cracker patch for JtR. Hacked together during June of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>. Unicode support and other fixes by magnum.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>
 * and Copyright (c) 2013-2020 magnum, and it is hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sevenzip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sevenzip);
#else

#include <string.h>

#include "arch.h"
#if !AC_BUILT && !__MIC__
#define HAVE_LIBZ 1 /* legacy build has -lz in LDFLAGS */
#endif
#if HAVE_LIBZ
#include <zlib.h>
#endif

#ifdef _OPENMP
#include <omp.h>
#endif
#include <fcntl.h>
#if !ARCH_LITTLE_ENDIAN
#undef SIMD_COEF_32
#undef SIMD_PARA_SHA256
#endif

#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "unicode.h"
#include "dyna_salt.h"
#include "config.h"
#include "john.h"
#include "crc32.h"
#include "simd-intrinsics.h"
#include "logger.h"

#define FORMAT_LABEL            "7z"

#ifdef SIMD_COEF_32

#define NBKEYS     (SIMD_COEF_32*SIMD_PARA_SHA256)
#define GETPOS(i,idx) ( (idx&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)idx/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 )
#define HASH_IDX_IN(idx)  (((unsigned int)idx&(SIMD_COEF_32-1))+(unsigned int)idx/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32)
#define HASH_IDX_OUT(idx) (((unsigned int)idx&(SIMD_COEF_32-1))+(unsigned int)idx/SIMD_COEF_32*8*SIMD_COEF_32)

#define ALGORITHM_NAME		"SHA256 " SHA256_ALGORITHM_NAME " AES"
#define PLAINTEXT_LENGTH	28
#define MIN_KEYS_PER_CRYPT	NBKEYS
#define MAX_KEYS_PER_CRYPT	NBKEYS
#else
#define ALGORITHM_NAME		"SHA256 32/" ARCH_BITS_STR " AES"
#define PLAINTEXT_LENGTH	125
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

#include "7z_common.h"

#ifndef OMP_SCALE
#define OMP_SCALE           1 // tuned w/ MKPC for core i7
#endif

static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int *cracked;
static int new_keys;
static int max_kpc;
static unsigned char (*master)[32];
#ifdef SIMD_COEF_32
static uint32_t (*vec_in)[2][NBKEYS*16];
static uint32_t (*vec_out)[NBKEYS*8];
static int *indices;
#endif

static void init(struct fmt_main *self)
{
	CRC32_t crc;

	omp_autotune(self, OMP_SCALE);

	// allocate 1 more slot to handle the tail of vector buffer
	max_kpc = self->params.max_keys_per_crypt + 1;

	saved_key = mem_calloc(max_kpc, sizeof(*saved_key));
	saved_len = mem_calloc(max_kpc, sizeof(*saved_len));
	cracked   = mem_calloc(max_kpc, sizeof(*cracked));
#ifdef SIMD_COEF_32
	vec_in  = mem_calloc_align(self->params.max_keys_per_crypt,
	                           sizeof(*vec_in), MEM_ALIGN_CACHE);
	vec_out = mem_calloc_align(self->params.max_keys_per_crypt,
	                           sizeof(*vec_out), MEM_ALIGN_CACHE);
#endif
	CRC32_Init(&crc);

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);

	if (cfg_get_bool(SECTION_FORMATS, "7z", "TrustPadding", 0))
		sevenzip_trust_padding = 1;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(master);
#ifdef SIMD_COEF_32
	MEM_FREE(vec_in);
	MEM_FREE(vec_out);
	MEM_FREE(indices);
#endif
}

static void set_salt(void *salt)
{
	static int old_power, old_size;

	sevenzip_salt = *((sevenzip_salt_t**)salt);

	if (sevenzip_salt->SaltSize || old_size || old_power != sevenzip_salt->NumCyclesPower) {
		new_keys = 1;
		old_power = sevenzip_salt->NumCyclesPower;
		old_size = sevenzip_salt->SaltSize;
	}
}

#ifdef SIMD_COEF_32
static void sevenzip_kdf(int buf_idx, int *indices, unsigned char *master)
{
	int i, j;
	long long round, rounds = (long long) 1 << sevenzip_salt->NumCyclesPower;
	uint32_t (*buf_in)[NBKEYS*16] = vec_in[buf_idx];
	uint32_t *buf_out = vec_out[buf_idx];
	int pw_len = saved_len[indices[0]];
	int tot_len = (pw_len + 8)*rounds;
	int acc_len = 0;
#if !ARCH_LITTLE_ENDIAN
	unsigned char temp[8] = { 0,0,0,0,0,0,0,0 };
#endif

	int cur_buf = 0;
	int fst_blk = 1;

	// it's assumed rounds is divisible by 64
	for (round = 0; round < rounds; ++round) {
		// copy password to vector buffer
		for (i = 0; i < NBKEYS; ++i) {
			UTF16 *buf = saved_key[indices[i]];
			for (j = 0; j < pw_len; ++j) {
				int len = acc_len + j;
				char *in = (char*)buf_in[(len & 64)>>6];
				in[GETPOS(len%64, i)] = ((char*)buf)[j];
			}

			for (j = 0; j < 8; ++j) {
				int len = acc_len + pw_len + j;
				char *in = (char*)buf_in[(len & 64)>>6];
#if ARCH_LITTLE_ENDIAN
				in[GETPOS(len%64, i)] = ((char*)&round)[j];
#else
				in[GETPOS(len%64, i)] = temp[j];
#endif
			}
		}
#if !ARCH_LITTLE_ENDIAN
		for (j = 0; j < 8; j++)
			if (++(temp[j]) != 0)
				break;
#endif
		acc_len += (pw_len + 8);

		// swap out and compute digest on the filled buffer
		if ((acc_len & 64) != (cur_buf << 6)) {
			if (fst_blk)
				SIMDSHA256body(buf_in[cur_buf], buf_out, NULL, SSEi_MIXED_IN);
			else
				SIMDSHA256body(buf_in[cur_buf], buf_out, buf_out, SSEi_MIXED_IN | SSEi_RELOAD);
			fst_blk = 0;
			cur_buf = 1 - cur_buf;
		}
	}

	// padding
	memset(buf_in[0], 0, sizeof(buf_in[0]));
	for (i = 0; i < NBKEYS; ++i) {
		buf_in[0][HASH_IDX_IN(i)] = (0x80U << 24);
		buf_in[0][HASH_IDX_IN(i) + 15*SIMD_COEF_32] = tot_len*8;
	}
	SIMDSHA256body(buf_in[0], buf_out, buf_out, SSEi_MIXED_IN | SSEi_RELOAD);

	// copy out result
	for (i = 0; i < NBKEYS; ++i) {
		uint32_t *m = (uint32_t*)&master[i*32];
		for (j = 0; j < 32/4; ++j)
			m[j] = JOHNSWAP(buf_out[HASH_IDX_OUT(i) + j*SIMD_COEF_32]);
	}
}
#else
static void sevenzip_kdf(int index, unsigned char *master)
{
	long long rounds = (long long) 1 << sevenzip_salt->NumCyclesPower;
	long long round;
#if !ARCH_LITTLE_ENDIAN
	int i;
	unsigned char temp[8] = { 0,0,0,0,0,0,0,0 };
#endif
	SHA256_CTX sha;

	/* kdf */
	SHA256_Init(&sha);
	for (round = 0; round < rounds; round++) {
		if (sevenzip_salt->SaltSize)
			SHA256_Update(&sha, sevenzip_salt->salt, sevenzip_salt->SaltSize);
		SHA256_Update(&sha, (char*)saved_key[index], saved_len[index]);
#if ARCH_LITTLE_ENDIAN
		SHA256_Update(&sha, (char*)&round, 8);
#else
		SHA256_Update(&sha, temp, 8);
		for (i = 0; i < 8; i++)
			if (++(temp[i]) != 0)
				break;
#endif
	}
	SHA256_Final(master, &sha);
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef SIMD_COEF_32
	static int tot_todo;
	int len;

	/* Tricky formula, see GitHub #1692 :-) */
	if (!indices)
		indices = mem_alloc((max_kpc + MIN(PLAINTEXT_LENGTH + 1, max_kpc) *
		                     (NBKEYS - 1)) * sizeof(int));
	if (!master)
		master =  mem_alloc((max_kpc + MIN(PLAINTEXT_LENGTH + 1, max_kpc) *
		                     (NBKEYS - 1)) * sizeof(*master));
#else
	if (!master)
		master =  mem_alloc(max_kpc * sizeof(*master));
#endif

#ifdef SIMD_COEF_32
	if (new_keys) {
		// sort passwords by length
		tot_todo = 0;
		for (len = 0; len <= PLAINTEXT_LENGTH*2; len += 2) {
			for (index = 0; index < count; ++index) {
				if (saved_len[index] == len)
					indices[tot_todo++] = index;
			}
			while (tot_todo % NBKEYS)
				indices[tot_todo++] = count;
		}
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < tot_todo; index += NBKEYS) {
		int j;

		if (new_keys)
			sevenzip_kdf(index/NBKEYS, indices + index, master[index]);

		/* do decryption and checks */
		for (j = 0; j < NBKEYS; ++j) {
			cracked[indices[index + j]] = sevenzip_decrypt(master[index + j]);
		}
	}
#else
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		/* derive key */
		if (new_keys)
			sevenzip_kdf(index, master[index]);

		/* do decryption and checks */
		cracked[index] = sevenzip_decrypt(master[index]);
	}
#endif // SIMD_COEF_32
	new_keys = 0;

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	/* Convert key to utf-16-le format (--encoding aware) */
	int len;
	len = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));

	if (len <= 0)
		len = strlen16(saved_key[index]);
	len *= 2;
	saved_len[index] = len;

	new_keys = 1;
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
}

struct fmt_main fmt_sevenzip = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_ENC | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"iteration count",
			"padding size",
			"compression type",
			"data length"
		},
		{ FORMAT_TAG },
		sevenzip_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		sevenzip_valid,
		fmt_default_split,
		fmt_default_binary,
		sevenzip_get_salt,
		{
			sevenzip_iteration_count,
			sevenzip_padding_size,
			sevenzip_compression_type,
			sevenzip_data_len
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		sevenzip_salt_compare,
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
		cmp_exact
	}
};

#endif /* plugin stanza */

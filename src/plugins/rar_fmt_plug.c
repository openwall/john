/* RAR 3.x cracker patch for JtR. Hacked together during
 * April of 2011 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 * magnum added -p mode support, using code based on libclamav
 * and OMP, AES-NI and OpenCL support.
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012-2020, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This code is based on the work of Alexander L. Roshal (C)
 *
 * The unRAR sources may be used in any software to handle RAR
 * archives without limitations free of charge, but cannot be used
 * to re-create the RAR compression algorithm, which is proprietary.
 * Distribution of modified unRAR sources in separate form or as a
 * part of other software is permitted, provided that it is clearly
 * stated in the documentation and source comments that the code may
 * not be used to develop a RAR (WinRAR) compatible archiver.
 *
 * Huge thanks to Marc Bevand <m.bevand (at) gmail.com> for releasing unrarhp
 * (http://www.zorinaq.com/unrarhp/) and documenting the RAR encryption scheme.
 * This patch is made possible by unrarhp's documentation.
 *
 * http://anrieff.net/ucbench/technical_qna.html is another useful reference
 * for RAR encryption scheme.
 *
 * Thanks also to Pavel Semjanov for crucial help with Huffman table checks.
 *
 * For type = 0 for files encrypted with "rar -hp ..." option
 * archive_name:$RAR3$*type*hex(salt)*hex(partial-file-contents):type::::archive_name
 *
 * For type = 1 for files encrypted with "rar -p ..." option
 * archive_name:$RAR3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*archive_name*offset-for-ciphertext*method:type::file_name
 *
 * or (inlined binary)
 *
 * archive_name:$RAR3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*1*hex(full encrypted file)*method:type::file_name
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#include "arch.h"

#if ARCH_ALLOWS_UNALIGNED || __ARM_FEATURE_UNALIGNED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rar;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rar);
#else

#include <string.h>

#include "sha.h"
#include "crc32.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "memory.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "johnswap.h"
#include "unrar.h"
#include "config.h"
#include "jumbo.h"

#define FORMAT_LABEL		"rar"
#define FORMAT_NAME		"RAR3"

/*
 * This format's speed is *highly* dependant on pw length (longer = slower)
 *
 * cRARk use 4-char passwords for CPU benchmark, but we use 5.
 */
#define BENCHMARK_COMMENT	" (length 5)"
#define BENCHMARK_LENGTH	0x105

#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)

#ifdef SIMD_COEF_32
#include "simd-intrinsics.h"
#define NBKEYS (SIMD_COEF_32*SIMD_PARA_SHA1)
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i,idx) ( (idx&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)idx/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 )
#else
#define GETPOS(i,idx) ( (idx&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)idx/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 )
#endif
#define HASH_IDX(idx) (((unsigned int)idx&(SIMD_COEF_32-1))+(unsigned int)idx/SIMD_COEF_32*5*SIMD_COEF_32)

#define ALGORITHM_NAME		"SHA1 " SHA1_ALGORITHM_NAME " AES"
#define PLAINTEXT_LENGTH    26
#define MIN_KEYS_PER_CRYPT  NBKEYS
#define MAX_KEYS_PER_CRYPT  NBKEYS
#else
#define ALGORITHM_NAME		"SHA1 AES 32/" ARCH_BITS_STR
/* NOTE for implementing support for lengths past 28 (56 bytes of UTF-16), see issue #4296 */
#define PLAINTEXT_LENGTH	28 //125
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

#define ROUNDS			0x40000

#ifdef _MSC_VER
#undef _OPENMP
#endif

#ifdef _OPENMP
#include <omp.h>
#endif

#include "rar_common.c"

// these are supposed to be stack arrays; however gcc cannot correctly align
// stack arrays so we have to use global arrays; we may switch back to stack
// arrays (which take less space) when gcc fixes this issue
#ifdef SIMD_COEF_32
static uint8_t  (*vec_in)[2][NBKEYS*64];
static uint32_t (*vec_out)[NBKEYS*5];
static uint8_t  (*tmp_in)[NBKEYS*64];
static uint32_t (*tmp_out)[NBKEYS*5];
#endif

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	threads = omp_get_max_threads();
	self->params.min_keys_per_crypt *= threads;
	self->params.max_keys_per_crypt *= threads;
#endif /* _OPENMP */

	// Length is a cost. We sort in buckets but we need them to be mostly full
	self->params.max_keys_per_crypt *= PLAINTEXT_LENGTH;

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);

	unpack_data = mem_calloc(threads, sizeof(unpack_data_t));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));
	// allocate 1 more slot to handle the tail of vector buffer
	saved_key = mem_calloc(self->params.max_keys_per_crypt + 1,
	                       UNICODE_LENGTH);
	saved_len = mem_calloc(self->params.max_keys_per_crypt + 1,
	                       sizeof(*saved_len));
	if (!saved_salt)
		saved_salt = mem_calloc(8, 1);
	aes_key = mem_calloc(self->params.max_keys_per_crypt + 1, 16);
	aes_iv = mem_calloc(self->params.max_keys_per_crypt + 1, 16);

#ifdef SIMD_COEF_32
	vec_in  = mem_calloc_align(self->params.max_keys_per_crypt,
	                           sizeof(*vec_in), MEM_ALIGN_CACHE);
	vec_out = mem_calloc_align(self->params.max_keys_per_crypt,
	                           sizeof(*vec_out), MEM_ALIGN_CACHE);
	tmp_in  = mem_calloc_align(self->params.max_keys_per_crypt,
	                           sizeof(*tmp_in), MEM_ALIGN_CACHE);
	tmp_out = mem_calloc_align(self->params.max_keys_per_crypt,
	                           sizeof(*tmp_out), MEM_ALIGN_CACHE);
#endif

#ifdef DEBUG
	self->params.benchmark_comment = " (1-16 characters)";
#endif

	/* CRC-32 table init, do it before we start multithreading */
	{
		CRC32_t crc;
		CRC32_Init(&crc);
	}
}

static void done(void)
{
	MEM_FREE(aes_iv);
	MEM_FREE(aes_key);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
	MEM_FREE(cracked);
	MEM_FREE(unpack_data);
	MEM_FREE(saved_salt);
#ifdef SIMD_COEF_32
	MEM_FREE(vec_in);
	MEM_FREE(vec_out);
	MEM_FREE(tmp_in);
	MEM_FREE(tmp_out);
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef SIMD_COEF_32
	int len;
	int *indices;
	int tot_todo = 0;

	/* Tricky formula, see GitHub #1692 :-) */
	indices = mem_calloc(count + MIN(PLAINTEXT_LENGTH + 1, count) *
	                     (NBKEYS - 1), sizeof(*indices));

	// sort passwords by length
	for (len = 0; len <= PLAINTEXT_LENGTH*2; len += 2) {
		for (index = 0; index < count; ++index) {
			if (saved_len[index] == len)
				indices[tot_todo++] = index;
		}
		while (tot_todo % NBKEYS)
			indices[tot_todo++] = count;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < tot_todo; index += NBKEYS) {
		unsigned int i, j, k;
		uint8_t (*RawPsw)[NBKEYS*64] = vec_in[index/NBKEYS];
		uint32_t *digest = vec_out[index/NBKEYS];
		// all passwords in one batch has the same length
		int pw_len = saved_len[indices[index]];
		int RawLength = pw_len + 8 + 3;
		int cur_len = 0;
		int fst_blk = 1;
		int cur_buf = 0;
		unsigned char tmp1 = 0, tmp2 = 0;

		for (i = 0; i < ROUNDS; ++i) {
			// copy passwords to vector buffer
			for (j = 0; j < NBKEYS; ++j) {
				int idx = indices[index + j];
				int len = cur_len;
				for (k = 0; k < pw_len; ++k) {
					RawPsw[(len & 64)>>6][GETPOS(len%64, j)] =
						saved_key[UNICODE_LENGTH*idx + k];
					len++;
				}
				for (k = 0; k < 8; ++k) {
					RawPsw[(len & 64)>>6][GETPOS(len%64, j)] = saved_salt[k];
					len++;
				}

				RawPsw[(len & 64)>>6][GETPOS(len%64, j)] = (unsigned char)i;
				len++;
				if ( ((unsigned char) i) == 0) {
					tmp1 = (unsigned char)(i >> 8);
					tmp2 = (unsigned char)(i >> 16);
				}
				RawPsw[(len & 64)>>6][GETPOS(len%64, j)] = tmp1;
				len++;
				RawPsw[(len & 64)>>6][GETPOS(len%64, j)] = tmp2;
			}
			cur_len += RawLength;

			if (i % (ROUNDS / 16) == 0) {
				uint8_t *tempin = tmp_in[index/NBKEYS];
				uint32_t *tempout = tmp_out[index/NBKEYS];
				memcpy(tempin, RawPsw[cur_buf], NBKEYS*64);
				for (j = 0; j < NBKEYS; ++j) { // padding
					uint32_t *tail;
					for (k = RawLength; k < 64; ++k)
						tempin[GETPOS(k, j)] = 0;
					tempin[GETPOS(RawLength, j)] = 0x80;
#if ARCH_LITTLE_ENDIAN==1
					tail = (uint32_t*)&tempin[GETPOS(64 - 1, j)];
#else
					tail = (uint32_t*)&tempin[GETPOS(64 - 1 - 3, j)];
#endif
					*tail = cur_len*8;
				}
				if (i == 0)
					SIMDSHA1body(tempin, tempout, NULL, SSEi_MIXED_IN);
				else
					SIMDSHA1body(tempin, tempout, digest,
					             SSEi_MIXED_IN | SSEi_RELOAD);
				for (j = 0; j < NBKEYS; ++j) {
					int idx = indices[index + j];
					aes_iv[idx*16 + i/(ROUNDS/16)] =
						(uint8_t)tempout[HASH_IDX(j) + 4*SIMD_COEF_32];
				}
			}
			// swap out and compute digests on the filled buffer
			if ((cur_len & 64) != (cur_buf << 6)) {
				if (fst_blk)
					SIMDSHA1body(RawPsw[cur_buf], digest, NULL, SSEi_MIXED_IN);
				else
					SIMDSHA1body(RawPsw[cur_buf], digest, digest,
					             SSEi_MIXED_IN | SSEi_RELOAD);
				fst_blk = 0;
				cur_buf = 1 - cur_buf;
			}
		}
		// padding
		memset(RawPsw[0], 0, sizeof(RawPsw[0]));
		for (j = 0; j < NBKEYS; ++j) {
			uint32_t *tail;
			RawPsw[0][GETPOS(0, j)] = 0x80;
#if ARCH_LITTLE_ENDIAN==1
			tail =  (uint32_t*)&RawPsw[0][GETPOS(64 - 1, j)];
#else
			tail =  (uint32_t*)&RawPsw[0][GETPOS(64 - 1 - 3, j)];
#endif

			*tail = cur_len*8;
		}
		SIMDSHA1body(RawPsw[0], digest, digest, SSEi_MIXED_IN | SSEi_RELOAD);

		for (j = 0; j < NBKEYS; ++j) {
			for (i = 0; i < 4; ++i) {
				int idx = indices[index + j];
				uint32_t *dst = (uint32_t*)&aes_key[idx*16];
#if ARCH_LITTLE_ENDIAN==1
				dst[i] = digest[HASH_IDX(j) + i*SIMD_COEF_32];
#else
				dst[i] = JOHNSWAP(digest[HASH_IDX(j) + i*SIMD_COEF_32]);
#endif
			}
		}
	}
	MEM_FREE(indices);
#else
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		int i16 = index*16;
		unsigned int i;
		unsigned char RawPsw[UNICODE_LENGTH + 8 + 3];
		int RawLength;
		SHA_CTX ctx, tempctx;
		unsigned int digest[5];
		unsigned char *PswNum, tempout[20];

		RawLength = saved_len[index] + 8 + 3;
		PswNum = (unsigned char*) &RawPsw[saved_len[index] + 8];
		PswNum[1] = PswNum[2] = 0;
		/* derive IV and key for AES from saved_key and
		   saved_salt, this code block is based on unrarhp's
		   and unrar's sources */
		memcpy(RawPsw, &saved_key[UNICODE_LENGTH * index], saved_len[index]);
		memcpy(RawPsw + saved_len[index], saved_salt, 8);
		SHA1_Init(&ctx);
		for (i = 0; i < ROUNDS; i++) {
			PswNum[0] = (unsigned char) i;
			if ( ((unsigned char) i) == 0) {
				PswNum[1] = (unsigned char) (i >> 8);
				PswNum[2] = (unsigned char) (i >> 16);
			}
			SHA1_Update(&ctx, RawPsw, RawLength);
			if (i % (ROUNDS / 16) == 0) {
				tempctx = ctx;
				SHA1_Final(tempout, &tempctx);
				aes_iv[i16 + i / (ROUNDS / 16)] = tempout[19];
			}
		}
		SHA1_Final((unsigned char*)digest, &ctx);
		for (i = 0; i < 4; i++)	/* reverse byte order */
			digest[i] = JOHNSWAP(digest[i]);
		memcpy(&aes_key[i16], (unsigned char*)digest, 16);
	}
#endif

	return count;
}

inline static void check_all_rar(rar_file *cur_file, int count)
{
	unsigned int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
		check_rar(cur_file, index, &aes_key[index * 16], &aes_iv[index * 16]);
}

static int cmp_all(void *binary, int count)
{
	fmt_data *blob = binary;
	rar_file *cur_file = blob->blob;
	int index;

	check_all_rar(cur_file, count);

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

struct fmt_main fmt_rar = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_OMP | FMT_BLOB | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		cpu_tests
	},{
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
			fmt_default_binary_hash
		},
		salt_hash,
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
		cmp_exact
	}
};
#endif /* plugin stanza */

#else
#if !defined(FMT_EXTERNS_H) && !defined(FMT_REGISTERS_H)
#ifdef __GNUC__
#warning ": target system requires aligned memory access, rar format disabled:"
#elif _MSC_VER
#pragma message(": target system requires aligned memory access, rar format disabled:")
#endif
#endif

#endif	/* ARCH_ALLOWS_UNALIGNED || __ARM_FEATURE_UNALIGNED */

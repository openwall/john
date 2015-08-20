/* RAR 3.x cracker patch for JtR. Hacked together during
 * April of 2011 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 * magnum added -p mode support, using code based on libclamav
 * and OMP, AES-NI and OpenCL support.
 * jimf added dyna_salt support, Oct 2014.
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum and it is hereby released to the general public
 * under the following terms:
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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rar;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rar);
#else

#include <string.h>
#include <errno.h>
#if AC_BUILT
#include "autoconfig.h"
#endif
#if _MSC_VER || __MINGW32__ || __MINGW64__ || __CYGWIN__ || HAVE_WINDOWS_H
#include "win32_memmap.h"
#if !defined(__CYGWIN__) && !defined(__MINGW64__)
#include "mmap-windows.c"
#elif defined HAVE_MMAP
#include <sys/mman.h>
#endif
#elif defined(HAVE_MMAP)
#include <sys/mman.h>
#endif

#include "arch.h"
#include "sha.h"
#include "crc32.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "dyna_salt.h"
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
#define ALGORITHM_NAME		"SHA1 AES 32/" ARCH_BITS_STR

#ifdef DEBUG
#define BENCHMARK_COMMENT	" (1-16 characters)"
#else
#define BENCHMARK_COMMENT	" (4 characters)"
#endif
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	125
#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define BINARY_SIZE		0
#define BINARY_ALIGN		MEM_ALIGN_NONE
#define SALT_SIZE		sizeof(rarfile*)
#define SALT_ALIGN		sizeof(rarfile*)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define ROUNDS			0x40000

/* The reason we want to bump OMP_SCALE in this case is to even out the
   difference in processing time for different length keys. It doesn't
   boost performance in other ways */
#ifdef _MSC_VER
#undef _OPENMP
#endif

#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE		4
#endif
#endif

#include "rar_common.c"
#include "memdbg.h"

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	self->params.max_keys_per_crypt = omp_t * OMP_SCALE * MAX_KEYS_PER_CRYPT;
#endif /* _OPENMP */

	if (pers_opts.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);

	unpack_data = mem_calloc(omp_t, sizeof(unpack_data_t));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       UNICODE_LENGTH);
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	if (!saved_salt)
		saved_salt = mem_calloc(8, 1);
	aes_key = mem_calloc(self->params.max_keys_per_crypt, 16);
	aes_iv = mem_calloc(self->params.max_keys_per_crypt, 16);

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
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

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

	check_rar(count);
	return count;
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP | FMT_DYNA_SALT,
		{ NULL },
		cpu_tests
	},{
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
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

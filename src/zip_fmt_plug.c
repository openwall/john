/*
 * ZIP cracker patch for JtR. Hacked together during June of 2011
 * by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Copyright (c) 2021, magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_zip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_zip);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "crc32.h"
#include "misc.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "memory.h"
#include "pkzip.h"
#include "pbkdf2_hmac_sha1.h"
#include "dyna_salt.h"
#include "hmac_sha.h"

#define KEY_LENGTH(mode)        (8 * ((mode) & 3) + 8)
#define SALT_LENGTH(mode)       (4 * ((mode) & 3) + 4)

#define BLK_SZ                  SHA_DIGEST_LENGTH

#define FORMAT_LABEL        "ZIP"
#define FORMAT_NAME         "WinZip"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME      "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME      "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif
#define PLAINTEXT_LENGTH    125
#define BINARY_ALIGN        sizeof(uint32_t)
#define SALT_SIZE           sizeof(winzip_salt*)
#define SALT_ALIGN          sizeof(winzip_salt*)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT  (SSE_GROUP_SZ_SHA1 * 8)
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  8
#endif

#ifndef OMP_SCALE
#define OMP_SCALE           32	// Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*crypt_key)[((WINZIP_BINARY_SIZE+3)/4)*4];
static winzip_salt *saved_salt;


//    filename:$zip2$*Ty*Mo*Ma*Sa*Va*Le*DF*Au*$/zip2$
//    Ty = type (0) and ignored.
//    Mo = mode (1 2 3 for 128/192/256 bit
//    Ma = magic (file magic).  This is reserved for now.  See pkzip_fmt_plug.c or zip2john.c for information.
//         For now, this must be a '0'
//    Sa = salt(hex).   8, 12 or 16 bytes of salt (depends on mode)
//    Va = Verification bytes(hex) (2 byte quick checker)
//    Le = real compr len (hex) length of compressed/encrypted data (field DF)
//    DF = compressed data DF can be L*2 hex bytes, and if so, then it is the ENTIRE file blob written 'inline'.
//         However, if the data blob is too long, then a .zip ZIPDATA_FILE_PTR_RECORD structure will be the 'contents' of DF
//    Au = Authentication code (hex) a 10 byte hex value that is the hmac-sha1 of data over D. This is the binary() value

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	saved_salt = *((winzip_salt**)salt);
}

static void set_key(char *key, int index)
{
	strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;
	const int key_len = KEY_LENGTH(saved_salt->v.mode);
	const int early_skip = 2 * key_len / BLK_SZ * BLK_SZ;
	const int late_skip = key_len / BLK_SZ * BLK_SZ;
	const int late_size = early_skip - late_skip;

#ifdef _OPENMP
/*
 * Some versions of gcc can't live with const stuff like key_len being in the shared list,
 * while other versions demand they do.  WAT!
 */
#pragma omp parallel for /*default(none) private(index) shared(count, saved_key, saved_salt, crypt_key)*/
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		unsigned char pwd_ver[MIN_KEYS_PER_CRYPT][3 * BLK_SZ];
		int i, lens[MIN_KEYS_PER_CRYPT];
		int something_hit = 0, hits[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[i + index]);
			pin[i] = (unsigned char*)saved_key[i + index];
			pout[i] = pwd_ver[i] + early_skip - late_skip;
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens, saved_salt->salt, SALT_LENGTH(saved_salt->v.mode),
		                KEYING_ITERATIONS, pout, BLK_SZ, early_skip);
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			if (!memcmp(pwd_ver[i] + 2 * key_len - late_skip, saved_salt->passverify, 2))
				something_hit = hits[i] = 1;
		if (something_hit) {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
				pout[i] = pwd_ver[i];
			pbkdf2_sha1_sse((const unsigned char **)pin, lens, saved_salt->salt, SALT_LENGTH(saved_salt->v.mode),
			                KEYING_ITERATIONS, pout, late_size, late_skip);
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				if (hits[i]) {
					hmac_sha1(pwd_ver[i] + key_len - late_skip, key_len,
					          (const unsigned char*)saved_salt->datablob, saved_salt->comp_len,
					          crypt_key[index+i], WINZIP_BINARY_SIZE);
				}
				else
					memset(crypt_key[index + i], 0, WINZIP_BINARY_SIZE);
			}
		} else {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
				memset(crypt_key[index + i], 0, WINZIP_BINARY_SIZE);
		}
#else
		unsigned char pwd_ver[3 * BLK_SZ];

		/* Get the block that contains the two-byte verifier */
		pbkdf2_sha1((unsigned char *)saved_key[index], strlen(saved_key[index]),
		            saved_salt->salt, SALT_LENGTH(saved_salt->v.mode), KEYING_ITERATIONS,
		            pwd_ver + early_skip - late_skip, BLK_SZ, early_skip);

		/* Early-rejection */
		if (!memcmp(pwd_ver + 2 * key_len - late_skip, saved_salt->passverify, 2)) {

			/* Get the remaining block(s) needed for the HMAC */
			pbkdf2_sha1((unsigned char *)saved_key[index], strlen(saved_key[index]),
			            saved_salt->salt, SALT_LENGTH(saved_salt->v.mode), KEYING_ITERATIONS,
			            pwd_ver, late_size, late_skip);

			hmac_sha1(pwd_ver + key_len - late_skip, key_len,
			          (const unsigned char*)saved_salt->datablob, saved_salt->comp_len,
			          crypt_key[index], WINZIP_BINARY_SIZE);
		}
		else
			memset(crypt_key[index], 0, WINZIP_BINARY_SIZE);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (((uint32_t*)&(crypt_key[i]))[0] == ((uint32_t*)binary)[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(crypt_key[index], binary, WINZIP_BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static unsigned int cost_hmac_len(void *salt)
{
	winzip_salt *s = *((winzip_salt**)salt);

	return s->comp_len;
}

struct fmt_main fmt_zip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		WINZIP_BENCHMARK_COMMENT,
		WINZIP_BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		WINZIP_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"HMAC size"
		},
		{ WINZIP_FORMAT_TAG },
		winzip_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		winzip_common_valid,
		winzip_common_split,
		winzip_common_binary,
		winzip_common_get_salt,
		{
			cost_hmac_len
		},
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

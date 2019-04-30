/*
 * EncFS cracker patch for JtR. Hacked together during July of 2012
 * by Dhiru Kholia <dhiru at openwall.com>
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_encfs;
#elif FMT_REGISTERS_H
john_register_one(&fmt_encfs);
#else

#include <stdint.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "options.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "misc.h"
#include "johnswap.h"
#include "encfs_common.h"
#include "pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL        "EncFS"
#define FORMAT_NAME         ""
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME      "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME " AES"
#else
#define ALGORITHM_NAME      "PBKDF2-SHA1 AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x507
#define BINARY_SIZE         0
#define PLAINTEXT_LENGTH    125
#define BINARY_ALIGN        MEM_ALIGN_NONE
#define SALT_SIZE           sizeof(*cur_salt)
#define SALT_ALIGN          sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE           1 // tuned w/ MKPC on core i7
#endif

#define KEY_CHECKSUM_BYTES  4

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;


static encfs_common_custom_salt *cur_salt;

static struct fmt_tests encfs_tests[] = {
	{"$encfs$192*181474*0*20*f1c413d9a20f7fdbc068c5a41524137a6e3fb231*44*9c0d4e2b990fac0fd78d62c3d2661272efa7d6c1744ee836a702a11525958f5f557b7a973aaad2fd14387b4f", "openwall"},
	{"$encfs$128*181317*0*20*e9a6d328b4c75293d07b093e8ec9846d04e22798*36*b9e83adb462ac8904695a60de2f3e6d57018ccac2227251d3f8fc6a8dd0cd7178ce7dc3f", "Jupiter"},
	{"$encfs$256*714949*0*20*472a967d35760775baca6aefd1278f026c0e520b*52*ac3b7ee4f774b4db17336058186ab78d209504f8a58a4272b5ebb25e868a50eaf73bcbc5e3ffd50846071c882feebf87b5a231b6", "Valient Gough"},
	{"$encfs$256*120918*0*20*e6eb9a85ee1c348bc2b507b07680f4f220caa763*52*9f75473ade3887bca7a7bb113fbc518ffffba631326a19c1e7823b4564ae5c0d1e4c7e4aec66d16924fa4c341cd52903cc75eec4", "Alo3San1t@nats"},
	// EncFS 1.7.4 running on Ubuntu 14.04.5 LTS
	{"$encfs$256*1441549*0*20*17ebe5f12d0aacd4b01dcbdc7be3c493c574b1d0*52*753146f6a9098c445242b1f49dc66beece6b2a2c335b975d8ff2b69d2448bf160ba116fbcc1c6d3fa71ecc90624aac6f0bcaac2e", "openwall"},
	{NULL}
};

static void init(struct fmt_main *self)
{
    omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(sizeof(*saved_key), self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_align(sizeof(*cracked), self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (encfs_common_custom_salt *) salt;
}

static void encfs_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		int i, j;
		unsigned char master[MIN_KEYS_PER_CRYPT][MAX_KEYLENGTH + MAX_IVLENGTH];
		unsigned char tmpBuf[sizeof(cur_salt->data)];
		unsigned int checksum = 0;
		unsigned int checksum2 = 0;
		unsigned char out[MIN_KEYS_PER_CRYPT][MAX_KEYLENGTH + MAX_IVLENGTH];

#ifdef SIMD_COEF_32
		int len[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			len[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = out[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, len, cur_salt->salt, cur_salt->saltLen, cur_salt->iterations, pout, cur_salt->keySize + cur_salt->ivLength, 0);
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			memcpy(master[i], out[i], cur_salt->keySize + cur_salt->ivLength);
#else
		pbkdf2_sha1((const unsigned char *)saved_key[index], strlen(saved_key[index]), cur_salt->salt, cur_salt->saltLen, cur_salt->iterations, out[0], cur_salt->keySize + cur_salt->ivLength, 0);
		memcpy(master[0], out[0], cur_salt->keySize + cur_salt->ivLength);
#endif
		for (j = 0; j < MIN_KEYS_PER_CRYPT; ++j) {
			// First N bytes are checksum bytes.
			for (i=0; i<KEY_CHECKSUM_BYTES; ++i)
				checksum = (checksum << 8) | (unsigned int)cur_salt->data[i];
			memcpy( tmpBuf, cur_salt->data+KEY_CHECKSUM_BYTES, cur_salt->keySize + cur_salt->ivLength );
			encfs_common_streamDecode(cur_salt, tmpBuf, cur_salt->keySize + cur_salt->ivLength ,checksum, master[j]);
			checksum2 = encfs_common_MAC_32(cur_salt, tmpBuf,  cur_salt->keySize + cur_salt->ivLength, master[j]);
			if (checksum2 == checksum) {
				cracked[index+j] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

struct fmt_main fmt_encfs = {
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
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		encfs_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		encfs_common_valid,
		fmt_default_split,
		fmt_default_binary,
		encfs_common_get_salt,
		{
			encfs_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		encfs_set_key,
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

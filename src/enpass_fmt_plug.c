/*
 * JtR format to crack Enpass Password Manager databases.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_enpass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_enpass);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               4 // this is a slow format, so 4 should be enough
#endif
#endif

#include "aes.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "enpass_common.h"
#include "pbkdf2_hmac_sha1.h"
#include "memdbg.h"

#define FORMAT_LABEL         "enpass"
#define FORMAT_NAME          "Enpass Password Manager"
#define FORMAT_TAG           "$enpass$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME       "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME       "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     -1
#define BINARY_SIZE          0
#define PLAINTEXT_LENGTH     125
#define SALT_SIZE            sizeof(struct custom_salt)
#define BINARY_ALIGN         1
#define SALT_ALIGN           sizeof(unsigned int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT   SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT   SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1
#endif

#define FILE_HEADER_SZ       16
#define SQLITE_FILE_HEADER   "SQLite format 3"
#define SQLITE_MAX_PAGE_SIZE 65536

static struct fmt_tests enpass_tests[] = {
	{"$enpass$0$24000$700dfb6d83ae3b4b87935ed8246123363656de4273979a1365197a632c6b1ce68ca801d0bb50d93c9a0509fbb061bba2ad579ed0d48ee781508c853b9bd042d3275cc92781770a211ecd08a254db873e50664a14b394d63e3e443a82d69c7df84c592a60b5b620e241c9675f097f931093f6ebf67f56e5db0d82eb61ff9da3636bf7c79598e6ee1f34b7abd2b1e5e3ae9e9a219de50d9c079fb7fb21910139468619c6ac562a4157c0e8e85df08b54aff33ec2005e2214549ba04d794882051e8e245f63f822d469c6588ccd38c02154f21cdfd06acd5ed1b97cbe7e23648ce70c471560222cd8927b0567cd0a3c317b7a8add994dc8fcda89ae4afc33c1260192e3c8c3ca9d50347a91a82025c1cb127aede8334286cc26f86591d34483b90d86d1e1372f74d1b7eee5aa233ed9199a3de01e7d16b092b4c902a602a16edcf03005596abc5c24f249dbb48236dc27738e93949c383734f6e39bf199fcd3fd22ab9268d1678d7259f94ab2c012e924ff2d26772ebf2cccc0ffe795264cd7a035f52f258b5ce78b7f1353c120f1aa30cbe943832fa70d3762222365109521c1a70a7ace321ddda173fb731c1d6f65c8e4af8f7b62660bc70a2c9ece21f8cddbe65d047f92aa6ca55a90864cb12c757030a7755ec4601a6f28dc2e728ee3f84fc1d39c261c845335a9d19e3356192b257186ff606756e58df67c11d2886870c90b69f5b51630f72d79f51884528214e9987865debb6b23ce8deecfb67cd43450a73675b53fcd20b6ae1da13f69dd349045d0b9b7dded042020ad081143231c79778d01f91c6e6df823885860ea781dd07867222b438599d02a815a4c18409c5e97a3d8e870ce1401bce7c556f05ac77af2659ef9b13d0d4df32a54674ef451cc2ffef50d4ca31efe19644db389ae9f0ce97686e5e53f1d82b98136258708911641b3a251eea41e6433534eb2810df49e040901367ee42b12cf7f853bab46f5360da2429989d232c9f6897e44221a2a5e946563db10423cfb073b6abf1e977f746e1d9c0fb929bb0e2c9dd50c11c76e0219a0004aa747de0db075305d4582293727f16f215403a9ca3d99af1750343101162954daebd58358b21276346519b2c05942223ad8314073900169b222b0e24f79c76dc61b4701edba670bc07bd4fa3c5a2179c69560f23ed925594f3ca230ed780904e82c7f8f6ee737c059d1af79eef0c1f8e6a0fdace62e87d88ad3b345afb96ea7b26eb0426585ea064933c8b8ec9264d910dc1573363dbec0755de36221eb368c5b2703c254a4d3d29d1b247c46200f743fe5f04f4b8fec2f143ba1276cc4b2bd7802bfe6fa63a49eb7a77f3443db74e0c889441fc2154d85bdbc0bbdc80eca3852ff8c7d7738ff9ba9eaa18174f4f65c526940289717bb87d05fd4eeef1272065b4bfa4d6f31a1b23c50e1355988", "openwall"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_autotune(self, OMP_SCALE);
#endif
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
		unsigned char master[MAX_KEYS_PER_CRYPT][32];
		unsigned char output[24];
		unsigned char *iv_in;
		unsigned char iv_out[16];
		int size, i;
		AES_KEY akey;

#ifdef SIMD_COEF_32
		int len[MAX_KEYS_PER_CRYPT];
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			len[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, len, cur_salt->salt, 16, cur_salt->iterations, pout, 32, 0);
#else
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
			pbkdf2_sha1((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]),
				cur_salt->salt, 16, cur_salt->iterations, master[i], 32, 0);
#endif
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			// memcpy(output, SQLITE_FILE_HEADER, FILE_HEADER_SZ);
			// See "sqlcipher_page_cipher" and "sqlite3Codec" functions
			size = page_sz - reserve_sz;
			iv_in = cur_salt->data + 16 + size;  // initial 16 bytes are salt
			memcpy(iv_out, iv_in, 16);
			AES_set_decrypt_key(master[i], 256, &akey);
			/*
			 * decrypting 8 bytes from offset 16 is enough since the
			 * verify_page function looks at output[16..23] only.
			 */
			AES_cbc_encrypt(cur_salt->data + 16, output + 16, 8, &akey, iv_out, AES_DECRYPT);
			if (enpass_common_verify_page(output) == 0)
				cracked[index+i] = 1;
			else
				cracked[index+i] = 0;
		}
	}

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

static void enpass_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_enpass = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		enpass_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		enpass_common_valid,
		fmt_default_split,
		fmt_default_binary,
		enpass_common_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		enpass_set_key,
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

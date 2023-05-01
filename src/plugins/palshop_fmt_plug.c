/* This format is reverse engineered from InsidePro Hash Manager!
 *
 * This software is Copyright (c) 2016, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * improved speed, JimF.  Reduced amount of hex encoding.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_palshop;
#elif FMT_REGISTERS_H
john_register_one(&fmt_palshop);
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
#include "base64_convert.h"

#define FORMAT_LABEL            "Palshop"
#define FORMAT_NAME             "MD5(Palshop)"
#define ALGORITHM_NAME          "MD5 + SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             10  /* 20 characters of "m2", now 10 binary bytes. */
#define CIPHERTEXT_LENGTH       51
#define SALT_SIZE               0
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#define FORMAT_TAG              "$palshop$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifndef OMP_SCALE
#define OMP_SCALE               256
#endif

static struct fmt_tests palshop_tests[] = {
	{"$palshop$68b11ee90ed17ef14aa0f51af494c2c63ad7d281a9888cb593e", "123"},
	{"ea3a8d0f4cd9e5e22ccede1ad59dd2c5c7e839348a8a519d505", "ABC"},
	// http://leopard.500mb.net/HashGenerator/
	{"$palshop$f2e3babc50b316e6e886f3062a37cead6d1bd16dd2bed49f7bc", "long password"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[ (BINARY_SIZE+sizeof(uint32_t)-1) / sizeof(uint32_t)];
static size_t *saved_len;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*crypt_out));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_len));
}

static void done(void)
{
	MEM_FREE(saved_len);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext;
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;

	if (!p)
		return 0;
	if (!ishexlc(p+1))
		return 0;
	if ( !((*p >= '0' && *p<= '9') || (*p >= 'a' && *p<= 'f') ) ) // first byte (was skipped in the hexlc call.
		return 0;

	if (strlen(p) != CIPHERTEXT_LENGTH)
		return 0;

	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

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

	++p; // skip the first 'nibble'.  Take next 10 bytes.
	base64_convert(p, e_b64_hex, 20, out, e_b64_raw, 10, 0, 0);

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char m1[53], buffer[16+20], *cp;
		int i;
		MD5_CTX mctx;
		SHA_CTX sctx;

		// m1 = md5($p)
		MD5_Init(&mctx);
		MD5_Update(&mctx, saved_key[index], saved_len[index]);
		MD5_Final(buffer, &mctx);

		// s1 = sha1($p)
		SHA1_Init(&sctx);
		SHA1_Update(&sctx, saved_key[index], saved_len[index]);
		SHA1_Final(buffer+16, &sctx);

		// data = m1[11:] + s1[:29] + m1[0:1]  // 51 bytes!
		cp = m1;
		*cp++ = itoa16[buffer[5]&0xF];
		for (i = 6; i < 25+6; ++i) {
			cp[0] = itoa16[buffer[i]>>4];
			cp[1] = itoa16[buffer[i]&0xF];
			cp += 2;
		}
		cp[-1] = itoa16[buffer[0]>>4];


		// m2
		MD5_Init(&mctx);
		MD5_Update(&mctx, m1, 51);
		MD5_Final(buffer, &mctx);

		// s2 = sha1(data)
		// SHA1_Init(&sctx);
		// SHA1_Update(&sctx, data, 51);
		// SHA1_Final((unsigned char*)crypt_out[index], &sctx);
		// hex_encode((unsigned char*)crypt_out[index], 20, s1);

		// hash =  m2[11:] + s2[:29] + m2[0], but starting 20 bytes should be enough!
		//memcpy((unsigned char*)crypt_out[index], m2 + 11, 20);

		// we actually take m2[12:32] (skipping that first 'odd' byte.0
		// in binary now, skipping the unneeded hex conversion.
		memcpy((unsigned char*)crypt_out[index], buffer+6, 10);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*((uint32_t*)binary) == crypt_out[index][0])
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

static void palshop_set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_palshop = {
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
		{ FORMAT_TAG },
		palshop_tests
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
		palshop_set_key,
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

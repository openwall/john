/*
 * Copyright (c) 2007 Marti Raudsepp <marti AT juffo org>
 *
 * Simple MySQL 4.1+ PASSWORD() hash cracker, rev 1.
 * Adapted from the original rawSHA1_fmt.c cracker.
 *
 * Note that many version 4.1 and 5.0 installations still use the old
 * homebrewn pre-4.1 hash for compatibility with older clients, notably all
 * Red Hat-based distributions.
 *
 * The new PASSWORD() function is unsalted and equivalent to
 * SHA1(SHA1(password)) where the inner is a binary digest (not hex!) This
 * means that with the SSE2-boosted SHA-1 implementation, it will be several
 * times faster than John's cracker for the old hash format. (though the old
 * hash had significant weaknesses, some of which are exploited with John's
 * format "mysql-fast")
 *
 * It's a slight improvement over the old hash, but still not something a
 * reasonable DBMS would use for password storage.
 *
 * Use of SSE2 intrinsics: Copyright magnum 2012 and hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted.
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_mysqlSHA1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_mysqlSHA1);
#else

#include <string.h>

#include "arch.h"

#ifdef SIMD_COEF_32
#define NBKEYS	(SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif
#include "simd-intrinsics.h"

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"

#define FORMAT_LABEL			"mysql-sha1"
#define FORMAT_NAME			"MySQL 4.1+"

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		41

#define BINARY_SIZE			20
#define BINARY_ALIGN			MEM_ALIGN_WORD
#define SALT_SIZE			0
#define SALT_ALIGN			MEM_ALIGN_NONE

#ifdef SIMD_COEF_32

#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define FMT_IS_BE
#include "common-simd-getpos.h"

#else

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#endif

static struct fmt_tests tests[] = {
	{"*5AD8F88516BD021DD43F171E2C785C69F8E54ADB", "tere"},
	{"*2c905879f74f28f8570989947d06a8429fb943e6", "verysecretpassword"},
	{"*A8A397146B1A5F8C8CF26404668EFD762A1B7B82", "________________________________"},
	{"*F9F1470004E888963FB466A5452C9CBD9DF6239C", "12345678123456781234567812345678"},
	{"*97CF7A3ACBE0CA58D5391AC8377B5D9AC11D46D9", "' OR 1 /*'"},
	{"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "password"},
	{"*7534F9EAEE5B69A586D1E9C1ACE3E3F9F6FCC446", "5"},
	{"*be1bdec0aa74b4dcb079943e70528096cca985f8", ""},
	{"*0D3CED9BEC10A777AEC23CCC353A8C08A633045E", "abc"},
	{"*18E70DF2758EE4C0BD954910E5808A686BC38C6A", "VAwJsrUcrchdG9"},
	{"*440F91919FD39C01A9BC5EDB6E1FE626D2BFBA2F", "lMUXgJFc2rNnn"},
	{"*171A78FB2E228A08B74A70FE7401C807B234D6C9", "TkUDsVJC"},
	{"*F7D70FD3341C2D268E98119ED2799185F9106F5C", "tVDZsHSG"},
	{NULL}
};

#ifdef SIMD_COEF_32
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key mysqlSHA1_saved_key
#define crypt_key mysqlSHA1_crypt_key
#define interm_key mysqlSHA1_interm_key

JTR_ALIGN(MEM_ALIGN_SIMD) char saved_key[SHA_BUF_SIZ*4*NBKEYS];
JTR_ALIGN(MEM_ALIGN_SIMD) char crypt_key[BINARY_SIZE*NBKEYS];
JTR_ALIGN(MEM_ALIGN_SIMD) char interm_key[SHA_BUF_SIZ*4*NBKEYS];

#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static uint32_t crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;

	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) != CIPHERTEXT_LENGTH) return 0;
	if (ciphertext[0] != '*')
		return 0;
	for (i = 1; i < CIPHERTEXT_LENGTH; i++) {
		if (!( (('0' <= ciphertext[i])&&(ciphertext[i] <= '9'))
		       || (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		       || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
		{
			return 0;
		}
	}
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, sizeof(out));
	strupr(out);
	return out;
}

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_32
	int i;

	/* input strings have to be terminated by 0x80. The input strings in
	 * interm_key have a static length (20 bytes) so we can set them just
	 * once. If intrinsics, we do the same for the length byte.
	 */
	for (i = 0; i < NBKEYS; i++) {
		interm_key[GETPOS(20,i)] = 0x80;
		((unsigned int *)interm_key)[15*SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = 20 << 3;
	}
#endif
}

#define NON_SIMD_SINGLE_SAVED_KEY
#include "common-simd-setkey32.h"

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x, y;

	for (y = 0; y < SIMD_PARA_SHA1; y++) {
		for (x = 0; x < SIMD_COEF_32; x++) {
			if ( ((unsigned int*)binary)[0] ==
					((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5] )
				return 1;
		}
	}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int cmp_one(void * binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;

	if ( ((unsigned int*)binary)[0] != ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5] )
		return 0;
	if ( ((unsigned int*)binary)[1] != ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32*1] )
		return 0;
	if ( ((unsigned int*)binary)[2] != ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32*2] )
		return 0;
	if ( ((unsigned int*)binary)[3] != ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32*3] )
		return 0;
	if ( ((unsigned int*)binary)[4] != ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32*4] )
		return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#ifdef SIMD_COEF_32
	unsigned int i;

	SIMDSHA1body(saved_key, (unsigned int *)crypt_key, NULL, SSEi_MIXED_IN);

	for (i = 0; i < SIMD_PARA_SHA1; i++)
		memcpy(&interm_key[i*SHA_BUF_SIZ*4*SIMD_COEF_32],
		       &crypt_key[i*BINARY_SIZE*SIMD_COEF_32],
		       SIMD_COEF_32*BINARY_SIZE);

	SIMDSHA1body(interm_key, (unsigned int *)crypt_key, NULL, SSEi_MIXED_IN);
#else
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (unsigned char *) saved_key, strlen(saved_key));
	SHA1_Final((unsigned char *) crypt_key, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (unsigned char *) crypt_key, BINARY_SIZE);
	SHA1_Final((unsigned char *) crypt_key, &ctx);
#endif
	return count;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *realcipher;
	int i;

	if (!realcipher)
		realcipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	// ignore first character '*'
	ciphertext += 1;
	for (i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN==1
	alter_endianity((unsigned char *)realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

#define COMMON_GET_HASH_SIMD32 5
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

struct fmt_main fmt_mysqlSHA1 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{ NULL },
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

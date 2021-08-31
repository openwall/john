/*
 * Copyright (c) 2008 Alexandre Hamelin
 * alexandre.hamelin(@)gmail.com
 * Based on saltSHA1 format source.
 *
 * Intrinsics use: Copyright magnum 2012 and hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted.
 *
 * Oracle 11g SHA1 cracker
 *
 * Please note that a much better way to crack Oracle 11g passwords exists than
 * brute forcing the SHA1 hash since the pre-Oracle 10g hash is still stored in
 * the SYS.USER$ table in the column PASSWORD.
 *
 * $ uname -a
 * Linux xyz 2.6.22-hardened-r8 #1 SMP Fri Jan 11 23:24:31 EST 2008 x86_64 AMD Athlon(tm) 64 X2 Dual Core Processor 5200+ AuthenticAMD GNU/Linux
 * $ ./john --test
 * [...]
 * Benchmarking: Oracle 11g [oracle11]... DONE
 * Many salts:     2387K c/s real, 2507K c/s virtual
 * Only one salt:  2275K c/s real, 2275K c/s virtual
 * [...]
 *
 * To use:
 *  1. Connect as a DBA to Oracle 11g with sqlplus
 *  2. set heading off
 *     set feedback off
 *     set pagesize 1000
 *     set linesize 100
 *     spool ora11-passwds.txt
 *  3. SELECT name || ':' || SUBSTR(spare4,3)
 *     FROM sys.user$
 *     WHERE spare4 IS NOT NULL
 *     ORDER BY name;
 *  4. spool off
 *     quit
 *  5. Remove extra spaces (%s:/\s\+$//) and extra lines (:g!/:\w/d) in output.
 *  6. ./john [-f:oracle11] ora11-passwds.txt
 *
 * TODO:
 * The prefix "S:" suggests that other hashing functions might be used to store
 * user passwords; if this is indeed possible (I've not verified in the docs
 * yet) maybe implement other 11g cracking functions in the same oracle11_fmt.c
 * file.
 * Change the hash format for JtR? Prefix with "O11$" or "S:" ? (but "S:" might
 * not be possible due to the way JtR parses password files)
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_oracle11;
#elif FMT_REGISTERS_H
john_register_one(&fmt_oracle11);
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
#include "unicode.h"
#include "sha.h"
#include "johnswap.h"
#include <ctype.h>

#define FORMAT_LABEL			"oracle11"
#define FORMAT_NAME			"Oracle 11g"
#define FORMAT_TAG			"$oracle11$"
#define FORMAT_TAG_LENGTH		(sizeof(FORMAT_TAG) - 1)

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

/* Maximum length of password in characters. Oracle supports identifiers of 30
 * characters max. (ALTER USER user IDENTIFIED BY 30lettersPassword) */
#define PLAINTEXT_LENGTH		30
/* Length in characters of the cipher text, as seen in the password file.
 * Excludes prefix if any. */
#define CIPHERTEXT_LENGTH		60

/* Length of hashed value without the salt, in bytes. */
#define BINARY_SIZE			20
#define BINARY_ALIGN			4
/* Length of salt in bytes. */
#define SALT_SIZE			10
#define SALT_ALIGN			4

/* Sanity check. Don't change. */
#if (BINARY_SIZE + SALT_SIZE) * 2 != CIPHERTEXT_LENGTH
#error Incorrect binary sizes or cipher text length.
#endif

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define FMT_IS_BE
#include "common-simd-getpos.h"
#define GETPOS_WORD(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 +               (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests tests[] = {
	/* 160 bits of SHA1, followed by 80 bits of salt. No "S:" prefix. */
	{"5FDAB69F543563582BA57894FE1C1361FB8ED57B903603F2C52ED1B4D642", "abc123"},
	{"450F957ECBE075D2FA009BA822A9E28709FBC3DA82B44D284DDABEC14C42", "SyStEm123!@#"},
	{"3437FF72BD69E3FB4D10C750B92B8FB90B155E26227B9AB62D94F54E5951", "oracle"},
	{"61CE616647A4F7980AFD7C7245261AF25E0AFE9C9763FCF0D54DA667D4E6", "11g"},
	{"B9E7556F53500C8C78A58F50F24439D79962DE68117654B6700CE7CC71CF", "11g"},

	/* with FORMAT_TAG */
	{"$oracle11$7233E3B91B45F6B813BCFFB5D8669167CB4F498D0642558A8A3BB39948C0", "testpwd"},
	{"$oracle11$f013fe236e70f5b47e933d84eac5ef2b1ab6e8b2b90bd9536750cad2998c", "TOTO1234#"},

	{NULL}
};

static unsigned char *saved_salt;

#ifdef SIMD_COEF_32

static unsigned char *saved_key;
static unsigned char *crypt_key;
static int *saved_len;
#else

static char saved_key[PLAINTEXT_LENGTH + 1];
static int saved_len;
static SHA_CTX ctx;
static uint32_t crypt_key[BINARY_SIZE / 4];

#endif

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_32
	unsigned int i;

	saved_key = mem_calloc_align(SHA_BUF_SIZ * 4, NBKEYS, MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(BINARY_SIZE, NBKEYS, MEM_ALIGN_SIMD);
	saved_len = mem_calloc(sizeof(int), NBKEYS);
	/* Set lengths to SALT_LEN to avoid strange things in crypt_all()
	   if called without setting all keys (in benchmarking). Unset
	   keys would otherwise get a length of -10 and a salt appended
	   at pos 4294967286... */
	for (i=0; i < NBKEYS; i++)
		((unsigned int *)saved_key)[15*SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = 10 << 3;
#endif
	saved_salt = mem_calloc(1, SALT_SIZE);
}

static void done(void)
{
	MEM_FREE(saved_salt);
#ifdef SIMD_COEF_32
	MEM_FREE(saved_len);
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext;

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		p += FORMAT_TAG_LENGTH;

	if (strlen(p) != CIPHERTEXT_LENGTH)
		return 0;

	if (!ishex(p))
		return 0;

	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[FORMAT_TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		snprintf(out, sizeof(out), "%s", ciphertext);
	else
		snprintf(out, sizeof(out), "%s%s", FORMAT_TAG, ciphertext);

	strupr(out + FORMAT_TAG_LENGTH);

	return out;
}

static void *get_salt(char *ciphertext)
{
	static unsigned char *salt;
	char *p = ciphertext;
	int i;

	if (!salt) salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	if (!memcmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		p += FORMAT_TAG_LENGTH;

	p += 2 * BINARY_SIZE;
	for (i = 0; i < SALT_SIZE; i++) {
		salt[i] = atoi16[ARCH_INDEX(p[i*2+0])]*16 +
			atoi16[ARCH_INDEX(p[i*2+1])];
	}

	return (void *)salt;
}

static void set_salt(void *salt)
{
	memcpy(saved_salt, salt, SALT_SIZE);
}

static void clear_keys(void)
{
#ifdef SIMD_COEF_32
	unsigned int i;
	memset(saved_key, 0, SHA_BUF_SIZ * 4 * NBKEYS);
	/* Set lengths to SALT_LEN to avoid strange things in crypt_all()
	   if called without setting all keys (in benchmarking). Unset
	   keys would otherwise get a length of -10 and a salt appended
	   at pos 4294967286... */
	for (i=0; i < NBKEYS; i++)
		((unsigned int *)saved_key)[15*SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = 10 << 3;
#endif
}

#define SALT_APPENDED SALT_SIZE
#define NON_SIMD_SINGLE_SAVED_KEY
#define NON_SIMD_SET_SAVED_LEN
#include "common-simd-setkey32.h"

static int cmp_all(void *binary, int count)
{
#ifdef SIMD_COEF_32
	unsigned int x, y;

	for (y = 0; y < SIMD_PARA_SHA1; y++) {
		for (x = 0; x < SIMD_COEF_32; x++) {
			if ( ((unsigned int *)binary)[0] == ((unsigned int *)crypt_key)[x+y*SIMD_COEF_32*5] )
				return 1;
		}
	}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_one(void * binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;

	if ( (((unsigned int *)binary)[0] != ((unsigned int *)crypt_key)[x+y*SIMD_COEF_32*5])   |
	    (((unsigned int *)binary)[1] != ((unsigned int *)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32]) |
	    (((unsigned int *)binary)[2] != ((unsigned int *)crypt_key)[x+y*SIMD_COEF_32*5+2*SIMD_COEF_32]) |
	    (((unsigned int *)binary)[3] != ((unsigned int *)crypt_key)[x+y*SIMD_COEF_32*5+3*SIMD_COEF_32])|
	    (((unsigned int *)binary)[4] != ((unsigned int *)crypt_key)[x+y*SIMD_COEF_32*5+4*SIMD_COEF_32]) )
		return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#ifdef SIMD_COEF_32
	unsigned int index;

	for (index = 0; index < count; ++index)
	{
		unsigned int len = ((((unsigned int *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32]) >> 3) - SALT_SIZE;
		unsigned int i = 0;

		// 1. Copy a byte at a time until we're aligned in buffer
		// 2. Copy a whole word, or two!
		// 3. Copy the stray bytes
#if !ARCH_ALLOWS_UNALIGNED || !ARCH_LITTLE_ENDIAN
		for ( ; i < SALT_SIZE; ++i)
			saved_key[GETPOS(i+len, index)] = saved_salt[i];
#else
		switch (len & 3)
		{
		case 0:
			*(uint32_t*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(uint32_t*)&saved_salt[i]);
			i += 4;
			*(uint32_t*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(uint32_t*)&saved_salt[i]);
			i += 4;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			break;
		case 1:
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			*(uint32_t*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(uint32_t*)&saved_salt[i]);
			i += 4;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			break;
		case 2:
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			*(uint32_t*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(uint32_t*)&saved_salt[i]);
			i += 4;
			*(uint32_t*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(uint32_t*)&saved_salt[i]);
			break;
		case 3:
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			*(uint32_t*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(uint32_t*)&saved_salt[i]);
			i += 4;
			*(uint32_t*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(uint32_t*)&saved_salt[i]);
			i += 4;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			break;
		}
#endif
	}
	SIMDSHA1body(saved_key, (unsigned int *)crypt_key, NULL, SSEi_MIXED_IN);
#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, saved_len );
	SHA1_Update( &ctx, saved_salt, SALT_SIZE );
	SHA1_Final( (unsigned char *)crypt_key, &ctx);

#endif
	return count;
}

static void * get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		long dummy;
	} realcipher;

	char *p = ciphertext;
	int i;

	if (!memcmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		p += FORMAT_TAG_LENGTH;

	for (i=0;i<BINARY_SIZE;i++)
		realcipher.c[i] = atoi16[ARCH_INDEX(p[i*2])]*16 +
						atoi16[ARCH_INDEX(p[i*2+1])];

#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN==1
	alter_endianity((unsigned char *)realcipher.c, BINARY_SIZE);
#endif
	return (void *)realcipher.c;
}

#define COMMON_GET_HASH_SIMD32 5
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	return *(uint32_t*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_oracle11 = {
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
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
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
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		clear_keys,
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

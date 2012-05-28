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

#include <string.h>

#include "arch.h"

#ifdef SHA1_SSE_PARA
#define MMX_COEF	4
#include "sse-intrinsics.h"
#define NBKEYS	(MMX_COEF * SHA1_SSE_PARA)
#elif MMX_COEF
#define NBKEYS	MMX_COEF
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"
#include <ctype.h>

#define FORMAT_LABEL			"oracle11"
#define FORMAT_NAME			"Oracle 11g"

#ifdef SHA1_N_STR
#define ALGORITHM_NAME			"SSE2i " SHA1_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define ALGORITHM_NAME			"SSE2 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define ALGORITHM_NAME			"MMX 2x"
#elif defined(MMX_COEF)
#define ALGORITHM_NAME			"?"
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

/* Maximum length of password in characters. Oracle supports identifiers of 30
 * characters max. (ALTER USER user IDENTIFIED BY 30lettersPassword) */
#define PLAINTEXT_LENGTH		30
/* Length in characters of the cipher text, as seen in the password file.
 * Excludes prefix if any. */
#define CIPHERTEXT_LENGTH		60

/* Length of hashed value without the salt, in bytes. */
#define BINARY_SIZE			20
/* Length of salt in bytes. */
#define SALT_SIZE			10

/* Sanity check. Don't change. */
#if (BINARY_SIZE + SALT_SIZE) * 2 != CIPHERTEXT_LENGTH
#error Incorrect binary sizes or cipher text length.
#endif

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 ) //for endianity conversion
#define GETPOS_WORD(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF +               (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4)
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
	{NULL}
};

static unsigned char saved_salt[SALT_SIZE];

#ifdef MMX_COEF

/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key oracle11_saved_key
#define crypt_key oracle11_crypt_key
#ifdef _MSC_VER
__declspec(align(16)) unsigned char saved_key[SHA_BUF_SIZ*4*NBKEYS];
__declspec(align(16)) unsigned char crypt_key[BINARY_SIZE*NBKEYS];
#else
unsigned char saved_key[SHA_BUF_SIZ*4*NBKEYS] __attribute__ ((aligned(16)));
unsigned char crypt_key[BINARY_SIZE*NBKEYS] __attribute__ ((aligned(16)));
#endif

#else

static char saved_key[PLAINTEXT_LENGTH + 1];
static int saved_key_length;
static SHA_CTX ctx;
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];

#endif

static void init(struct fmt_main *pFmt)
{
#ifdef MMX_COEF
	int i;
	/* Set lengths to SALT_LEN to avoid strange things in crypt_all()
	   if called without setting all keys (in benchmarking). Unset
	   keys would otherwise get a length of -10 and a salt appended
	   at pos 4294967286... */
	for (i=0; i < NBKEYS; i++)
		((unsigned int *)saved_key)[15*MMX_COEF + (i&3) + (i>>2)*SHA_BUF_SIZ*MMX_COEF] = 10 << 3;
#endif
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;

	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;
	return !ciphertext[i];
}

static void *salt(char *ciphertext)
{
	static unsigned char *salt;
	int i;

	if (!salt) salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	for (i = 0; i < SALT_SIZE; i++) {
		salt[i] = atoi16[ARCH_INDEX(ciphertext[BINARY_SIZE*2+i*2+0])]*16 +
			atoi16[ARCH_INDEX(ciphertext[BINARY_SIZE*2+i*2+1])];
	}

	return (void *)salt;
}

static void set_salt(void *salt)
{
	memcpy(saved_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
	ARCH_WORD_32 *keybuf_word = (unsigned int*)&saved_key[GETPOS_WORD(0, index)];
	unsigned int len;

	len = SALT_SIZE;
	while((*keybuf_word = JOHNSWAP(*wkey++)) & 0xff000000) {
		if (!(*keybuf_word & 0xff0000))
		{
			len++;
			goto key_cleaning;
		}
		if (!(*keybuf_word & 0xff00))
		{
			len+=2;
			goto key_cleaning;
		}
		if (!(*keybuf_word & 0xff))
		{
			len+=3;
			goto key_cleaning;
		}
		len += 4;
		keybuf_word += MMX_COEF;
	}

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}
	saved_key[GETPOS(len, index)] = 0x80;
	((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] = len << 3;
#else
	saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);
	saved_key[saved_key_length] = 0;
#endif
}

static char *get_key(int index)
{
#ifdef MMX_COEF
	unsigned int i,s;
	static char out[PLAINTEXT_LENGTH + 1];

	s = (((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] >> 3) - SALT_SIZE;

	for(i = 0; i < s; i++)
		out[i] = ((char*)saved_key)[ GETPOS(i, index) ];
	out[i] = 0;

	return (char *) out;
#else
	saved_key[saved_key_length] = 0;
	return saved_key;
#endif
}

static int cmp_all(void *binary, int index) {
#ifdef MMX_COEF
	unsigned int x,y=0;

#ifdef SHA1_SSE_PARA
	for(;y<SHA1_SSE_PARA;y++)
#endif
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((unsigned int *)binary)[0] == ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int count) {
	return 1;
}

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	unsigned int x,y;
	x = index&(MMX_COEF-1);
	y = index>>(MMX_COEF>>1);

	if( (((unsigned int *)binary)[0] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5])   |
	    (((unsigned int *)binary)[1] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+MMX_COEF]) |
	    (((unsigned int *)binary)[2] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+2*MMX_COEF]) |
	    (((unsigned int *)binary)[3] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+3*MMX_COEF])|
	    (((unsigned int *)binary)[4] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+4*MMX_COEF]) )
		return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}

static void crypt_all(int count) {
#ifdef MMX_COEF
	unsigned int index;
	for (index = 0; index < count; ++index)
	{
		unsigned int len = ((((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF]) >> 3) - SALT_SIZE;
		unsigned int i = 0;

		// 1. Copy a byte at a time until we're aligned in buffer
		// 2. Copy a whole word, or two!
		// 3. Copy the stray bytes
		switch (len & 3)
		{
		case 0:
			*(ARCH_WORD_32*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(ARCH_WORD_32*)&saved_salt[i]);
			i += 4;
			*(ARCH_WORD_32*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(ARCH_WORD_32*)&saved_salt[i]);
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
			*(ARCH_WORD_32*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(ARCH_WORD_32*)&saved_salt[i]);
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
			*(ARCH_WORD_32*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(ARCH_WORD_32*)&saved_salt[i]);
			i += 4;
			*(ARCH_WORD_32*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(ARCH_WORD_32*)&saved_salt[i]);
			break;
		case 3:
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			i++;
			*(ARCH_WORD_32*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(ARCH_WORD_32*)&saved_salt[i]);
			i += 4;
			*(ARCH_WORD_32*)&saved_key[GETPOS_WORD((len+i),index)] =
				JOHNSWAP(*(ARCH_WORD_32*)&saved_salt[i]);
			i += 4;
			saved_key[GETPOS((len+i), index)] = saved_salt[i];
			break;
		}
	}
#ifdef SHA1_SSE_PARA
	SSESHA1body(saved_key, (unsigned int *)crypt_key, NULL, 0);
#else
	shammx_nosizeupdate_nofinalbyteswap( (unsigned char *) crypt_key, (unsigned char *) saved_key, 1);
#endif
#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, saved_key_length );
	SHA1_Update( &ctx, saved_salt, SALT_SIZE );
	SHA1_Final( (unsigned char *)crypt_key, &ctx);

#endif
}

static void * binary(char *ciphertext)
{
	static unsigned char realcipher[BINARY_SIZE];

	int i;
	for(i=0;i<BINARY_SIZE;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 +
						atoi16[ARCH_INDEX(ciphertext[i*2+1])];

#ifdef MMX_COEF
	alter_endianity((unsigned char *)realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

static int binary_hash_0(void *binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }
static int binary_hash_5(void *binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffffff; }
static int binary_hash_6(void *binary) { return ((ARCH_WORD_32 *)binary)[0] & 0x7ffffff; }

#ifdef MMX_COEF
#define KEY_OFF ((index/MMX_COEF)*MMX_COEF*5+(index&(MMX_COEF-1)))
static int get_hash_0(int index) { return ((ARCH_WORD_32 *)crypt_key)[KEY_OFF] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32 *)crypt_key)[KEY_OFF] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32 *)crypt_key)[KEY_OFF] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32 *)crypt_key)[KEY_OFF] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32 *)crypt_key)[KEY_OFF] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32 *)crypt_key)[KEY_OFF] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32 *)crypt_key)[KEY_OFF] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0x7ffffff; }
#endif

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_oracle11 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact,
		fmt_default_get_source
	}
};

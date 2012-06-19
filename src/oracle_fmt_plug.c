/*
 * Copyright (c) 2004 Simon Marechal
 * simon.marechal at thales-security.com
 *
 * UTF-8 support: Copyright magnum 2012 and hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted.
 */

#include <string.h>
#include <openssl/des.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "unicode.h"

#define FORMAT_LABEL			"oracle"
#define FORMAT_NAME			"Oracle 10 DES"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		120 // worst case UTF-8 is 40 characters of Unicode, that'll do

#define BINARY_SIZE			8
#define SALT_SIZE			(32 + 4)  // also contain the NULL
#define CIPHERTEXT_LENGTH		16

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

//#define DEBUG_ORACLE

static struct fmt_tests oracle_tests[] = {
	{"O$SYSTEM#9EEDFA0AD26C6D52", "THALES" },
	{"O$SIMON#4F8BC1809CB2AF77", "A"},
	{"O$SIMON#183D72325548EF11", "THALES2" },
	{"O$SIMON#C4EB3152E17F24A4", "TST" },
	{"O$BOB#b02c8e79ed2e7f46", "LAPIN" },
	{"O$BOB#6bb4e95898c88011", "LAPINE" },
	{"O$BOB#cdc6b483874b875b", "GLOUGLOU" },
	{"O$BOB#ef1f9139db2d5279", "GLOUGLOUTER" },
	{"O$BOB#c0ee5107c9a080c1", "AZERTYUIOP" },
	{"O$BOB#99e8b231d33772f9", "CANARDWC" },
	{"O$BOB#da3224126a67c8ed", "COUCOU_COUCOU" },
	{"O$BOB#ec8147abb3373d53", "LONG_MOT_DE_PASSE_OUI" },

	{"9EEDFA0AD26C6D52", "THALES",        {"SYSTEM"} },
	{"4F8BC1809CB2AF77", "A",             {"SIMON"} },
	{"183D72325548EF11", "THALES2",       {"SIMON"} },
	{"C4EB3152E17F24A4", "TST",           {"SIMON"} },
	{"b02c8e79ed2e7f46", "LAPIN",         {"BOB"} },
	{"6bb4e95898c88011", "LAPINE",        {"BOB"} },
	{"cdc6b483874b875b", "GLOUGLOU",      {"bob"} },  // put some low case in there, to make SURE the up case conversion works.
	{"ef1f9139db2d5279", "GLOUGLOUTER",   {"bob"} },  // also these 2 make sure lower cased passwords 'match' the 'get_key' method in the format tests.
	{"c0ee5107c9a080c1", "AZERTYUIOP",    {"BOB"} },
	{"99e8b231d33772f9", "CANARDWC",      {"BOB"} },
	{"da3224126a67c8ed", "COUCOU_COUCOU", {"BOB"} },
	{"ec8147abb3373d53", "LONG_MOT_DE_PASSE_OUI",   {"BOB"} },
	{NULL}
};

#if ARCH_LITTLE_ENDIAN
#define ENDIAN_SHIFT_L  << 8
#define ENDIAN_SHIFT_R  >> 8
#else
#define ENDIAN_SHIFT_L
#define ENDIAN_SHIFT_R
#endif

static ARCH_WORD_32 crypt_key[2];

static UTF16 cur_salt[SALT_SIZE / 2 + PLAINTEXT_LENGTH];
static UTF16 cur_key[PLAINTEXT_LENGTH + 1];

static DES_key_schedule desschedule1;
static DES_key_schedule desschedule2;

static int salt_length;
static int key_length;
static char *plain_key;

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;
	int l;

	/*
	 * 2 cases
	 * 1 - it comes from the disk, and does not have O$ + salt
	 * 2 - it comes from memory, and has got O$ + salt + # + blah
	 */

	if (!memcmp(ciphertext, "O$", 2))
	{
		l = strlen(ciphertext) - CIPHERTEXT_LENGTH;
		if(ciphertext[l-1]!='#')
			return 0;
	}
	else
	{
		if(strlen(ciphertext)!=CIPHERTEXT_LENGTH)
			return 0;
		l = 0;
	}
	for (i = l; i < l + CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
			(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
			|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}

	return 1;
}

static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	char *cp;

	if (!strncmp(split_fields[1], "O$", 2))
		return split_fields[1];
	if (!split_fields[0])
		return split_fields[1];
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 4);
	sprintf (cp, "O$%s#%s", split_fields[0], split_fields[1]);
	if (valid(cp, pFmt))
	{
		UTF8 tmp8[16*3+1];
		UTF16 tmp16[17];
		int utf8len, utf16len;

		// we no longer need this.  It was just used for valid().   We will recompute
		// all lengths, after we do an upcase, since upcase can change the length of the
		// utf8 string.
		MEM_FREE(cp);

		// Upcase user name, --encoding aware
		utf8len = enc_uc(tmp8, 16*3, (unsigned char*)split_fields[0], strlen(split_fields[0]));

		if (utf8len <= 0 && split_fields[0][0])
			return split_fields[1];

		// make sure this 'fits' into 16 unicode's
		utf16len = enc_to_utf16(tmp16, 16, tmp8, utf8len);
		if (utf16len <= 0)
			return split_fields[1];

		cp = mem_alloc_tiny(utf8len + strlen(split_fields[1]) + 4, MEM_ALIGN_NONE);
		sprintf (cp, "O$%s#%s", tmp8, split_fields[1]);
#ifdef DEBUG_ORACLE
		printf ("tmp8         : %s\n", tmp8);
#endif
		return cp;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static void oracle_init(struct fmt_main *pFmt)
{
	unsigned char deskey[8];

	initUnicode(UNICODE_UNICODE);

	deskey[0] = 0x01;
	deskey[1] = 0x23;
	deskey[2] = 0x45;
	deskey[3] = 0x67;
	deskey[4] = 0x89;
	deskey[5] = 0xab;
	deskey[6] = 0xcd;
	deskey[7] = 0xef;

	DES_set_key((DES_cblock *)deskey, &desschedule1);
}

static void oracle_set_salt(void *salt) {
	salt_length = ((unsigned short *)salt)[0];
	memcpy(cur_salt, &((unsigned short *)salt)[1], salt_length);
}

static void oracle_set_key(char *key, int index) {
	UTF16 cur_key_mixedcase[PLAINTEXT_LENGTH+1];
#if ARCH_LITTLE_ENDIAN
	UTF16 *c;
#endif

	plain_key = key;
	// Can't use enc_to_utf16_be() because we need to do utf16_uc later
	key_length = enc_to_utf16((UTF16 *)cur_key_mixedcase, PLAINTEXT_LENGTH, (unsigned char*)key, strlen(key));

	if (key_length <= 0)
		key_length = strlen16(cur_key_mixedcase);

	// We convert and uppercase in one shot
	key_length = utf16_uc((UTF16 *)cur_key, PLAINTEXT_LENGTH, cur_key_mixedcase, key_length);
	// we have no way to 'undo' here, since the expansion is due to single-2-multi expansion in the upcase,
	// and we can not 'fix' our password.  We simply have to 'not' properly decrypt this one, but protect ourselves.
	if (key_length < 0)
		key_length *= -1;

	// This must be byte-swapped on LE systems only (odd!?)
#if ARCH_LITTLE_ENDIAN
	c = cur_key;
	while((*c = *c << 8 | *c >> 8))
		c++;
#endif
	key_length *= sizeof(UTF16);

#ifdef DEBUG_ORACLE
	dump_stuff_msg("cur_key    ", (unsigned char*)&cur_key[0], key_length);
#endif
}

static char *oracle_get_key(int index) {
	static UTF8 UC_Key[PLAINTEXT_LENGTH*3*3+1];
	// Calling this will ONLY upcase characters 'valid' in the code page. There are MANY
	// code pages which mssql WILL upcase the letter (in UCS-2), but there is no upper case value
	// in the code page.  Thus we MUST keep the lower cased letter in this case.
	enc_uc(UC_Key, PLAINTEXT_LENGTH*3*3, (UTF8*)plain_key, strlen(plain_key));
	return (char*)UC_Key;
}

static void oracle_crypt_all(int count)
{
	unsigned char buf[sizeof(cur_salt)];
	unsigned int l;

	l = salt_length + key_length;
	crypt_key[0] = 0;
	crypt_key[1] = 0;
	memcpy((char *)cur_salt + salt_length, cur_key, key_length);

#ifdef DEBUG_ORACLE
	dump_stuff_msg("cur_salt    ", (unsigned char*)&cur_salt[0], salt_length+key_length);
#endif

	DES_ncbc_encrypt((unsigned char *)cur_salt, buf, l, &desschedule1, (DES_cblock *) crypt_key, DES_ENCRYPT);
	DES_set_key((DES_cblock *)crypt_key, &desschedule2);
	crypt_key[0] = 0;
	crypt_key[1] = 0;
	DES_ncbc_encrypt((unsigned char *)cur_salt, buf, l, &desschedule2, (DES_cblock *) crypt_key, DES_ENCRYPT);

#ifdef DEBUG_ORACLE
	dump_stuff_msg("  crypt_key ", (unsigned char*)&crypt_key[0], 8);
#endif
}

static void * oracle_binary(char *ciphertext)
{
	static unsigned char *out3;
	int l;
	int i;

	if (!out3) out3 = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	l = strlen(ciphertext) - CIPHERTEXT_LENGTH;
	for(i=0;i<BINARY_SIZE;i++)
	{
		out3[i] = atoi16[ARCH_INDEX(ciphertext[i*2+l])]*16
			+ atoi16[ARCH_INDEX(ciphertext[i*2+l+1])];
	}
	return out3;
}

static void * oracle_get_salt(char * ciphertext)
{
	static UTF16 *out;
	UTF8 salt[SALT_SIZE + 1];
	int l;

	if (!out) out = mem_alloc_tiny(SALT_SIZE+2, MEM_ALIGN_WORD);
	l = 2;
	while( ciphertext[l] && (ciphertext[l]!='#') )
	{
		salt[l-2] = ciphertext[l];
		l++;
		if (l-2 >= SALT_SIZE-2) break;
	}
	salt[l-2] = 0;

	// we now upcase the user name in the prepare() function.
	// So we are going back to 'simple' plain->utf16 convert only.
	l = enc_to_utf16_be(&out[1], 16, (UTF8 *)salt, l-2);
	if (l <= 0)
		l = strlen16(&out[1]);

	out[0] = (l<<1);
	return out;
}

// Public domain hash function by DJ Bernstein (salt is a username)
static int salt_hash(void *salt)
{
	UTF16 *s = ((UTF16*)salt) + 1;
	unsigned int hash = 5381;

	while (*s)
		hash = ((hash << 5) + hash) ^ *s++;

	return hash & (SALT_HASH_SIZE - 1);
}

static int binary_hash0(void * binary) { return (((ARCH_WORD_32 *)binary)[0] & 0xf); }
static int binary_hash1(void * binary) { return (((ARCH_WORD_32 *)binary)[0] & 0xff); }
static int binary_hash2(void * binary) { return (((ARCH_WORD_32 *)binary)[0] & 0xfff); }
static int binary_hash3(void * binary) { return (((ARCH_WORD_32 *)binary)[0] & 0xffff); }
static int binary_hash4(void * binary) { return (((ARCH_WORD_32 *)binary)[0] & 0xfffff); }

static int get_hash0(int index) { return crypt_key[0] & 0xf; }
static int get_hash1(int index) { return crypt_key[0] & 0xff; }
static int get_hash2(int index) { return crypt_key[0] & 0xfff; }
static int get_hash3(int index) { return crypt_key[0] & 0xffff; }
static int get_hash4(int index) { return crypt_key[0] & 0xfffff; }

static int oracle_cmp_all(void *binary, int index) {
	return !memcmp(binary, crypt_key, sizeof(crypt_key));
}

static int oracle_cmp_exact(char *source, int count) {
	return 1;
}

struct fmt_main fmt_oracle = {
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
		FMT_8_BIT | FMT_UNICODE | FMT_UTF8,
		oracle_tests
	}, {
		oracle_init,
		prepare,
		valid,
		fmt_default_split,
		oracle_binary,
		oracle_get_salt,
		{
			binary_hash0,
			binary_hash1,
			binary_hash2,
			binary_hash3,
			binary_hash4
		},
		salt_hash,
		oracle_set_salt,
		oracle_set_key,
		oracle_get_key,
		fmt_default_clear_keys,
		oracle_crypt_all,
		{
			get_hash0,
			get_hash1,
			get_hash2,
			get_hash3,
			get_hash4
		},
		oracle_cmp_all,
		oracle_cmp_all,
		oracle_cmp_exact
	}
};

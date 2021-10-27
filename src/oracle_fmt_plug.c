/*
 * This software is Copyright (c) 2004 bartavelle, <simon at banquise.net>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * UTF-8 support: Copyright magnum 2012 and hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_oracle;
#elif FMT_REGISTERS_H
john_register_one(&fmt_oracle);
#else

#include <string.h>
#include <openssl/des.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "unicode.h"

#define FORMAT_LABEL            "oracle"
#define FORMAT_NAME             "Oracle 10"
#define FORMAT_TAG              "O$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "DES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        120 // worst case UTF-8 is 40 characters of Unicode, that'll do
#define BINARY_SIZE             8
#define BINARY_ALIGN            4
#define MAX_USERNAME_LEN        30
#define SALT_SIZE               (MAX_USERNAME_LEN*2 + 4)  // also contain the NULL
#define SALT_ALIGN              2
#define CIPHERTEXT_LENGTH       16
#define MAX_INPUT_LEN           (CIPHERTEXT_LENGTH + 3 + MAX_USERNAME_LEN * (options.input_enc == UTF_8 ? 3 : 1))
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifndef OMP_SCALE
#define OMP_SCALE               64 // Tuned w/ MKPC for core i7
#endif

//#define DEBUG_ORACLE

static struct fmt_tests tests[] = {
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
	{"O$bob#ec8147abb3373d53", "LONG_MOT_DE_PASSE_OUI" },

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

static UTF16 cur_salt[SALT_SIZE / 2 + PLAINTEXT_LENGTH];
static UTF16 (*cur_key)[PLAINTEXT_LENGTH + 1];
static char (*plain_key)[PLAINTEXT_LENGTH + 1];
static int (*key_length);
static uint32_t (*crypt_key)[2];

static DES_key_schedule desschedule_static;

static int salt_length;

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	int l;

	/*
	 * 2 cases
	 * 1 - it comes from the disk, and does not have O$ + salt
	 * 2 - it comes from memory, and has got O$ + salt + # + blah
	 */

	if (strnlen(ciphertext, MAX_INPUT_LEN + 1) > MAX_INPUT_LEN)
		return 0;

	if (!memcmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
	{
		int len;
		char name[MAX_USERNAME_LEN + 1];
		UTF16 name16[MAX_USERNAME_LEN + 1 + 1];

		ciphertext += FORMAT_TAG_LEN;
		l = strlen(ciphertext) - CIPHERTEXT_LENGTH;
		if (l <= 0)
			return 0;
		if (ciphertext[l-1] != '#')
			return 0;
		strnzcpy(name, ciphertext, sizeof(name));
		len = enc_to_utf16(name16, MAX_USERNAME_LEN + 1,
		                   (UTF8*)name, strlen(name));
		if (len < 0) {
			static int error_shown = 0;
#ifdef HAVE_FUZZ
			if (options.flags & (FLG_FUZZ_CHK | FLG_FUZZ_DUMP_CHK))
				return 0;
#endif
			if (!error_shown)
				fprintf(stderr, "%s: Input file is not UTF-8. Please use --input-enc to specify a codepage.\n", self->params.label);
			error_shown = 1;
			return 0;
		}
		if (len > MAX_USERNAME_LEN)
			return 0;
	}
	else
	{
		if (strlen(ciphertext)!=CIPHERTEXT_LENGTH)
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

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;

	if (!split_fields[0])
		return split_fields[1];
	if (!strncmp(split_fields[1], FORMAT_TAG, FORMAT_TAG_LEN))
		return split_fields[1];
	if (strnlen(split_fields[1], CIPHERTEXT_LENGTH + 1) == CIPHERTEXT_LENGTH) {
		cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 4);
		sprintf(cp, "%s%s#%s", FORMAT_TAG, split_fields[0], split_fields[1]);
		if (valid(cp, self)) {
			UTF8 tmp8[MAX_USERNAME_LEN * 3 + 1];
			int utf8len;

			// we no longer need this.  It was just used for valid().   We will recompute
			// all lengths, after we do an upcase, since upcase can change the length of the
			// utf8 string.
			MEM_FREE(cp);

			// Upcase user name, --encoding aware
			utf8len = enc_uc(tmp8, sizeof(tmp8), (unsigned char*)split_fields[0], strlen(split_fields[0]));

			cp = mem_alloc_tiny(utf8len + strlen(split_fields[1]) + 4, MEM_ALIGN_NONE);
			sprintf(cp, "%s%s#%s", FORMAT_TAG, tmp8, split_fields[1]);
#ifdef DEBUG_ORACLE
			printf("tmp8         : %s\n", tmp8);
#endif
			return cp;
		}
		MEM_FREE(cp);
	}
	return split_fields[1];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[FORMAT_TAG_LEN + sizeof(cur_salt) + 1 + CIPHERTEXT_LENGTH];
	char *cp;
	strnzcpy(out, ciphertext, sizeof(out));
	enc_strupper(&out[FORMAT_TAG_LEN]);
	cp = strrchr(out, '#');
	if (cp)
		strlwr(cp);

	return out;
}

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	DES_set_key_unchecked((DES_cblock *)"\x01\x23\x45\x67\x89\xab\xcd\xef", &desschedule_static);
	cur_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*cur_key));
	plain_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*plain_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
	key_length = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*key_length));
}

static void done(void)
{
	MEM_FREE(key_length);
	MEM_FREE(crypt_key);
	MEM_FREE(plain_key);
	MEM_FREE(cur_key);
}

static void set_salt(void *salt) {
	salt_length = ((unsigned short *)salt)[0];
	memcpy(cur_salt, &((unsigned short *)salt)[1], salt_length);
}

static void oracle_set_key(char *key, int index) {
	UTF16 cur_key_mixedcase[PLAINTEXT_LENGTH+1];
	UTF16 *c;

	strnzcpy(plain_key[index], key, sizeof(*plain_key));
	// Can't use enc_to_utf16_be() because we need to do utf16_uc later
	key_length[index] = enc_to_utf16((UTF16 *)cur_key_mixedcase, PLAINTEXT_LENGTH, (unsigned char*)key, strlen(key));

	if (key_length[index] < 0)
		key_length[index] = strlen16(cur_key_mixedcase);

	// We convert and uppercase in one shot
	key_length[index] = utf16_uc((UTF16 *)cur_key[index], PLAINTEXT_LENGTH, cur_key_mixedcase, key_length[index]);
	// we have no way to 'undo' here, since the expansion is due to single-2-multi expansion in the upcase,
	// and we can not 'fix' our password.  We simply have to 'not' properly decrypt this one, but protect ourselves.
	if (key_length[index] < 0)
		key_length[index] *= -1;

	// Now byte-swap to UTF16-BE
	c = cur_key[index];
	while((*c = *c << 8 | *c >> 8))
		c++;
	key_length[index] *= sizeof(UTF16);

#ifdef DEBUG_ORACLE
	dump_stuff_msg("cur_key    ", (unsigned char*)&cur_key[index][0], key_length[index]);
#endif
}

static char *get_key(int index) {
	static UTF8 UC_Key[PLAINTEXT_LENGTH*3*3+1];
	// Calling this will ONLY upcase characters 'valid' in the code page. There are MANY
	// code pages which mssql WILL upcase the letter (in UCS-2), but there is no upper case value
	// in the code page.  Thus we MUST keep the lower cased letter in this case.
	enc_uc(UC_Key, sizeof(UC_Key), (UTF8*)plain_key[index], strlen(plain_key[index]));
	return (char*)UC_Key;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int idx = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (idx = 0; idx < count; idx++) {
		unsigned char buf[sizeof(cur_salt)];
		unsigned char buf2[SALT_SIZE + PLAINTEXT_LENGTH*2];
		DES_key_schedule sched_local;
		unsigned int l;

		l = salt_length + key_length[idx];
		memcpy(buf2, cur_salt, salt_length);
		memcpy(buf2 + salt_length, cur_key[idx], key_length[idx]);
#ifdef DEBUG_ORACLE
		dump_stuff_msg("cur_salt    ", buf2, salt_length+key_length[idx]);
#endif
		crypt_key[idx][0] = 0;
		crypt_key[idx][1] = 0;

		DES_ncbc_encrypt(buf2, buf, l, &desschedule_static, (DES_cblock *) crypt_key[idx], DES_ENCRYPT);
		DES_set_key_unchecked((DES_cblock *)crypt_key[idx], &sched_local);
		crypt_key[idx][0] = 0;
		crypt_key[idx][1] = 0;
		DES_ncbc_encrypt(buf2, buf, l, &sched_local, (DES_cblock *) crypt_key[idx], DES_ENCRYPT);

#ifdef DEBUG_ORACLE
		dump_stuff_msg("  crypt_key ", (unsigned char*)&crypt_key[idx][0], 8);
#endif
	}

	return count;
}

static void * get_binary(char *ciphertext)
{
	static unsigned char *out3;
	int l;
	int i;

	if (!out3) out3 = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	l = strlen(ciphertext) - CIPHERTEXT_LENGTH;
	for (i = 0; i < BINARY_SIZE; i++) {
		out3[i] = atoi16[ARCH_INDEX(ciphertext[i*2+l])]*16
			+ atoi16[ARCH_INDEX(ciphertext[i*2+l+1])];
	}

	return out3;
}

static void * get_salt(char * ciphertext)
{
	static UTF16 *out;
	UTF8 salt[SALT_SIZE + 1];
	int l;

	if (!out) out = mem_alloc_tiny(SALT_SIZE+2, MEM_ALIGN_WORD);
	memset(out, 0, SALT_SIZE+2);
	ciphertext += FORMAT_TAG_LEN;
	l = 0;
	while( ciphertext[l] && (ciphertext[l]!='#') )
	{
		salt[l] = ciphertext[l];
		l++;
		if (l >= SALT_SIZE-2) break;
	}
	salt[l] = 0;

	// Encoding-aware shift to upper-case
	enc_strupper((char*)salt);

	l = enc_to_utf16_be(&out[1], MAX_USERNAME_LEN, (UTF8 *)salt, l);

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

#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

static int cmp_all(void *binary, int count)
{
	int i;
	uint32_t b = *(uint32_t*)binary;

	for (i = 0; i < count; ++i)
		if (b == *((uint32_t*)(crypt_key[i])) )
			return 1;
	return 0;
}

static int cmp_one(void *binary, int idx)
{
	return !memcmp(binary, crypt_key[idx], sizeof(crypt_key[idx]));
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_oracle = {
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
		FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
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
		oracle_set_key,
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
#endif /* HAVE_LIBCRYPTO */

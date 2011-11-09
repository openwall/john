/*
 * Copyright (c) 2008 Alexandre Hamelin
 * alexandre.hamelin(@)gmail.com
 * Based on saltSHA1 format source.
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
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include <ctype.h>

#define FORMAT_LABEL			"oracle11"
#define FORMAT_NAME			"Oracle 11g"
#define ALGORITHM_NAME			"oracle11"

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

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	/* 160 bits of SHA1, followed by 80 bits of salt. No "S:" prefix. */
	{"5FDAB69F543563582BA57894FE1C1361FB8ED57B903603F2C52ED1B4D642", "abc123"},
	{"450F957ECBE075D2FA009BA822A9E28709FBC3DA82B44D284DDABEC14C42", "SyStEm123!@#"},
	{"3437FF72BD69E3FB4D10C750B92B8FB90B155E26227B9AB62D94F54E5951", "oracle"},
	{"61CE616647A4F7980AFD7C7245261AF25E0AFE9C9763FCF0D54DA667D4E6", "11g"},
	{"B9E7556F53500C8C78A58F50F24439D79962DE68117654B6700CE7CC71CF", "11g"},
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
static int saved_key_length;
static unsigned char saved_salt[SALT_SIZE];
static SHA_CTX ctx;
static ARCH_WORD_32 crypt_out[BINARY_SIZE / 4];

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
	static unsigned char salt[SALT_SIZE];
	int i;

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

static void set_key(char *key, int index) {
	saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);
	saved_key[saved_key_length] = 0;
}

static char *get_key(int index) {
	return saved_key;
}

static int cmp_all(void *binary, int index) {
	return !memcmp(binary, crypt_out, BINARY_SIZE);
}

static int cmp_exact(char *source, int count) {
	return 1;
}

static void crypt_all(int count) {
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, saved_key_length );
	SHA1_Update( &ctx, saved_salt, SALT_SIZE );
	SHA1_Final( (unsigned char *)crypt_out, &ctx);
}

static void * binary(char *ciphertext)
{
	static unsigned char realcipher[BINARY_SIZE];

	int i;
	for(i=0;i<BINARY_SIZE;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 +
						atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	return (void *)realcipher;
}

static int binary_hash_0(void *binary)
{
  return ((ARCH_WORD_32 *)binary)[0] & 0xF;
}

static int binary_hash_1(void *binary)
{
  return ((ARCH_WORD_32 *)binary)[0] & 0xFF;
}

static int binary_hash_2(void *binary)
{
  return ((ARCH_WORD_32 *)binary)[0] & 0xFFF;
}

static int binary_hash_3(void *binary)
{
  return ((ARCH_WORD_32 *)binary)[0] & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
  return ((ARCH_WORD_32 *)binary)[0] & 0xFFFFF;
}

static int get_hash_0(int index)
{
  return crypt_out[0] & 0xF;
}

static int get_hash_1(int index)
{
  return crypt_out[0] & 0xFF;
}

static int get_hash_2(int index)
{
  return crypt_out[0] & 0xFFF;
}

static int get_hash_3(int index)
{
  return crypt_out[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
  return crypt_out[0] & 0xFFFFF;
}

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
		fmt_default_init,
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
			binary_hash_4
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
			get_hash_4
		},
		cmp_all,
		cmp_all,
		cmp_exact
	}
};

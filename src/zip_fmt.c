/*
 * ZIP cracker patch for JtR. Hacked together during June of 2011
 * by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Files borrowed from http://www.gladman.me.uk/cryptography_technology/fileencrypt/
 * have "gladman_" prepended to them.
 *
 * http://www.winzip.com/aes_info.htm (There is a 1 in 65,536 chance that an
 * incorrect password will yield a matching verification value; therefore, a
 * matching verification value cannot be absolutely relied on to indicate a
 * correct password.). The alternative is to implement/use a full unzip engine.
 */

#include <string.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"
#include "crc32.h"
#include "misc.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "gladman_fileenc.h"

#define FORMAT_LABEL        "zip"
#define FORMAT_NAME         "WinZip PBKDF2-HMAC-SHA-1"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         2
#define SALT_SIZE           512
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  96

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];
static int has_been_cracked[MAX_KEYS_PER_CRYPT];
static unsigned char saved_salt[48];
static unsigned char passverify[2];
static int type;		/* type of zip file */
static int mode;

static struct fmt_tests zip_tests[] = {
	{"$zip$*0*1*8005b1b7d077708d*dee4", "testpassword#"},
	{"$zip$*0*3*e3bd6c1a4c4950d0c35c1b0ca2bd5e84*061f", "testpassword#"},
	{NULL}
};

struct fmt_main zip_fmt;

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$zip$*", 6);
}

static void *get_salt(char *ciphertext)
{
	return ciphertext;
}

static void set_salt(void *salt)
{
	int i, strength, n;
	/* extract data from "salt" */
	char *encoded_salt, *p;
	char *saltcopy_mem = strdup(salt);
	char *saltcopy = saltcopy_mem + 6; /* skip over "$zip$*" */

	type = atoi(strtok(saltcopy, "*"));
	strength = atoi(strtok(NULL, "*"));
	mode = strength;
	switch (strength) {
	case 1:
		n = 8;
		break;
	case 2:
		n = 12;
		break;
	case 3:
		n = 16;
		break;
	default:
		fprintf(stderr, "ZIP: Unsupported strength %d\n", strength);
		error();
		n = 0; /* Not reached */
	}
	encoded_salt = strtok(NULL, "*");
	for (i = 0; i < n; i++)
		saved_salt[i] = atoi16[ARCH_INDEX(encoded_salt[i * 2])] * 16
		    + atoi16[ARCH_INDEX(encoded_salt[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 2; i++)
		passverify[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	memset(has_been_cracked, 0, MAX_KEYS_PER_CRYPT);
	MEM_FREE(saltcopy_mem);
}

static void zip_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static void crypt_all(int count)
{
	int index;
#ifdef _OPENMP
#pragma omp parallel for default(none) private(index) shared(count, passverify, has_been_cracked, saved_key, saved_salt, mode)
#endif
	for (index = 0; index < count; index++) {
		unsigned char pwd_ver[2] = { 0 };
		unsigned char kbuf[2 * MAX_KEY_LENGTH + PWD_VER_LENGTH];
/* Derive the encryption and authetication keys and the password verifier */
		derive_key((unsigned char *)saved_key[index],
		    strlen(saved_key[index]), saved_salt, SALT_LENGTH(mode),
		    KEYING_ITERATIONS, kbuf,
		    2 * KEY_LENGTH(mode) + PWD_VER_LENGTH);
		memcpy(pwd_ver, kbuf + 2 * KEY_LENGTH(mode), PWD_VER_LENGTH);
		has_been_cracked[index] = !memcmp(pwd_ver, passverify, 2);
	}
}

static int cmp_all(void *binary, int count)
{
	return 1;
}

static int cmp_one(void *binary, int index)
{
	return has_been_cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return has_been_cracked[index];
}

struct fmt_main zip_fmt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,   /*ldr_remove_hash(crk_db, salt, pw);*/
		zip_tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		zip_set_key,
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

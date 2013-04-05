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
#include "pbkdf2_hmac_sha1.h"

/* From gladman_fileenc.h */
#define PWD_VER_LENGTH         2
#define KEYING_ITERATIONS   1000
#define KEY_LENGTH(mode)        (8 * ((mode) & 3) + 8)
#define SALT_LENGTH(mode)       (4 * ((mode) & 3) + 4)

#define FORMAT_LABEL        "zip"
#define FORMAT_NAME         "WinZip PBKDF2-HMAC-SHA-1"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define BINARY_SIZE         0
#define SALT_SIZE           128
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  96

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];
static int has_been_cracked[MAX_KEYS_PER_CRYPT];
static unsigned char *saved_salt;
static unsigned char passverify[2];
static int type;		/* type of zip file */
static int mode;

static struct fmt_tests zip_tests[] = {
	{"$zip$*0*1*8005b1b7d077708d*dee4", "testpassword#"},
	{"$zip$*0*3*e3bd6c1a4c4950d0c35c1b0ca2bd5e84*061f", "testpassword#"},
	{NULL}
};

struct fmt_main zip_fmt;

static int ishex(char *q)
{
       while (atoi16[ARCH_INDEX(*q)] != 0x7F)
               q++;
       return !*q;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;

	if (strncmp(ciphertext, "$zip$*", 6))
		return 0;
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += 6;	/* skip leading '$zip$*' */
	if (!(ptr = strtok(ctcopy, "*")))
		goto error;
	if (*ptr != '0')
		goto error;
	if (!(ptr = strtok(NULL, "*")))
		goto error;
	if (strlen(ptr) != 1)
		goto error;
	if (!(ptr = strtok(NULL, "*")))
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtok(NULL, "*")))
		goto error;
	if (!ishex(ptr))
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	int i, strength, n;
	static unsigned char salt[SALT_SIZE];
	/* extract data from "ciphertext" */
	char *encoded_ciphertext, *p;
	char *copy_mem = strdup(ciphertext);
	char *copy = copy_mem + 6; /* skip over "$zip$*" */

	type = atoi(strtok(copy, "*"));
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
	encoded_ciphertext = strtok(NULL, "*");
	for (i = 0; i < n; i++)
		salt[i] = atoi16[ARCH_INDEX(encoded_ciphertext[i * 2])] * 16
		    + atoi16[ARCH_INDEX(encoded_ciphertext[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 2; i++)
		passverify[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(copy_mem);
	return (void*)salt;
}

static void set_salt(void *salt)
{
	memset(has_been_cracked, 0, MAX_KEYS_PER_CRYPT);
	saved_salt = (unsigned char*)salt;
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
		unsigned char kbuf[2 * PLAINTEXT_LENGTH + PWD_VER_LENGTH];
/* Derive the encryption and authetication keys and the password verifier */
		pbkdf2((unsigned char *)saved_key[index],
		       strlen(saved_key[index]), saved_salt, SALT_LENGTH(mode),
		       KEYING_ITERATIONS, kbuf,
		       2 * KEY_LENGTH(mode) + PWD_VER_LENGTH);
		memcpy(pwd_ver, kbuf + 2 * KEY_LENGTH(mode), PWD_VER_LENGTH);
		has_been_cracked[index] = !memcmp(pwd_ver, passverify, 2);
	}
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (has_been_cracked[i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return has_been_cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return has_been_cracked[index];
}

struct fmt_main fmt_zip = {
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

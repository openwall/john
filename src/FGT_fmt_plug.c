/*
 * Fortigate (FortiOS) Password cracker
 *
 * This software is Copyright (c) 2012 Mat G. <mat.jtr at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Passwords are located in "config system admin" part of the configuration file :
 *
 * config system admin
 *     edit "<username>"
 *        set password ENC AK1wTiFOMv7mZOTvQNmKQBAY98hZZjSRLxAY8vZp8NlDWU=
 *
 * Password is : AK1|base64encode(salt|hashed_password)
 * where hashed_password is SHA1(salt|password|fortinet_magic)
 *
 * salt is 12 bytes long
 * hashed_password is 20 bytes long (SHA1 salt)
 * encoded password is 47 bytes long (3 bytes for AK1 and 44 bytes of base64encode(salt|hashed_password))
 *
 */

#include <string.h>

#include "common.h"
#include "formats.h"
#include "misc.h"

#include "sha.h"
#include "base64.h"
#include "sse-intrinsics.h"

#define FORMAT_LABEL			"fortigate"
#define FORMAT_NAME             "Fortigate FortiOS"
#define ALGORITHM_NAME			SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		44
#define HASH_LENGTH             CIPHERTEXT_LENGTH + 3

#define BINARY_SIZE             20
#define SALT_SIZE               12

#define FORTINET_MAGIC          "\xa3\x88\xba\x2e\x42\x4c\xb0\x4a\x53\x79\x30\xc1\x31\x07\xcc\x3f\xa1\x32\x90\x29\xa9\x81\x5b\x70"
#define FORTINET_MAGIC_LENGTH   24

#define MIN_KEYS_PER_CRYPT		1
#ifdef _OPENMP
#define MAX_KEYS_PER_CRYPT		(0x200 * 3)
#else
#define MAX_KEYS_PER_CRYPT		0x100
#endif


static struct fmt_tests fgt_tests[] =
{
	{"AK1wTiFOMv7mZOTvQNmKQBAY98hZZjSRLxAY8vZp8NlDWU=", "fortigate"},
	{"AK1Vd1SCGVtAAT931II/U22WTppAISQkITHOlz0ukIg4nA=", "admin"},
	{"AK1DZLDpqz335ElPtuiNTpguiozY7xVaHjHYnxw6sNlI6A=", "ftnt"},
	{NULL}
};

static SHA_CTX ctx_salt;

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];
static int saved_key_len[MAX_KEYS_PER_CRYPT];

static ARCH_WORD_32 crypt_key[MAX_KEYS_PER_CRYPT][BINARY_SIZE / sizeof(ARCH_WORD_32)];

static int FGT_valid(char *ciphertext, struct fmt_main *self)
{
	if (strlen(ciphertext) != HASH_LENGTH)
		return 0;
	if (strncmp(ciphertext, "AK1", 3))
		return 0;

	return 1;
}

static void * FGT_get_salt(char *ciphertext)
{
	static char out[SALT_SIZE];
	char buf[SALT_SIZE+BINARY_SIZE+1];

	base64_decode(ciphertext+3, CIPHERTEXT_LENGTH, buf);
	memcpy(out, buf, SALT_SIZE);

	return out;
}

static void FGT_set_salt(void *salt)
{
	SHA1_Init(&ctx_salt);
	SHA1_Update(&ctx_salt, salt, SALT_SIZE);
}

static void FGT_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH+1);
	saved_key_len[index] = strlen(key);
}

static char * FGT_get_key(int index)
{
	return saved_key[index];
}

static void * FGT_binary(char *ciphertext)
{
	static char bin[BINARY_SIZE];
	char buf[SALT_SIZE+BINARY_SIZE+1];

	memset(buf, 0, sizeof(buf));
	base64_decode(ciphertext+3, CIPHERTEXT_LENGTH, buf);
	// skip over the 12 bytes of salt and get only the hashed password
	memcpy(bin, buf+SALT_SIZE, BINARY_SIZE);

	return bin;
}


static int FGT_cmp_all(void *binary, int count)
{
	ARCH_WORD_32 b0 = *(ARCH_WORD_32 *)binary;
	int i;

	for (i = 0; i < count; i++) {
		if (b0 != *(ARCH_WORD_32 *)crypt_key[i])
			continue;
		if (!memcmp(binary, crypt_key[i], BINARY_SIZE))
			return 1;
	}
	return 0;


}

static int FGT_cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static int FGT_cmp_exact(char *source, int index)
{
	return 1;
}


static void FGT_crypt_all(int count)
{
	int i;
#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(ctx_salt, count, saved_key, saved_key_len, crypt_key)
#endif
	for (i = 0; i < count; i++) {
		SHA_CTX ctx;

		memcpy(&ctx, &ctx_salt, sizeof(ctx));

		SHA1_Update(&ctx, saved_key[i], saved_key_len[i]);
		SHA1_Update(&ctx, (char *)FORTINET_MAGIC, FORTINET_MAGIC_LENGTH);
		SHA1_Final((unsigned char*)crypt_key[i], &ctx);
	}
}


static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xF; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFF; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFFF; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7FFFFFF; }


static int get_hash_0(int index) { return ((ARCH_WORD_32 *)(crypt_key[index]))[0] & 0xF; }
static int get_hash_1(int index) { return ((ARCH_WORD_32 *)(crypt_key[index]))[0] & 0xFF; }
static int get_hash_2(int index) { return ((ARCH_WORD_32 *)(crypt_key[index]))[0] & 0xFFF; }
static int get_hash_3(int index) { return ((ARCH_WORD_32 *)(crypt_key[index]))[0] & 0xFFFF; }
static int get_hash_4(int index) { return ((ARCH_WORD_32 *)(crypt_key[index]))[0] & 0xFFFFF; }
static int get_hash_5(int index) { return ((ARCH_WORD_32 *)(crypt_key[index]))[0] & 0xFFFFFF; }
static int get_hash_6(int index) { return ((ARCH_WORD_32 *)(crypt_key[index]))[0] & 0x7FFFFFF; }


static int FGT_salt_hash(void *salt)
{
	ARCH_WORD_32 mysalt = *(ARCH_WORD_32 *)salt;
	return mysalt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_FGT = {
    {
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP ,
		fgt_tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		FGT_valid,
		fmt_default_split,
		FGT_binary,
		FGT_get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		FGT_salt_hash,
		FGT_set_salt,
		FGT_set_key,
		FGT_get_key,
		fmt_default_clear_keys,
		FGT_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		FGT_cmp_all,
		FGT_cmp_one,
		FGT_cmp_exact
	}
};

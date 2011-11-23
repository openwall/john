/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 * based on rawMD4_fmt.c code, with trivial changes by groszek.
 */

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x00908000

#include <string.h>
#include <openssl/sha.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"raw-sha224"
#define FORMAT_NAME			"Raw SHA-224"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		56

#define BINARY_SIZE			28
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01", "password"},
	{"$SHA224$7e6a4309ddf6e8866679f61ace4f621b0e3455ebac2e831a60f13cd1", "12345678"},
	{NULL}
};

static int saved_key_length;
static char saved_key[PLAINTEXT_LENGTH + 1];
static SHA256_CTX ctx;
static ARCH_WORD_32 crypt_out
    [(BINARY_SIZE + sizeof(ARCH_WORD_32) - 1) / sizeof(ARCH_WORD_32)];

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, "$SHA224$", 8))
		p += 8;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'A' && *q <= 'F') /* support lowercase only */
			return 0;
		q++;
	}
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index)
{
	static char out[8 + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, "$SHA224$", 8))
		return ciphertext;

	memcpy(out, "$SHA224$", 8);
	memcpy(out + 8, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 8;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0x7FFFFFF;
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

static int get_hash_5(int index)
{
	return crypt_out[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return crypt_out[0] & 0x7FFFFFF;
}

static void set_key(char *key, int index)
{
	saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);
}

static char *get_key(int index)
{
	saved_key[saved_key_length] = 0;
	return saved_key;
}

static void crypt_all(int count)
{
	SHA224_Init(&ctx);
	SHA224_Update(&ctx, saved_key, saved_key_length);
	SHA224_Final((unsigned char *)crypt_out, &ctx);
}

static int cmp_all(void *binary, int count)
{
	return !memcmp(binary, crypt_out, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_rawSHA224 = {
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
		split,
		get_binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
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
		cmp_all,
		cmp_exact
	}
};

#else
#ifdef __GNUC__
#warning Note: SHA-224 format disabled - it needs OpenSSL 0.9.8 or above
#endif
#endif

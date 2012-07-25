/*
 * This  software is Copyright © 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * Based on hmac-md5 by Bartavelle
 */

#include "sha2.h"

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"hmac-sha384"
#define FORMAT_NAME			"HMAC SHA-384"

#if ARCH_BITS >= 64
#define ALGORITHM_NAME			"64/" ARCH_BITS_STR " " SHA2_LIB
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR " " SHA2_LIB
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125

#define PAD_SIZE			128
#define BINARY_SIZE			(384/8)
#define SALT_SIZE			PAD_SIZE
#define CIPHERTEXT_LENGTH		(SALT_SIZE + 1 + BINARY_SIZE * 2)

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"what do ya want for nothing?#af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649", "Jefe"},
	{"Beppe#Grillo#8361922C63506E53714F8A8491C6621A76CF0FD6DFEAD91BF59B420A23DFF2745C0A0D5E142D4F937E714EA8C228835B", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	{NULL}
};

static union xx {
	char c[BINARY_SIZE+1];
	ARCH_WORD a[BINARY_SIZE/sizeof(ARCH_WORD)+1];
} u;
static char *crypt_key = u.c;  // Requires alignment on generic sha2.c
static unsigned char opad[PAD_SIZE];
static unsigned char ipad[PAD_SIZE];
static unsigned char cursalt[SALT_SIZE];
static char saved_plain[PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int pos, i;
	char *p;

	p = strrchr(ciphertext, '#'); // allow # in salt
	if (!p || p > &ciphertext[strlen(ciphertext)-1]) return 0;
	i = (int)(p - ciphertext);
	if(i > SALT_SIZE) return 0;
	pos = i+1;
	if (strlen(ciphertext+pos) != BINARY_SIZE*2) return 0;
	for (i = pos; i < BINARY_SIZE*2+pos; i++)
	{
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
		        (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		        || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static char *split(char *ciphertext, int index)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(strrchr(out, '#'));

	return out;
}

static void set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	int len;
	int i;

	len = strlen(key);

	memset(ipad, 0x36, PAD_SIZE);
	memset(opad, 0x5C, PAD_SIZE);

#if PLAINTEXT_LENGTH > PAD_SIZE
	memcpy(saved_plain, key, len);
	saved_plain[len] = 0;

	if (len > PAD_SIZE) {
		SHA512_CTX ctx;
		unsigned char k0[BINARY_SIZE];

		SHA384_Init( &ctx );
		SHA384_Update( &ctx, key, len);
		SHA384_Final( k0, &ctx);

		len = BINARY_SIZE;

		for(i=0;i<len;i++)
		{
			ipad[i] ^= k0[i];
			opad[i] ^= k0[i];
		}
	}
	else
#endif /* PLAINTEXT_LENGTH > PAD_SIZE */
	for(i=0;i<len;i++)
	{
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}
}

static char *get_key(int index)
{
#if PLAINTEXT_LENGTH > PAD_SIZE
	return saved_plain;
#else
	unsigned int i;
	for(i=0;i<PLAINTEXT_LENGTH;i++)
		saved_plain[i] = ipad[ i ] ^ 0x36;
	saved_plain[i] = 0;
	return (char*) saved_plain;
#endif
}

static int cmp_all(void *binary, int count)
{
	return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static int cmp_exact(char *source, int count)
{
	return (1);
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static void crypt_all(int count)
{
	SHA512_CTX ctx;

	SHA384_Init( &ctx );
	SHA384_Update( &ctx, ipad, PAD_SIZE );
	SHA384_Update( &ctx, cursalt, strlen( (char*) cursalt) );
	SHA384_Final( (unsigned char*) crypt_key, &ctx);

	SHA384_Init( &ctx );
	SHA384_Update( &ctx, opad, PAD_SIZE );
	SHA384_Update( &ctx, crypt_key, BINARY_SIZE);
	SHA384_Final( (unsigned char*) crypt_key, &ctx);
}

static void *binary(char *ciphertext)
{
	static unsigned char realcipher[BINARY_SIZE];
	int i,pos;

	for(i=strlen(ciphertext);ciphertext[i]!='#';i--); // allow # in salt
	pos=i+1;
	for(i=0;i<BINARY_SIZE;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];

	return (void*)realcipher;
}

static void *salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE];

	memset(salt, 0, sizeof(salt));
	// allow # in salt
	memcpy(salt, ciphertext, strrchr(ciphertext, '#') - ciphertext);
	return salt;
}

struct fmt_main fmt_hmacSHA384 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		valid,
		split,
		binary,
		salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

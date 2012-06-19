/*
 * Drupal 7 phpass variant using SHA-512 and hashes cut at 258 bits.
 *
 * This  software is Copyright © 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * These are 8 byte salted hashes with a loop count that defines the number
 * of loops to compute. Drupal uses 258 bits of the hash, this is a multiple of
 * 6 but not 8. I presume this is for getting unpadded base64. Anyway we store
 * an extra byte but for now we will only compare 256 bits. I doubt that will
 * pose any problems. Actually I'm not quite sure the last bits end up correct
 * from the current version of binary().
 *
 * Based on [old thick] phpass-md5.
 */

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x00908000

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#if defined(__APPLE__) && defined(__MACH__)
#ifdef __MAC_OS_X_VERSION_MIN_REQUIRED
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif
#else
#include <openssl/sha.h>
#endif
#else
#include <openssl/sha.h>
#endif

#define FORMAT_LABEL			"drupal7"
#define FORMAT_NAME			"Drupal 7 $S$ SHA-512"
#if ARCH_BITS >= 64
#define ALGORITHM_NAME			"64/" ARCH_BITS_STR
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		" (x16385)"
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		63
#define CIPHERTEXT_LENGTH		55

#define DIGEST_SIZE			(512/8)

#define BINARY_SIZE			(258/8) // ((258+7)/8)
#define SALT_SIZE			8

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"$S$CwkjgAKeSx2imSiN3SyBEg8e0sgE2QOx4a/VIfCHN0BZUNAWCr1X", "virtualabc"},
	{"$S$CFURCPa.k6FAEbJPgejaW4nijv7rYgGc4dUJtChQtV4KLJTPTC/u", "password"},
	{"$S$C6x2r.aW5Nkg7st6/u.IKWjTerHXscjPtu4spwhCVZlP89UKcbb/", "NEW_TEMP_PASSWORD"},
	{NULL}
};

#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE			8
#endif

static unsigned char *cursalt;
static unsigned loopCnt;
static unsigned char (*EncKey)[PLAINTEXT_LENGTH + 1];
static unsigned int *EncKeyLen;
static char (*crypt_key)[DIGEST_SIZE];

static void init(struct fmt_main *pFmt)
{
#if defined (_OPENMP)
	int omp_t;

	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	EncKey = mem_calloc_tiny(sizeof(*EncKey) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	EncKeyLen = mem_calloc_tiny(sizeof(*EncKeyLen) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;
	unsigned count_log2;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	if (strncmp(ciphertext, "$S$", 3) != 0)
		return 0;
	for (i = 3; i < CIPHERTEXT_LENGTH; ++i)
		if (atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
	if (count_log2 < 7 || count_log2 > 31)
		return 0;

	return 1;
}

static void set_salt(void *salt)
{
	loopCnt = (1 << (atoi64[ARCH_INDEX(((char*)salt)[8])]));
	cursalt = salt;
}

static void set_key(char *key, int index)
{
	int len;

	len = strlen(key);
	EncKeyLen[index] = len;
	memcpy(((char*)EncKey[index]), key, len + 1);
}

static char *get_key(int index)
{
	return (char*)EncKey[index];
}

static int cmp_all(void *binary, int count)
{
	int index;

	for(index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		SHA512_CTX ctx;
		unsigned char tmp[DIGEST_SIZE + PLAINTEXT_LENGTH];
		int len = EncKeyLen[index];
		unsigned Lcount = loopCnt - 1;

		SHA512_Init( &ctx );
		SHA512_Update( &ctx, cursalt, 8 );
		SHA512_Update( &ctx, EncKey[index], len );
		memcpy(&tmp[DIGEST_SIZE], (char *)EncKey[index], len);
		SHA512_Final( tmp, &ctx);

		len += DIGEST_SIZE;

		do {
			SHA512_Init( &ctx );
			SHA512_Update( &ctx, tmp, len);
			SHA512_Final( tmp, &ctx);
		} while (--Lcount);
		SHA512_Init( &ctx );
		SHA512_Update( &ctx, tmp, len);
		SHA512_Final( (unsigned char *) crypt_key[index], &ctx);
	}
}

static void * binary(char *ciphertext)
{
	int i;
	unsigned sixbits;
	static unsigned char b[BINARY_SIZE + 1];
	int bidx=0;
	char *pos;

	pos = &ciphertext[3 + 1 + 8];
	for (i = 0; i < 10; ++i) {
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits<<6);
		sixbits >>= 2;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits<<4);
		sixbits >>= 4;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits<<2);
	}
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx++] |= (sixbits<<6);
	sixbits >>= 2;
	b[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx++] |= (sixbits<<4);
	return b;
}

static void * salt(char *ciphertext)
{
	static unsigned long salt_[(SALT_SIZE/sizeof(unsigned long))+1];
	unsigned char *salt = (unsigned char*)salt_;
	// store off the 'real' 8 bytes of salt
	memcpy(salt, &ciphertext[4], 8);
	// append the 1 byte of loop count information.
	salt[8] = ciphertext[3];
	return salt;
}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }

static int get_hash_0(int index) { return *((ARCH_WORD_32 *)&crypt_key[index]) & 0xf; }
static int get_hash_1(int index) { return *((ARCH_WORD_32 *)&crypt_key[index]) & 0xff; }
static int get_hash_2(int index) { return *((ARCH_WORD_32 *)&crypt_key[index]) & 0xfff; }
static int get_hash_3(int index) { return *((ARCH_WORD_32 *)&crypt_key[index]) & 0xffff; }
static int get_hash_4(int index) { return *((ARCH_WORD_32 *)&crypt_key[index]) & 0xfffff; }

static int salt_hash(void *salt)
{
	return *((ARCH_WORD *)salt) & 0x3FF;
}

struct fmt_main fmt_drupal7 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		// true salt is SALT_SIZE but we add the loop count
		SALT_SIZE + 1,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
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
		cmp_one,
		cmp_exact
	}
};

#else
#ifdef __GNUC__
#warning Note: Drupal7 format disabled - it needs OpenSSL 0.9.8 or above
#endif
#endif

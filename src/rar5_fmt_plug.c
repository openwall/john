/* RAR 5.0 cracker patch for JtR. Hacked together during May of 2013 by Dhiru
 * Kholia.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the
 * following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"
#include "johnswap.h"
#include "stdint.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               1 // tuned on core i7
#endif

#define SIZE_SALT50 16
#define SIZE_PSWCHECK 8
#define SIZE_PSWCHECK_CSUM 4
#define SIZE_INITV 16

#define FORMAT_LABEL		"RAR5"
#define FORMAT_NAME		"PBKDF2 SHA-256"
#define FORMAT_TAG  		"$rar5$"
#define TAG_LENGTH  		6
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		SIZE_PSWCHECK
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define SHA256_DIGEST_SIZE      32

static struct fmt_tests rar5_tests[] = {
	{"$rar5$16$37526a0922b4adcc32f8fed5d51bb6c8$16$8955617d9b801def51d734095bb8ecdb$8$9f0b23c98ebb3653", "password"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int version;
	int hp;
	int saltlen;
	int ivlen;
	unsigned int iterations;
	unsigned char salt[32];
	unsigned char iv[32];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;
	return 1;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	ctcopy += TAG_LENGTH;
	p = strtok(ctcopy, "$");
	cs.saltlen = atoi(p);
	p = strtok(NULL, "$");
	for (i = 0; i < cs.saltlen; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "$");
	cs.ivlen = atoi(p);
	p = strtok(NULL, "$");
	for (i = 0; i < cs.ivlen; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	cs.iterations = 1 << 15;
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void hmac_sha256(unsigned char * pass, int passlen, unsigned char * salt,
                        int saltlen, int add, unsigned char * ret)
{
	uint8_t i, ipad[64], opad[64];
	SHA256_CTX ctx;
	memset(ipad, 0x36, 64);
	memset(opad, 0x5c, 64);

	for (i = 0; i < passlen; i++) {
		ipad[i] ^= pass[i];
		opad[i] ^= pass[i];
	}

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ipad, 64);
	SHA256_Update(&ctx, salt, saltlen);
	SHA256_Final(ret, &ctx);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, opad, 64);
	SHA256_Update(&ctx, ret, 32);
	SHA256_Final(ret, &ctx);
}


#define  Min(x,y) (((x)<(y)) ? (x):(y))
// PBKDF2 for 32 unsigned char key length. We generate the key for specified number
// of iteration count also as two supplementary values (key for checksums
// and password verification) for iterations+16 and iterations+32.
static void rar5kdf(unsigned char *Pwd, size_t PwdLength,
            unsigned char *Salt, size_t SaltLength,
            unsigned char *Key, unsigned char *V1, unsigned char *V2, int Count)
{
	const size_t MaxSalt=64;
	unsigned char SaltData[MaxSalt+4];
	unsigned char U1[SHA256_DIGEST_SIZE];
	unsigned char U2[SHA256_DIGEST_SIZE];
	int I;
	int J;
	int K;
	int CurCount[] = { Count-1, 16, 16 };
	unsigned char *CurValue[] = { Key    , V1, V2 };
	unsigned char Fn[SHA256_DIGEST_SIZE]; // Current function value.
	memcpy(SaltData, Salt, Min(SaltLength,MaxSalt));

	SaltData[SaltLength + 0] = 0; // Salt concatenated to 1.
	SaltData[SaltLength + 1] = 0;
	SaltData[SaltLength + 2] = 0;
	SaltData[SaltLength + 3] = 1;

	// First iteration: HMAC of password, salt and block index (1).
	hmac_sha256(Pwd, PwdLength, SaltData, SaltLength + 4, 0, U1);
	memcpy(Fn, U1, sizeof(Fn)); // Function at first iteration.

	for (I = 0; I < 3; I++) // For output key and 2 supplementary values.
	{
		for (J = 0; J < CurCount[I]; J++) {
			hmac_sha256(Pwd, PwdLength, U1, sizeof(U1), 1, U2); // U2 = PRF (P, U1).
			memcpy(U1, U2, sizeof(U1));
			for (K = 0; K < sizeof(Fn); K++) // Function ^= U.
				Fn[K] ^= U1[K];
		}
		memcpy(CurValue[I], Fn, SHA256_DIGEST_SIZE);
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char Key[32],PswCheckValue[SHA256_DIGEST_SIZE],HashKeyValue[SHA256_DIGEST_SIZE];
		char *password = saved_key[index];
		unsigned char PswCheck[SHA256_DIGEST_SIZE];
		int i;
		rar5kdf((unsigned char*)password, strlen(password),
				cur_salt->salt, SIZE_SALT50,
				Key, HashKeyValue, PswCheckValue,
				cur_salt->iterations);
		// special wtf processing
		memset(PswCheck, 0, SIZE_PSWCHECK);
		for (i = 0; i <SHA256_DIGEST_SIZE; i++)
			PswCheck[i % SIZE_PSWCHECK] ^= PswCheckValue[i];

		memcpy((unsigned char*)crypt_out[index], PswCheck, SIZE_PSWCHECK);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void rar5_set_key(char *key, int index)
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

struct fmt_main fmt_rar5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		rar5_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		fmt_default_source,
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
		set_salt,
		rar5_set_key,
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
		cmp_exact
	}
};

/* This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Based on hmac-sha512 by magnum
 *
 * Minor fixes, format unification and OMP support done by Dhiru Kholia <dhiru@openwall.com> */

#include <ctype.h>
#include <string.h>
#include <assert.h>
#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "sha2.h"

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int
#define uint64_t		unsigned long long int

#define FORMAT_LABEL		"pbkdf2-hmac-sha512"
#define FORMAT_TAG		"$pbkdf2-hmac-sha512$"
#define FORMAT_NAME		"GRUB2 / OS X 10.8 pbkdf2-hmac-sha512"
#define ALGORITHM_NAME		"PBKDF2-SHA512 CPU"
#define BINARY_SIZE		64
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define KEYS_PER_CRYPT		1
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif

#define PAD_SIZE		128
#define PLAINTEXT_LENGTH	15
#define BINARY_SIZE		64
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN(a,b)		(((a)<(b))?(a):(b))
#define MAX(a,b)		(((a)>(b))?(a):(b))

// #define DEBUG

static struct fmt_tests tests[] = {
	/* Mountain Lion hashes */
	{"$pbkdf2-hmac-sha512$23923.c3fa2e153466f7619286024fe7d812d0a8ae836295f84b9133ccc65456519fc3.ccb903ee691ade6d5dee9b3c6931ebed6ddbb1348f1b26c21add8ba0d45f27e61e97c0b80d9a18020944bb78f1ebda6fdd79c5cf08a12c80522caf987c287b6d", "openwall"},
	{"$pbkdf2-hmac-sha512$37174.ef768765ba15907760b71789fe62436e3584dfadbbf1eb8bf98673b60ff4e12b.294d42f6e0c3a93d598340bfb256efd630b53f32173c2b0d278eafab3753c10ec57b7d66e0fa79be3b80b3693e515cdd06e9e9d26d665b830159dcae152ad156", "m\xC3\xBCller"},
	{"$pbkdf2-hmac-sha512$24213.db9168b655339be3ff8936d2cf3cb573bdf7d40afd9a17fca439a0fae1375960.471a868524d66d995c6a8b7a0d27bbbc1af0c203f1ac31e7ceb2fde92f94997b887b38131ac2b543d285674dce639560997136c9af91916a2865ba960762196f", "applecrap"},
	/* GRUB hashes */
	{"$pbkdf2-hmac-sha512$10000.82DBAB96E072834D1F725DB9ADED51E703F1D449E77D01F6BE65147A765C997D8865A1F1AB50856AA3B08D25A5602FE538AD0757B8CA2933FE8CA9E7601B3FBF.859D65960E6D05C6858F3D63FA35C6ADFC456637B4A0A90F6AFA7D8E217CE2D3DFDC56C8DEACA217F0864AE1EFB4A09B00EB84CF9E4A2723534F34E26A279193", "openwall"},
{NULL}
};

static struct custom_salt {
	uint8_t length;
	uint8_t salt[64];
	uint32_t rounds;
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, FORMAT_TAG, strlen(FORMAT_TAG));
}

static void bad_ciphertext(char *ciphertext)
{
	fprintf(stderr, "get_salt(%s) Error - probably ciphertext is broken\n",
	    ciphertext);
	exit(1);
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;

	char *p, *c = ciphertext;
	int saltlen;
	c += strlen(FORMAT_TAG);
	cs.rounds = atoi(c);
	assert(cs.rounds > 0);
#ifdef DEBUG
	printf("get_salt(%s)\n", ciphertext);
	printf("rounds=%d\n", cs.rounds);
#endif
	c = strchr(c, '.');
	if (c++ == NULL) {
		bad_ciphertext(ciphertext);
	}
	p = strchr(c, '.');
	if (p == NULL) {
		bad_ciphertext(ciphertext);
	}
	saltlen = 0;
	while (c < p) {			/** extract salt **/
		cs.salt[saltlen++] =
		    atoi16[tolower(c[0])] * 16 + atoi16[tolower(c[1])];
		c += 2;
	}
	cs.length = saltlen;
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
	p = strrchr(ciphertext, '.') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
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

static void hmac_sha512(uint8_t * pass, uint8_t passlen, uint8_t * salt,
    uint8_t saltlen, uint32_t add, uint64_t * ret)
{
	uint8_t i, ipad[PAD_SIZE], opad[PAD_SIZE];
	SHA512_CTX ctx;
	memset(ipad, 0x36, PAD_SIZE);
	memset(opad, 0x5c, PAD_SIZE);

	for (i = 0; i < passlen; i++) {
		ipad[i] ^= pass[i];
		opad[i] ^= pass[i];
	}

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, ipad, PAD_SIZE);
	SHA512_Update(&ctx, salt, saltlen);
	if (add > 0)
		SHA512_Update(&ctx, &add, 4);
	SHA512_Final((uint8_t *) ret, &ctx);

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, opad, PAD_SIZE);
	SHA512_Update(&ctx, (uint8_t *) ret, BINARY_SIZE);
	SHA512_Final((uint8_t *) ret, &ctx);
}


static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		int i, j, l;
		uint64_t tmp[BINARY_SIZE];
		uint64_t key[BINARY_SIZE];
		l = strlen(saved_key[index]);
		hmac_sha512((unsigned char*)saved_key[index], l,
		    (uint8_t *) cur_salt->salt, cur_salt->length, 0x01000000,
		    tmp);
		memcpy(key, tmp, BINARY_SIZE);

		for (i = 1; i < cur_salt->rounds; i++) {
			hmac_sha512((unsigned char*)saved_key[index], l,
			    (uint8_t *) tmp, BINARY_SIZE, 0, tmp);
			for (j = 0; j < 8; j++)
				key[j] ^= tmp[j];
		}

#ifdef	DEBUG
		printf("hash[%d]:", index);
		for (j = 0; j < 16; j++) {
			printf("%08x ", ((uint32_t *) key)[j]);
		}
		puts("");
#endif
		memcpy((unsigned char*)crypt_out[index], key, BINARY_SIZE);
	}
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

static void set_key(char *key, int index)
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

struct fmt_main fmt_pbkdf2_hmac_sha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		sizeof(ARCH_WORD_32),
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		sizeof(ARCH_WORD),
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		fmt_default_salt_hash,
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
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

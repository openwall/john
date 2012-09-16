/* WoltLab Burning Board 3 (WBB3) cracker patch for JtR. Hacked together during
 * May of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format => user:$wbb3$*type*hash
 *
 * Where,
 *
 * type => 1, for sha1($salt.sha1($salt.sha1($pass))) hashing scheme
 *
 * JimF, July 2012.
 * Made small change in hex_encode 10x improvement in speed.  Also some other
 * changes.  Should be a thin dyanamic.
 */

#if defined(__APPLE__) && defined(__MACH__) && \
	defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && \
	__MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#else
#include "sha.h"
#endif

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               1
#endif

#define FORMAT_LABEL		"wbb3"
#define FORMAT_NAME		"WoltLab BB3 salted SHA-1"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1 /* change to 0 once there's any speedup for "many salts" */
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		20
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	64

static struct fmt_tests wbb3_tests[] = {
	{"$wbb3$*1*0b053db07dc02bc6f6e24e00462f17e3c550afa9*e2063f7c629d852302d3020599376016ff340399", "123456"},
	{"$wbb3$*1*0b053db07dc02bc6f6e24e00462f17e3c550afa9*f6975cc560c5d03feb702158d08f90bf2fa773d6", "password"},
	{"$wbb3$*1*a710463f75bf4568d398db32a53f9803007388a3*2c56d23b44eb122bb176dfa2a1452afaf89f1143", "123456"},
	{"$wbb3$*1*1039145e9e785ddb2ac7ccca89ac1b159b595cc1*2596b5f8e7cdaf4b15604ad336b810e8e2935b1d", "12345678"},
	{"$wbb3$*1*db763342e23f8ccdbd9c90d1cc7896d80b7e0a44*26496a87c1a7dd68f7beceb2fc40b6fc4223a453", "12345678"},
	{"$wbb3$*1*bf2c7d0c8fb6cb146adf8933e32da012d31b5bbb*d945c02cf85738b7db4f4f05edd676283280a513", "123456789"},
	{"$wbb3$*1*d132b22d3f1d942b99cc1f5fbd5cc3eb0824d608*e3e03fe02223c5030e834f81997f614b43441853", "1234567890"},
	{NULL}
};


static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int type;
	unsigned char salt[41];
} *cur_salt;

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	static int omp_t = 1;
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
	return !strncmp(ciphertext, "$wbb3$", 6);
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char _ctcopy[256], *ctcopy = _ctcopy;
	char *p;

	strnzcpy(ctcopy, ciphertext, 255);
	ctcopy += 7;	/* skip over "$wbb3$*" */
	p = strtok(ctcopy, "*");
	cs.type = atoi(p);
	p = strtok(NULL, "*");
	strcpy((char *)cs.salt, p);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '*') + 1;
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

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		unsigned char hexhash[40];
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
		hex_encode((unsigned char*)crypt_out[index], 20, hexhash);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->salt, 40);
		SHA1_Update(&ctx, hexhash, 40);
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
		hex_encode((unsigned char*)crypt_out[index], 20, hexhash);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->salt, 40);
		SHA1_Update(&ctx, hexhash, 40);
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (*((ARCH_WORD_32*)binary) == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *((ARCH_WORD_32*)binary) == crypt_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	void *binary = get_binary(source);
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static void wbb3_set_key(char *key, int index)
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

struct fmt_main wbb3_fmt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		wbb3_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		wbb3_set_key,
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

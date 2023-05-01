/*
 * WoltLab Burning Board 3 (WBB3) cracker patch for JtR. Hacked together during
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
 * JimF, July 2012. Made small change in hex_encode 10x improvement in speed.
 * Also some other changes. This should be a thin dyanamic.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_wbb3;
#elif FMT_REGISTERS_H
john_register_one(&fmt_wbb3);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               8  // MKPC and OMP_SCALE tuned on Core i5-6500

#include "arch.h"
#include "sha.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "wbb3"
#define FORMAT_NAME             "WoltLab BB3"
#define FORMAT_TAG              "$wbb3$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        32
#define BINARY_SIZE             20
#define MAX_SALT_LEN            40
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

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
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
static unsigned char (*hexhash1)[40];
static int dirty;

static struct custom_salt {
	int type;
	unsigned char salt[MAX_SALT_LEN+1];
} *cur_salt;

inline static void hex_encode(unsigned char *str, int len, unsigned char *out)
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
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
	hexhash1 = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*hexhash1));
}

static void done(void)
{
	MEM_FREE(hexhash1);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char _ctcopy[256], *ctcopy = _ctcopy;
	char *p;
	int res, extra;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	strnzcpy(ctcopy, ciphertext, 255);
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*"); /* type */
	if (!p)
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	res = strlen(p);
	if (res > MAX_SALT_LEN || !ishexlc_oddOK(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* hash */
		goto err;
	if (hexlenl(p, &extra) != BINARY_SIZE * 2 || extra)
		goto err;

	return 1;

err:
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char _ctcopy[256], *ctcopy = _ctcopy;
	char *p;

	memset(&cs, 0, sizeof(cs));
	strnzcpy(ctcopy, ciphertext, 255);
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$wbb3$*" */
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
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

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char hexhash[40];
		SHA_CTX ctx;

		if (dirty) {
			unsigned char out[20];
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, saved_key[index], strlen(saved_key[index]));
			SHA1_Final(out, &ctx);
			hex_encode(out, 20, hexhash1[index]);
		}
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->salt, 40);
		SHA1_Update(&ctx, hexhash1[index], 40);
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
		hex_encode((unsigned char*)crypt_out[index], 20, hexhash);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->salt, 40);
		SHA1_Update(&ctx, hexhash, 40);
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
	}
	dirty = 0;

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*((uint32_t*)binary) == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *((uint32_t*)binary) == crypt_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	void *binary = get_binary(source);
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static void wbb3_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
	dirty = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_wbb3 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG },
		wbb3_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		wbb3_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

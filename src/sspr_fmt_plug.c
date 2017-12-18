/*
 * Format for cracking NetIQ SSPR hashes.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Special thanks goes to https://github.com/crypticgeek for documenting the
 * "SHA1_SALT" hashing scheme.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sspr;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sspr);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               4
#endif
#endif

#include "formats.h"
#include "md5.h"
#include "sha.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "memdbg.h"

#define FORMAT_LABEL            "sspr"
#define FORMAT_NAME             "NetIQ SSPR"
#define FORMAT_TAG              "$sspr$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5/SHA1/SHA256/SHA512 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             64
#define BINARY_SIZE_MIN         16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define MAX_SALT_LEN            1500

static struct fmt_tests tests[] = {
	{"$sspr$2$100000$tMR6sNepv6M6nOqOy3SWnAUWo22p0GI7$f0ae3140ce2cf46c13d0b6c4bd4fab65b45b27c0", "openwall@123"},
	{"$sspr$2$100000$BrWV47lSy3Mwpp8pb60ZlJS85YS242bo$1f71c58c8dfc16c9037d3cd1cf21d1139cad4fa4", "password@123"},
	{"$sspr$1$100000$NONE$64840051a425cbc0b4e2d3750d9e0de3e800de18", "password@12345"},
	{"$sspr$1$100000$NONE$5cd2aeb3adf2baeca485672f01486775a208a40e", "openwall@12345"},
	{"$sspr$0$100000$NONE$1e6172e71e6af1c15f4c5ca658815835", "abc@12345"},
	{"$sspr$0$100000$NONE$1117af8ec9f70e8eed192c6c01776b6b", "abc@123"},
	{"$sspr$3$100000$blwmhFBUiq67iEX9WFc8EG8mCxWL4tCR$c0706a057dfdb5d31d6dd40f060c8982e1e134fdf1e7eb0d299009c2f56c1936", "hello@12345"},
	{"$sspr$3$100000$lNInqvnmbv9x65N2ltQeCialILG8Fr47$6bd508dcc2a5626c9d7ab3296bcce0538ca0ba24bf43cd2aebe2f58705814a00", "abc@123"},
	{"$sspr$4$100000$ZP3ftUBQwrovglISxt9ujUtwslsSMCjj$a2a89e0e185f2a32f18512415e4dfc379629f0222ead58f0207e9c9f7424c36fe9c7a615be6035849c11da1293da78e50e725a664b7f5fe123ede7871f13ae7f", "hello@123"},
	{"$sspr$4$100000$ZzhxK3gHP8HVkcELqIeybuRWvZjDirtg$ca5608befc50075bc4a1441de23beb4a034197d70df670addabc62a4a4d26b2e78ee38c50e9d18ce55d31b00fbb9916af12e80bf3e395ff38e58f8a958427602", "hello@12345"},
	{"$sspr$2$100000$4YtbuUHaTSHBuE1licTV16KjSZuMMMCn$23b3cf4e1a951b2ed9d5df43632f77092fa93128", "\xe4""bc@123"},  // original password was "äbc@123", application uses a code page
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	uint32_t iterations;
	uint32_t saltlen;
	uint32_t fmt;
	char salt[MAX_SALT_LEN];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int threads = omp_get_max_threads();

	if (threads > 1) {
		self->params.min_keys_per_crypt *= threads;
		threads *= OMP_SCALE;
		self->params.max_keys_per_crypt *= threads;
	}
#endif
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
        MEM_FREE(saved_key);
        MEM_FREE(crypt_out);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)  // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0 && value != 1 && value != 2 && value != 3 && value != 4)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)  // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)  // salt
		goto err;
	if (strlen(p) > MAX_SALT_LEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)  // binary
		goto err;
	value = hexlenl(p, &extra);
	if (value < BINARY_SIZE_MIN * 2 || value > BINARY_SIZE * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.fmt = atoi(p);
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "$");
	cs.saltlen = strlen(p);
	strncpy(cs.salt, p, MAX_SALT_LEN);

	MEM_FREE(keeptr);

	return &cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	memset(buf.c, 0, BINARY_SIZE);
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE_MIN; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		uint32_t c;
		SHA_CTX ctx;
		SHA256_CTX sctx;
		SHA512_CTX sctx2;
		MD5_CTX mctx;
		unsigned char buf[64];

		if (cur_salt->fmt == 0) {
			MD5_Init(&mctx);
			MD5_Update(&mctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			MD5_Final(buf, &mctx);
			for (c = 1; c < cur_salt->iterations; c++) {
				MD5_Init(&mctx);
				MD5_Update(&mctx, buf, 16);
				MD5_Final(buf, &mctx);
			}
		} else if (cur_salt->fmt == 1) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			SHA1_Final(buf, &ctx);
			for (c = 1; c < cur_salt->iterations; c++) {
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, buf, 20);
				SHA1_Final(buf, &ctx);
			}
		} else if (cur_salt->fmt == 2) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, cur_salt->salt, cur_salt->saltlen);
			SHA1_Update(&ctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			SHA1_Final(buf, &ctx);
			for (c = 1; c < cur_salt->iterations; c++) {
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, buf, 20);
				SHA1_Final(buf, &ctx);
			}
		} else if (cur_salt->fmt == 3) {
			SHA256_Init(&sctx);
			SHA256_Update(&sctx, cur_salt->salt, cur_salt->saltlen);
			SHA256_Update(&sctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			SHA256_Final(buf, &sctx);
			for (c = 1; c < cur_salt->iterations; c++) {
				SHA256_Init(&sctx);
				SHA256_Update(&sctx, buf, 32);
				SHA256_Final(buf, &sctx);
			}
		} else if (cur_salt->fmt == 4) {
			SHA512_Init(&sctx2);
			SHA512_Update(&sctx2, cur_salt->salt, cur_salt->saltlen);
			SHA512_Update(&sctx2, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			SHA512_Final(buf, &sctx2);
			for (c = 1; c < cur_salt->iterations; c++) {
				SHA512_Init(&sctx2);
				SHA512_Update(&sctx2, buf, 64);
				SHA512_Final(buf, &sctx2);
			}
		}
		memcpy(crypt_out[index], buf, BINARY_SIZE_MIN);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE_MIN);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void sspr_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int get_kdf_type(void *salt)
{
	return ((struct custom_salt *)salt)->fmt;
}

struct fmt_main fmt_sspr = {
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
		{
			"KDF [0:MD5 1:SHA1 2:SHA1_SALT 3:SHA256_SALT 4:SHA512_SALT]",
		},
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			get_kdf_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		sspr_set_key,
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

#endif /* plugin stanza */

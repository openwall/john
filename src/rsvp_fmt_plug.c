/*
 * Cracker for HMAC-MD5 and HMAC-SHA1 based authentication in RSVP.
 *
 * This software is Copyright (c) 2014 Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without#
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rsvp;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rsvp);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE 4096
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE 8192
#endif
#endif // __MIC__
#endif

#include "arch.h"
#include "md5.h"
#include "sha.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"
#include "memdbg.h"

#define FORMAT_LABEL            "rsvp"
#define FORMAT_NAME             "HMAC-MD5 / HMAC-SHA1, RSVP, IS-IS"
#define FORMAT_TAG              "$rsvp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define HEXCHARS                "0123456789abcdef"
#define MAX_SALT_SIZE           8192
// currently only 2 types, 1 for md5 and 2 for SHA1. Bump this
// number each type a type is added, and make sure the types
// are sequential.
#define MAX_TYPES               2

static struct fmt_tests tests[] = {
	{"$rsvp$1$10010000ff0000ac002404010100000000000001d7e95bfa0000003a00000000000000000000000000000000000c0101c0a8011406000017000c0301c0a8010a020004020008050100007530000c0b01c0a8010a0000000000240c0200000007010000067f00000545fa000046fa000045fa0000000000007fffffff00300d020000000a010000080400000100000001060000014998968008000001000000000a000001000005dc05000000$636d8e6db5351fbc9dad620c5ec16c0b", "password12345"},
	{"$rsvp$2$10010000ff0000b0002804010100000000000001d7e95bfa0000055d0000000000000000000000000000000000000000000c0101c0a8011406000017000c0301c0a8010a020004020008050100007530000c0b01c0a8010a0000000000240c0200000007010000067f00000545fa000046fa000045fa0000000000007fffffff00300d020000000a010000080400000100000001060000014998968008000001000000000a000001000005dc05000000$ab63f157e601742983b853f13a63bc4d4379a434", "JtR_kicks_ass"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;

// when we add more types, they need to be sequential (next will be 3),
// AND we need to bump this to the count. Each type will use one of these
// to track whether it has build the first half of the hmac.  The size
// of this array should be 1 more than the max number of types.
static int new_keys[MAX_TYPES+1];

// we make our crypt_out large enough for an SHA1 output now.  Even though
// we only compare first BINARY_SIZE data.
static ARCH_WORD_32 (*crypt_out)[ (BINARY_SIZE+4) / sizeof(ARCH_WORD_32)];
static SHA_CTX *ipad_ctx;
static SHA_CTX *opad_ctx;
static MD5_CTX *ipad_mctx;
static MD5_CTX *opad_mctx;

static  struct custom_salt {
	int type;
	int salt_length;
	unsigned char salt[MAX_SALT_SIZE];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_num_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
	ipad_ctx  = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_ctx));
	opad_ctx  = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_ctx));
	ipad_mctx = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_mctx));
	opad_mctx = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_mctx));
}

static void done(void)
{
	MEM_FREE(opad_mctx);
	MEM_FREE(ipad_mctx);
	MEM_FREE(opad_ctx);
	MEM_FREE(ipad_ctx);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *strkeep;
	int version;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;
	strkeep = strdup(ciphertext);
	p = &strkeep[TAG_LENGTH];

	if ((p = strtokm(p, "$")) == NULL) /* version */
		goto err;
	version = atoi(p);
	if (version != 1  && version != 2)
		goto err;

	if ((p = strtokm(NULL, "$")) == NULL) /* salt */
		goto err;
	if (strlen(p) >= MAX_SALT_SIZE*2)
		goto err;
	if (!ishex(p))
		goto err;

	if ((p = strtokm(NULL, "$")) == NULL) /* hash */
		goto err;
	/* there is code that trim longer binary values, so we do not need to check for extra long */
	if (strlen(p) < BINARY_SIZE*2)
		goto err;
	if (!ishex(p))
		goto err;

	MEM_FREE(strkeep);
	return 1;
err:;
	MEM_FREE(strkeep);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p, *q;

	memset(&cs, 0, SALT_SIZE);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	p = ciphertext;
	cs.type = atoi(p);
	p = p + 2;
	q = strchr(p, '$') + 1;
	cs.salt_length = (q - p) / 2;

	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) |
			atoi16[ARCH_INDEX(p[2 * i + 1])];

	return (void*)&cs;
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char buf[20];
		if (cur_salt->type == 1) {
			MD5_CTX ctx;
			if (new_keys[cur_salt->type]) {
				int i, len = strlen(saved_key[index]);
				unsigned char *p = (unsigned char*)saved_key[index];
				unsigned char pad[64];

				if (len > 64) {
					MD5_Init(&ctx);
					MD5_Update(&ctx, p, len);
					MD5_Final(buf, &ctx);
					len = 16;
					p = buf;
				}
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x36;
				}
				MD5_Init(&ipad_mctx[index]);
				MD5_Update(&ipad_mctx[index], pad, len);
				if (len < 64)
					MD5_Update(&ipad_mctx[index], "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36", 64-len);
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x5C;
				}
				MD5_Init(&opad_mctx[index]);
				MD5_Update(&opad_mctx[index], pad, len);
				if (len < 64)
					MD5_Update(&opad_mctx[index], "\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C", 64-len);
			}
			memcpy(&ctx, &ipad_mctx[index], sizeof(ctx));
			MD5_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
			MD5_Final(buf, &ctx);
			memcpy(&ctx, &opad_mctx[index], sizeof(ctx));
			MD5_Update(&ctx, buf, 16);
			MD5_Final((unsigned char*)(crypt_out[index]), &ctx);
		} else if (cur_salt->type == 2) {
			SHA_CTX ctx;
			if (new_keys[cur_salt->type]) {
				int i, len = strlen(saved_key[index]);
				unsigned char *p = (unsigned char*)saved_key[index];
				unsigned char pad[64];

				if (len > 64) {
					SHA1_Init(&ctx);
					SHA1_Update(&ctx, p, len);
					SHA1_Final(buf, &ctx);
					len = 20;
					p = buf;
				}
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x36;
				}
				SHA1_Init(&ipad_ctx[index]);
				SHA1_Update(&ipad_ctx[index], pad, len);
				if (len < 64)
					SHA1_Update(&ipad_ctx[index], "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36", 64-len);
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x5C;
				}
				SHA1_Init(&opad_ctx[index]);
				SHA1_Update(&opad_ctx[index], pad, len);
				if (len < 64)
					SHA1_Update(&opad_ctx[index], "\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C", 64-len);
			}
			memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
			SHA1_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
			SHA1_Final(buf, &ctx);
			memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
			SHA1_Update(&ctx, buf, 20);
			// NOTE, this writes 20 bytes. That is why we had to bump up the size of each crypt_out[] value,
			// even though we only look at the first 16 bytes when comparing the saved binary.
			SHA1_Final((unsigned char*)(crypt_out[index]), &ctx);
		}

	}
	new_keys[cur_salt->type] = 0;

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (((ARCH_WORD_32*)binary)[0] == crypt_out[index][0])
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

static void rsvp_set_key(char *key, int index)
{
	saved_len[index] = strlen(key);
	strncpy(saved_key[index], key, sizeof(saved_key[0]));

	// Workaround for self-test code not working as IRL
	new_keys[1] = new_keys[2] = 2;
}

static void clear_keys(void) {
	int i;
	for (i = 0; i <= MAX_TYPES; ++i)
		new_keys[i] = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

#if FMT_MAIN_VERSION > 11
/*
 * report hash algorithm used for hmac as "tunable cost"
 */
static unsigned int rsvp_hash_type(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->type;
}
#endif
struct fmt_main fmt_rsvp = {
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
#if FMT_MAIN_VERSION > 11
		{
			"hash algorithm used for hmac [1:MD5 2:SHA1]"
		},
#endif
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
#if FMT_MAIN_VERSION > 11
		{
			rsvp_hash_type,
		},
#endif
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
		rsvp_set_key,
		get_key,
		clear_keys,
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

#endif

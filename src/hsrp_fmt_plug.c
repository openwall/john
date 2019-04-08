/*
 * Cracker for MD5 authentication in HSRP, HSRPv2, VRRP, and GLBP.
 * http://www.rfc-editor.org/rfc/rfc1828.txt
 *
 * This is dedicated to Darya. You inspire me.
 *
 * This software is Copyright (c) 2014, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Optimized in Feb 2016, JimF.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_hsrp;
#elif FMT_REGISTERS_H
john_register_one(&fmt_hsrp);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "hsrp"
#define FORMAT_NAME             "\"MD5 authentication\" HSRP, HSRPv2, VRRP, GLBP"
#define FORMAT_TAG              "$hsrp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        55 // Must fit in a single MD5 block
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define REAL_SALT_SIZE          50
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      256

#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE 32
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE 8 // Tuned w/ MKPC for core i7
#endif
#endif

static struct fmt_tests tests[] = {
	{"$hsrp$000004030a64010000000000000000000a000064041c010000000a0000140000000000000000000000000000000000000000$52e1db09d18d695b8fefb3730ff8d9d6", "password12345"},
	{"$hsrp$000004030a5a01000000000000000000ac102801041c01000000ac1028140000000000000000000000000000000000000000$f15dfa631a0679e0801f8e6b0c0c17ac", "openwall"},
	{"$hsrp$000010030a64010000000000000000000a000064041c010000000a0000140000000000000000000000000000000000000000$f02fc41b1b516e2d1261d8800d39ccea", "openwall12345"},
	/* HSRPv2 hashes */
	{"$hsrp$0128020006040001aabbcc000a000000006400000bb8000027100a000064000000000000000000000000041c010000000a00000a0000000000000000000000000000000000000000$642fedafe1f374bd2fdd8f1ba81d87a2", "password"},
	{"$hsrp$0128020006040001aabbcc001400000000c800000bb8000027100a000064000000000000000000000000041c010000000a0000140000000000000000000000000000000000000000$0481257f0fe583b275f03a48e88de72f", "password12345"},
	{NULL}
};

static char (*saved_key)[64];	// 1 full limb of MD5, we do out work IN this buffer.
static MD5_CTX (*saved_ctx);
static int *saved_len, dirty;
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	int length;
	unsigned char salt[2048];  // be safe ;)
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
	saved_ctx = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_ctx));
}

static void done(void)
{
	MEM_FREE(saved_ctx);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q = NULL;
	int len;

	p = ciphertext;

	if (strncmp(p, FORMAT_TAG, TAG_LENGTH))
		return 0;

	p += TAG_LENGTH;

	q = strrchr(ciphertext, '$');
	if (!q || q+1==p)
		return 0;
	q = q + 1;
	// if ((q - p - 1) > REAL_SALT_SIZE * 2)
	//	return 0;

	len = strspn(q, HEXCHARS_lc);
	if (len != BINARY_SIZE * 2 || len != strlen(q))
		return 0;

	if (strspn(p, HEXCHARS_lc) != q - p - 1)
		return 0;

	if (q-p > (sizeof(cur_salt->salt)-1)*2)
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i, len;

	memset(&cs, 0, SALT_SIZE);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	len = (strrchr(ciphertext, '$') - ciphertext) / 2;

	for (i = 0; i < len; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(ciphertext[2 * i])] << 4) |
			atoi16[ARCH_INDEX(ciphertext[2 * i + 1])];

	cs.length = len;

	return &cs;
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

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#define PUTCHAR(buf, index, val) ((unsigned char*)(buf))[index] = (val)

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		MD5_CTX ctx;
		int len = saved_len[index];
		if (dirty) {
			// we use the saved_key buffer in-line.
			unsigned int *block = (unsigned int*)saved_key[index];
			MD5_Init(&saved_ctx[index]);
			// set bit
			saved_key[index][len] = 0x80;
			block[14] = len << 3;
#if !ARCH_LITTLE_ENDIAN
			block[14] = JOHNSWAP(block[14]);
#endif
			MD5_Update(&saved_ctx[index], (unsigned char*)block, 64);
			// clear the bit, so that get_key returns proper key.
			saved_key[index][len] = 0;
		}
		memcpy(&ctx, &saved_ctx[index], sizeof(MD5_CTX));
		// data
		MD5_Update(&ctx, cur_salt->salt, cur_salt->length);
		// key (again)
		MD5_Update(&ctx, saved_key[index], len);

		MD5_Final((unsigned char*)crypt_out[index], &ctx);
	}
	dirty = 0;

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
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

static void hsrp_set_key(char *key, int index)
{
	int olen = saved_len[index];
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
	if (olen > saved_len[index])
		memset(&(saved_key[index][saved_len[index]]), 0, olen-saved_len[index]);
	dirty = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_hsrp = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
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
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		hsrp_set_key,
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

#endif

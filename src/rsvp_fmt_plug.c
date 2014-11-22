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
#define OMP_SCALE 2048 // XXX
#endif

#include "arch.h"
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"
#include "memdbg.h"
#include "hmacmd5.h"
#include "gladman_hmac.h"

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

static struct fmt_tests tests[] = {
	{"$rsvp$1$10010000ff0000ac002404010100000000000001d7e95bfa0000003a00000000000000000000000000000000000c0101c0a8011406000017000c0301c0a8010a020004020008050100007530000c0b01c0a8010a0000000000240c0200000007010000067f00000545fa000046fa000045fa0000000000007fffffff00300d020000000a010000080400000100000001060000014998968008000001000000000a000001000005dc05000000$636d8e6db5351fbc9dad620c5ec16c0b", "password12345"},
	{"$rsvp$2$10010000ff0000b0002804010100000000000001d7e95bfa0000055d0000000000000000000000000000000000000000000c0101c0a8011406000017000c0301c0a8010a020004020008050100007530000c0b01c0a8010a0000000000240c0200000007010000067f00000545fa000046fa000045fa0000000000007fffffff00300d020000000a010000080400000100000001060000014998968008000001000000000a000001000005dc05000000$ab63f157e601742983b853f13a63bc4d4379a434", "JtR_kicks_ass"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static  struct custom_salt {
	int type;
	int salt_length;
	unsigned char salt[8192];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_num_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
		self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_len = mem_calloc_tiny(sizeof(*saved_len) *
		self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
		self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}


// XXX improve me
static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q = NULL;
	int version;

	p = ciphertext;
	if (strncmp(p, FORMAT_TAG, TAG_LENGTH))
		return 0;
	p += TAG_LENGTH;
	if (!p)
		return 0;
	version = atoi(p);
	if (version != 1  && version != 2)
		return 0;

	q = strrchr(ciphertext, '$') + 1;
	if (!q)
		return 0;

	return 1;
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
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		if (cur_salt->type == 1) {
			HMACMD5Context ctx;

			hmac_md5_init_rfc2104((unsigned char*)saved_key[index], saved_len[index], &ctx);
			hmac_md5_update(cur_salt->salt, cur_salt->salt_length, &ctx);
			hmac_md5_final((unsigned char*)crypt_out[index], &ctx);
		} else if (cur_salt->type == 2) {
			hmac_sha1((unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->salt_length, (unsigned
						char*)crypt_out[index], 16); }

	}

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
			"hash algorithm used for hmac [1:MD5/2:SHA1]"
		},
#endif
		tests
	}, {
		init,
		fmt_default_done,
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
		set_salt,
		rsvp_set_key,
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

#endif

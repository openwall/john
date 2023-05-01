/*
 * iSCSI CHAP authentication cracker. Hacked together during September of 2012
 * by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Input Format : CHAP_N(username):$chap$id*challenge*response
 *
 * CHAP_I => id.
 *
 * References:
 *
 * https://download.samba.org/pub/pub/unpacked/ppp/pppd/chap-md5.c
 * http://www.blackhat.com/presentations/bh-usa-05/bh-us-05-Dwivedi-update.pdf
 * http://www.willhackforsushi.com/presentations/PEAP_Shmoocon2008_Wright_Antoniewicz.pdf
 *
 * https://tools.ietf.org/html/rfc2865 -> The CHAP challenge value is found in
 * the CHAP-Challenge Attribute (60) if present in the packet, otherwise in the
 * Request Authenticator field.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_chap;
#elif FMT_REGISTERS_H
john_register_one(&fmt_chap);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "md5.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "chap"
#define FORMAT_NAME             "iSCSI CHAP authentication / EAP-MD5"
#define FORMAT_TAG              "$chap$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        32
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#define SALT_SIZE               sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1024

#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE               2
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tune w/ MKPC for core i7
#endif
#endif

static struct fmt_tests chap_tests[] = {
	{"$chap$0*cc7e5247514551acdcbf782c4027bfb1*fdfdad5277812ae40956a66f3db23308", "password"},
	{"$chap$0*81a49cb700e8c2ee9bc3852a506406c3*8876e228962a999637eecc2423f55f07", "password"},
	{"$chap$0*e270954e7d84f99535dce2e5d7340a7d*4d64f587c7b5248406b939e1e9abeb74", "bar"},
	// EAP-MD5 hashes are also supported!
	{"$chap$2*d7ec2fff2ada437f9dcd4e3b0df44d50*1ffc6c2659bc5bb94144fd01eb756e37", "beaVIs"},
	{"$chap$2*00000000000000000000000000000000*9920418b3103652d3b80ffff04da5863", "bradtest"},
	// RADIUS EAP-MD5 hash
	{"$chap$1*266b0e9a58322f4d01ab25b35f879464*c9f9769597e320843f5f2af7b8f1c9bd", "S0cc3r"},
	// RADIUS CHAP authentication is supported too
	{"$chap$238*98437c9fd4cb5f446202c0b1ffab2592*050d578a292a4bfd9f030d2797919687", "hello"},
	// Wild hash cracked by JtR
	{"$chap$2*b73158a35a255d051758e95ed4abb2cdc69bb454110e827441213ddc8770e93ea141e1fc673e017e97eadc6b*7f3d71b4c0c6569d2fa26f4c14ac3cf0", "U$er1"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	unsigned char id; /* CHAP_I */
	unsigned char challenge[128]; /* CHAP_C */
	int challenge_length;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, extra;
	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* id */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* challenge */
		goto err;
	len = strlen(p);
	if (len > 256 || (len&1))
		goto err;
	if (hexlenl(p, &extra) != len || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* binary */
		goto err;
	if (hexlenl(p, &extra) != BINARY_SIZE*2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN; /* skip over "$chap$" */
	p = strtokm(ctcopy, "*");
	cs.id = atoi(p);
	p = strtokm(NULL, "*");
	cs.challenge_length = strlen(p) / 2;
	for (i = 0; i < cs.challenge_length; i++)
		cs.challenge[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
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
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out; /* CHAP_R */
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
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, &cur_salt->id, 1);
		MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		MD5_Update(&ctx, cur_salt->challenge, cur_salt->challenge_length);
		MD5_Final((unsigned char*)crypt_out[index], &ctx);
	}

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

static void chap_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_chap = {
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
		chap_tests
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
		chap_set_key,
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

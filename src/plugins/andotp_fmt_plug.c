/*
 * Format for cracking andOTP encrypted backups.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_andotp;
#elif FMT_REGISTERS_H
john_register_one(&fmt_andotp);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               256  // tuned on i7-7820HQ (fluctuates a lot)

#include "../formats.h"
#include "../misc.h"
#include "../common.h"
#include "../params.h"
#include "../options.h"
#include "../sha2.h"
#include "../aes_gcm.h"
#include "../memory.h"

#define FORMAT_LABEL            "andOTP"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$andotp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "SHA256 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507 // ciphertext length is a "cost"
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4  // tuned on i7-7820HQ

#define IVLEN                   12
#define TAGLEN                  16
#define MIN_CIPHERTEXT_LENGTH   2  // excluding IV + TAG
#define MAX_CIPHERTEXT_LENGTH   1024 * 1024  // 1 MiB

static struct fmt_tests tests[] = {
	{"$andotp$0*0fb35cdb85dc40cd30bb4a0a*2fa0*75e3406c9f3b6f534286ea892a6adcde", "1234"},
	{"$andotp$0*1b0a64375523b7719c57fa1b*c1dbb7f88c0d58dd4bdc0d087a49e5de9bc259be7a62745ddf0c57485c17a954761bb1fbdea1caba03238f5bb402774a92e6d00947d381209bf68bb186b7f1dfca76379b8d5fc94a556586c2dd80f2ba7dd1979915b3a1763776aaee030dc1e0999c3af6bad75817f8b3f148b54ecac9363aa1f2b42784d6fb1bc038eda505c06df4f4b321b9b3687991ee0703*e74dc16f22f5fb3546574f8883039e3f", "openwall123"},
	{"$andotp$0*e8c06f01931b2e7ba2415221*d32f0b766bceb1688b42e5397a47b574eeaa20413c01a81ac42f43efb22303b47d6f1a6289eebec86c4b6dfa7a2a27cf72788dc4d320a5243f2f5f4719b5bc19b341a30c33da2cd55a1ab3ba53ecf25e3fe1b05e413a55c071fa3bf82ab1835b575ca552d101a3c41f946faad405473849a9cb2e8887963a440cfb1e5a7611c2e33976b79205ba72dac7213a7c*89f234227d322b137ffb455f6350665c", "openwall"},
	{"$andotp$0*d5d82faa599a0aafde38918d*7b7f*3c244ae13d5b45198ed39bacc285f691", "åbc"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	uint32_t ctlen;
	unsigned char iv[IVLEN];
	unsigned char tag[TAGLEN];
	unsigned char ciphertext[MAX_CIPHERTEXT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(cracked);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version / type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // iv
		goto err;
	if (hexlenl(p, &extra) != IVLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
		goto err;
	if (hexlenl(p, &extra) < MIN_CIPHERTEXT_LENGTH * 2 || extra)
		goto err;
	if (hexlenl(p, &extra) > MAX_CIPHERTEXT_LENGTH * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // tag
		goto err;
	if (hexlenl(p, &extra) != TAGLEN * 2 || extra)
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
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	p = strtokm(NULL, "*");
	for (i = 0; i < IVLEN; i++)
		cs.iv[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.ctlen = strlen(p) / 2;
	for (i = 0; i < cs.ctlen; i++)
		cs.ciphertext[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < TAGLEN; i++)
		cs.tag[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);

	return &cs;
}

static int check_password(int index, struct custom_salt *cs)
{
	unsigned char key[32];
	int ret;
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, saved_key[index], saved_len[index]);
	SHA256_Final(key, &ctx);

	ret = aes_gcm_ad(key, 32, cs->iv, IVLEN, cs->ciphertext, cs->ctlen, NULL, 0, cur_salt->tag, NULL, 1);

	if (!ret)
		return 1;
	else
		return 0;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		if (check_password(index, cur_salt)) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_andotp = {
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
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
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

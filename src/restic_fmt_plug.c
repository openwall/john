/*
 * This software is Copyright (c) 2020, Jürgen Hötzel <juergen at hoetzel.info>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_restic;
#elif FMT_REGISTERS_H
john_register_one(&fmt_restic);
#endif

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "aes.h"
#include "arch.h"
#include "base64_convert.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "poly1305-donna/poly1305-donna.h"
#include "yescrypt/sysendian.h"
#include "yescrypt/yescrypt.h"

#define FORMAT_NAME "Restic Repository"
#define FORMAT_LABEL "restic"
#define FORMAT_TAG "$restic$"
#define TAG_LENGTH (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME "PBKDF2/scrypt Poly1305"
#define PLAINTEXT_LENGTH 125
#define BINARY_SIZE 16 /* MAC */
#define BINARY_ALIGN sizeof(uint32_t)
#define DATA_SIZE 160
#define SALT_ALIGN sizeof(uint32_t)
#define MAC_SIZE 16
#define NONCE_SIZE 16
#define BENCHMARK_COMMENT ""
#define BENCHMARK_LENGTH 7
#define MIN_KEYS_PER_CRYPT 1
#define MAX_KEYS_PER_CRYPT 1

static int max_threads;
static yescrypt_local_t *local;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
static uint64_t poly1305_key_mask[2];

typedef struct restic_salt {
	uint32_t N;
	uint32_t r;
	uint32_t p;
	char salt[64];
	unsigned char data[DATA_SIZE];
} restic_salt;

static restic_salt *cur_salt;

static struct fmt_tests restic_tests[] = {
	{
		"$restic$scrypt*8192*8*1*ed29ad65948797a275f15b1da36fdd2b0247a7772d69ecfdf21141d837fb0780b6fb48cf7ccc3e4146a105dee0df4851256e204671d97c718c7e6b4a7a8cfb75*879acc157daa013218fcccf6b60be20f1e52baa893698a589f026165f51bbb1da03b0a5db42885d8bcffb34030b0bb26716e9f7c950cccb674494d63d104ee8808e713a7d483a6a0ef36b14aaac652eaa3a92b12f9d7a4cfead72ed0a216ccaeb0ddf9c6e94aa84c82590ae9a6ffc1b48b4fba163635ffb4e0633de668827e567e8c834539ae18d750be6f8f86f12101b04ab926fa570038eb6f78ef6021c1b1",
		"penance"
	},
	{
		"$restic$scrypt*32768*8*5*e6dac36997999525fdeeb075434416047dab7d28b0c26f82fa44a469747659ecb86614e66b75151e0bd8acc2f8c7b29d258bf8e6a39d47455bd8d34e87622510*f82d75db1dc5087fb2bdb014bb51cf07b72b62d10cb164fb244b0358b9c1bbac3663f0ca3f00f12731dc3cc3b6c9de949dc74b31d22e515e55096d219d75babc798a9a7a47fc86034e6fe358a93a6b1eff71d2b791ecee3b775b2b910ecf55abef7d53e4a0fac08e5526f1c25eab06dcd26a1250cb37b7dc115391c680becce8a5e63bdbe2326626c88d16bece0d6dca51de89e43207ea6febc6e119486024a0",
		"password"
	},
	{NULL}
};

static void init(struct fmt_main *self)
{
	max_threads = 1;
	local = mem_alloc(sizeof(*local) * max_threads);
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_init_local(&local[i]);

	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));

	be64enc(&poly1305_key_mask[0], 0xFFFFFF0FFCFFFF0FULL);
	be64enc(&poly1305_key_mask[1], 0XFCFFFF0FFCFFFF0FULL);
}

static void done(void)
{
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_free_local(&local[i]);
	MEM_FREE(local);
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;

	if (((p = strtokm(ctcopy, "*")) == NULL) || (strcmp("scrypt", p) != 0))
		goto err;
	if (((p = strtokm(NULL, "*")) == NULL) || !isdec(p)) /* scrypt: N */
		goto err;
	if (((p = strtokm(NULL, "*")) == NULL) || !isdec(p)) /* scrypt: r */
		goto err;
	if (((p = strtokm(NULL, "*")) == NULL) || !isdec(p)) /* scrypt: p */
		goto err;
	if (((p = strtokm(NULL, "*")) == NULL) || !ishexn(p, 64)) /* scrypt: salt */
		goto err;
	if (((p = strtokm(NULL, "*")) == NULL) || !ishexn(p, 160)) /* restic: data */
		goto err;

	MEM_FREE(keeptr);
	return 1;
err:
	MEM_FREE(keeptr);
	return 0;
}

void *restic_get_binary(char *ciphertext)
{
	static unsigned char c[BINARY_SIZE];
	char *p;
	int i;
	p = strrchr(ciphertext, '*') + 1;
	// Restic design doc: If the password is incorrect or the key file has been tampered with,
	// the computed MAC will not match the last 16 bytes of the data
	p += (160 - 16) * 2;
	for (i = 0; i < BINARY_SIZE; i++) {
		c[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return c;
}

void *restic_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	restic_salt *cur_salt;

	cur_salt = mem_calloc_tiny(sizeof(restic_salt), SALT_ALIGN);

	ctcopy += TAG_LENGTH;

	strtokm(ctcopy, "*"); /* SCRYPT */

	p = strtokm(NULL, "*");
	cur_salt->N = atoi(p);

	p = strtokm(NULL, "*");
	cur_salt->r = atoi(p);

	p = strtokm(NULL, "*");
	cur_salt->p = atoi(p);

	p = strtokm(NULL, "*");
	for (i = 0; i < sizeof(cur_salt->salt); i++)
		cur_salt->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		                    atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "*");
	for (i = 0; i < sizeof(cur_salt->data); i++)
		cur_salt->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		                    atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return cur_salt;
}

unsigned int restic_tunable_cost_N(void *salt)
{
	restic_salt *rs = salt;
	return (unsigned int)rs->N;
}

unsigned int restic_tunable_cost_r(void *salt)
{
	restic_salt *rs = salt;
	return (unsigned int)rs->r;
}

unsigned int restic_tunable_cost_p(void *salt)
{
	restic_salt *rs = salt;
	return (unsigned int)rs->p;
}

void restic_set_salt(void *salt)
{
	cur_salt = (restic_salt *)salt;
}

void restic_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

char *restic_get_key(int index)
{
	return saved_key[index];
}

int restic_cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t *)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

int restic_cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

int restic_cmp_exact(char *source, int index)
{
	return 1;
}

static int restic_crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;
	int failed = 0;
	yescrypt_params_t params = {.N = cur_salt->N, .r = cur_salt->r, .p = cur_salt->p};
#ifdef _OPENMP
	#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		uint8_t kdf_out[64];
#ifdef _OPENMP
		int t = omp_get_thread_num();
		if (t >= max_threads) {
			#pragma omp atomic
			failed |= 2;
			continue;
		}
#else
		const int t = 0;
#endif
		if (yescrypt_kdf(NULL, &local[t], (const uint8_t *)saved_key[index],
		                 strlen(saved_key[index]),
		                 (const uint8_t *)cur_salt->salt, sizeof(cur_salt->salt), &params, kdf_out,
		                 sizeof(kdf_out))) {
			failed |= 1;
		}

		uint8_t *poly1305_key = kdf_out + 32;
		const unsigned char *nonce = cur_salt->data;
		const unsigned char *ciphertext = cur_salt->data + NONCE_SIZE;
		unsigned char prepared_key[32];
		uint64_t masked_key[32 / sizeof(uint64_t)];

		memcpy(masked_key, poly1305_key, 32);
		masked_key[2] &= poly1305_key_mask[0];
		masked_key[3] &= poly1305_key_mask[1];

		AES_KEY aeskey;
		AES_set_encrypt_key((unsigned char *)masked_key, 128, &aeskey);
		AES_ecb_encrypt(nonce, prepared_key + 16, &aeskey, AES_ENCRYPT);
		memcpy(prepared_key, masked_key + 2, 16);
		poly1305_auth((unsigned char *)crypt_out[index], ciphertext, 128,
		              prepared_key);
	}
	if (failed) {
#ifdef _OPENMP
		if (failed & 2) {
			fprintf(stderr, "OpenMP thread number out of range\n");
			error();
		}
#endif
		fprintf(stderr, "scrypt failed: %s\n", strerror(errno));
		error();
	}
	return count;
}

struct fmt_main fmt_restic = {/* fmt_params */
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
		sizeof(restic_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{"N", "r", "p"},
		{FORMAT_TAG},
		restic_tests
	},
	/* fmt_methods */
	{
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		restic_get_binary,
		restic_get_salt,
		{restic_tunable_cost_N, restic_tunable_cost_r, restic_tunable_cost_p},
		fmt_default_source,
		{fmt_default_binary_hash},
		fmt_default_salt_hash,
		NULL,
		restic_set_salt,
		restic_set_key,
		restic_get_key,
		fmt_default_clear_keys,
		restic_crypt_all,
		{fmt_default_get_hash},
		restic_cmp_all,
		restic_cmp_one,
		restic_cmp_exact
	}
};

/*
 * Format for cracking Signal Android app passphrases.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_signal;
#elif FMT_REGISTERS_H
john_register_one(&fmt_signal);
#else

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1  // this is a slow format

#include "loader.h"
#include "pkcs12.h"
#include "hmac_sha.h"

#define FORMAT_LABEL            "Signal"
#define FORMAT_NAME             "Signal Android"
#define ALGORITHM_NAME          "PKCS#12 PBE (SHA1) 32/" ARCH_BITS_STR
// I could not get openssl to use passwords > 48 bytes, so we will cut support at this length (JimF).
#define PLAINTEXT_LENGTH        48
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define FORMAT_TAG              "$signal$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

static struct fmt_tests tests[] = {
	// Android -> Signal 4.13.5
	{"$signal$1$6024$011d9eedb6367df21532acc22dcbb9b2$c492a9906443732b82ba846a14fad1eb$3f53a1cdff7417f3e576d390986218fc5808ae3a1470ca6c13b1fb0ca18673f7718e7f18cf633cd42841c6305953dd43a243e7fc6bdc2c4483d018d24792b7507d34b01a$a243e7fc6bdc2c4483d018d24792b7507d34b01a", "openwall"},
	{"$signal$1$6097$9ce8d884a8efdfb752d1aba4a846b152$33ac657792e920c25de375eda2581833$df06c02b79c500eae098005eb5846d83ce3c64f2ba5518b77f3a3de66e000440c9cc0830381addefed38d4a66c622970bb3449f8f99cbd9d30fedb580987e9e879c31c2c$bb3449f8f99cbd9d30fedb580987e9e879c31c2c", "openwall123"},
	{NULL}
};

static struct custom_salt {
	int iterations;
	int mac_salt_size;
	int master_secret_size;
	unsigned char mac_salt[32];
	unsigned char master_secret[128];
	unsigned char mac[20];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int *cracked, cracked_count;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version
		goto bail;
	if (!isdec(p))
		goto bail;
	if (atoi(p) != 1)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iterations
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // encrypted_salt
		goto bail;
	if (hexlenl(p, &extra) > 32 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // mac_salt
		goto bail;
	if (hexlenl(p, &extra) > 32 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // master_secret
		goto bail;
	if (hexlenl(p, &extra) > 128 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // mac
		goto bail;
	if (hexlenl(p, &extra) != 20 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;

	memset(&cs, 0, sizeof(cs));
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	cs.mac_salt_size = strlen(p) / 2;
	for (i = 0; i < cs.mac_salt_size; i++)
		cs.mac_salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	cs.master_secret_size = strlen(p) / 2;
	for (i = 0; i < cs.master_secret_size; i++)
		cs.master_secret[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

	MEM_FREE(keeptr);

	return (void *)&cs;
}

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
		unsigned char key[16];
		int keylen = 16;
		unsigned char hash[20];

		pkcs12_pbe_derive_key(1, cur_salt->iterations,
				MBEDTLS_PKCS12_DERIVE_KEY,
				(unsigned char*)saved_key[index],
				saved_len[index], cur_salt->mac_salt,
				cur_salt->mac_salt_size, key, keylen);
		hmac_sha1(key, keylen, cur_salt->master_secret, cur_salt->master_secret_size - 20, hash, 20);
		cracked[index] = !memcmp(hash, cur_salt->master_secret + cur_salt->master_secret_size - 20, 20);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
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
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int signal_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}

struct fmt_main fmt_signal = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_OMP,
		{
			"iteration count",
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
		fmt_default_binary,
		get_salt,
		{
			signal_iteration_count,
		},
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

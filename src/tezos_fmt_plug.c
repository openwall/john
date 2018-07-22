/*
 * JtR format to crack password protected Tezos keys.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Special thanks goes to https://github.com/NODESPLIT/tz-brute for making this
 * work possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_tezos;
#elif FMT_REGISTERS_H
john_register_one(&fmt_tezos);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "jumbo.h"
#include "ed25519.h"
#include "blake2.h"
#undef SIMD_COEF_64
#include "pbkdf2_hmac_sha512.h"
#include "memdbg.h"

#define FORMAT_NAME             "Tezos Key"
#define FORMAT_LABEL            "tezos"
#define FORMAT_TAG              "$tezos$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#if ARCH_BITS >= 64
#define ALGORITHM_NAME          "PBKDF2-SHA512 64/" ARCH_BITS_STR " " SHA2_LIB
#else
#define ALGORITHM_NAME          "PBKDF2-HMAC-SHA512 32/" ARCH_BITS_STR " " SHA2_LIB
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        125
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA512 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

static struct fmt_tests tezos_tests[] = {
	// http://doc.tzalpha.net/introduction/zeronet.html, https://faucet.tzalpha.net/
	{"$tezos$1*2048*put guide flat machine express cave hello connect stay local spike ski romance express brass*jbzbdybr.vpbdbxnn@tezos.example.org*tz1eTjPtwYjdcBMStwVdEcwY2YE3th1bXyMR*a19fce77caa0729c68072dc3eb274c7626a71880d926", "4FGU8MpuCo"},
	{"$tezos$1*2048*shove average clap front casino lawn segment dinosaur early solve hole dinner copy journey alley*kqdbxkwa.xvlnjlhg@tezos.example.org*tz1ZRcC58RDjA17Jmp2zDds6Hnk8UAjU8sxh*a19f97385132d6051136ef34d6a62a0bf5af9fecbe26", "XRknDmWXTm"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	uint32_t type;
	uint32_t iterations;
	uint32_t email_length;
	uint32_t mnemonic_length;
	uint32_t raw_address_length;
	char mnemonic[512];
	char email[256];
	char address[64];
	char raw_address[64];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
		goto err;
	if (strcmp(p, "1"))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // mnemonic
		goto err;
	if (strlen(p) > 512)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // email
		goto err;
	if (strlen(p) > 256)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // address
		goto err;
	if (strlen(p) > 64)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) // raw address
		goto err;
	if (hexlenl(p, &extra) > 64 * 2 || extra)
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
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	strcpy(cs.mnemonic, p);
	cs.mnemonic_length = strlen(p);
	p = strtokm(NULL, "*");
	strcpy(cs.email, p);
	cs.email_length = strlen(p);
	p = strtokm(NULL, "*");
	strcpy(cs.address, p);
	p = strtokm(NULL, "*");
	cs.raw_address_length = strlen(p) / 2;
	for (i = 0; i < cs.raw_address_length; i++)
		cs.raw_address[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);
	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void tezos_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
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
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char seed[MIN_KEYS_PER_CRYPT][64];
		char salt[MIN_KEYS_PER_CRYPT][16 + 256 + PLAINTEXT_LENGTH];
		int i;

		// create varying salt(s)
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			memcpy(salt[i], "mnemonic", 8);
			memcpy(salt[i] + 8, cur_salt->email, cur_salt->email_length + 1);
			strcat(salt[i], saved_key[index+i]);
		}

		// kdf
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			pbkdf2_sha512((unsigned char*)cur_salt->mnemonic,
					cur_salt->mnemonic_length, (unsigned char*)salt[i], strlen(salt[i]), 2048,
					seed[i], 64, 0);

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			unsigned char buffer[20];
			ed25519_public_key pk;
			ed25519_secret_key sk;

			// asymmetric stuff
			memcpy(sk, seed[i], 32);
			ed25519_publickey(sk, pk);

			blake2b((uint8_t *)buffer, (unsigned char*)pk, NULL, 20, 32, 0); // pk is pkh (pubkey hash)

			if (memmem(cur_salt->raw_address, cur_salt->raw_address_length, (void*)buffer, 8)) {
				cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
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

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *cs = (struct custom_salt*)salt;

	return cs->iterations;
}

struct fmt_main fmt_tezos = {
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
			"iteration count",
		},
		{ FORMAT_TAG },
		tezos_tests
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
			iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		tezos_set_key,
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

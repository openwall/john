/*
 * Format for brute-forcing PGP Virtual Disk images.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pgpdisk;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pgpdisk);
#else

#include <string.h>
#include <openssl/cast.h>

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1 // this is a slow format
#endif
#endif
#include "sha.h"
#include "loader.h"
#include "aes.h"
#include "twofish.h"
#include "memdbg.h"

#define FORMAT_LABEL            "pgpdisk"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "PGP Disk / Virtual Disk SHA1 " ARCH_BITS_STR
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define FORMAT_TAG              "$pgpdisk$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

static struct fmt_tests tests[] = {
	// Windows 7 + Symantec Encryption Desktop 10.4.1 MP1
	{"$pgpdisk$0*5*16000*3a1bfe10b9d17cf7b446cd94564fc594*1a1ce4453d81117830934495a2516ebc", "openwall"},
	{"$pgpdisk$0*5*16000*1786114971183410acfdc211cbf46230*7d94867264bc005a4a3c1dd211a13a91", "openwall"},
	{"$pgpdisk$0*4*16000*5197b63e47ea0254e719bce690d80fc2*7cbce8cfe5b1d15bb5d25126d76e7626", "openwall"}, // Twofish
	{"$pgpdisk$0*3*16000*3a3c3127fdfa2ea44318cac87c62d263*0a9f26421c5d78e50000000000000000", "openwall"}, // CAST5
	// macOS Sierra + Symantec Encryption Desktop 10.4.1 MP1
	{"$pgpdisk$0*5*16822*67a26aeb7d1f237214cce56527480d65*9eee4e08e8bd17afdddd45b19760823d", "12345678"},
	{"$pgpdisk$0*5*12608*72eacfad309a37bf169a4c7375a583d2*5725d6c36ded48b4309edb2e7fcdc69c", "äbc"},
	{"$pgpdisk$0*5*14813*72eacfad309a37bf169a4c7375a583d2*d3e61d400fecc177a100f576a5138570", "bar"},
	{"$pgpdisk$0*5*14792*72eacfad309a37bf169a4c7375a583d2*304ae364c311bbde2d6965ca3246a823", "foo"},
	{"$pgpdisk$0*7*17739*fb5de863aa2766aff5562db5a7b34ffd*9ca8d6b97c7ebea876f7db7fe35d9f15", "openwall"}, // EME2-AES
	// Windows XP SP3 + PGP 8.0
	{"$pgpdisk$0*3*16000*3248d14732ecfb671dda27fd614813bc*4829a0152666928f0000000000000000", "openwall"},
	{"$pgpdisk$0*4*16000*b47a66d9d4cf45613c3c73a2952d7b88*4e1cd2de6e986d999e1676b2616f5337", "openwall"},
	{NULL}
};

static struct custom_salt {
	int version;
	int algorithm;
	int iterations;
	int salt_size;
	unsigned char salt[16];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 2];
static uint32_t (*crypt_out)[BINARY_SIZE * 2 / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	static int omp_t = 1;
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);

	Twofish_initialise();
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out)
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int extra;
	int res;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // algorithm
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res != 7 && res != 6 && res != 5 && res != 4 && res != 3) // EME-AES, EME2-AES, AES-256, Twofish, CAST5
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // iterations
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) > 16 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // CheckBytes
		goto bail;
	if (hexlenl(p, &extra) > 16 * 2 || extra)
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
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);
	p = strtokm(NULL, "*");
	cs.algorithm = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.salt_size = 16;
	for (i = 0; i < cs.salt_size; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

	MEM_FREE(keeptr);

	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
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
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#undef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH 20

// HashSaltSchedulePassphrase in original source code
static void pgpdisk_kdf(char *password, unsigned char *salt, unsigned char *key, int key_length)
{
	uint32_t bytesNeeded = key_length;
	uint32_t offset = 0;
	unsigned char hash[SHA1_DIGEST_LENGTH];
	int plen;
	int iterations = cur_salt->iterations;
	SHA_CTX ctx; // SHA1 usage is hardcoded

	plen = strlen(password);
	while (bytesNeeded > 0) {
		uint32_t bytesThisTime = SHA1_DIGEST_LENGTH < bytesNeeded ? SHA1_DIGEST_LENGTH: bytesNeeded;
		uint8_t j;
		uint16_t i;

		SHA1_Init(&ctx);
		if (offset > 0) {
			SHA1_Update(&ctx, key, SHA1_DIGEST_LENGTH);
		}
		SHA1_Update(&ctx, password, plen);
		SHA1_Final(hash, &ctx);

		SHA1_Init(&ctx);
		if (cur_salt->algorithm == 3)
			SHA1_Update(&ctx, salt, 8); // kNumSaltBytes = 8, for CAST5
		else
			SHA1_Update(&ctx, salt, 16); // kNumSaltBytes = 16, for AES-256, Twofish

		for (i = 0, j = 0; i < iterations; i++, j++) {
			SHA1_Update(&ctx, hash, bytesThisTime);
			SHA1_Update(&ctx, &j, 1);
		}
		SHA1_Final(key + offset, &ctx);

		bytesNeeded -= bytesThisTime;
		offset += bytesThisTime;
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		int i;

		for (i = 0; i < MAX_KEYS_PER_CRYPT; i++) {
			unsigned char key[40];

			if (cur_salt->algorithm == 5 || cur_salt->algorithm == 6 || cur_salt->algorithm == 7) {
				AES_KEY aes_key;

				pgpdisk_kdf(saved_key[i+index], cur_salt->salt, key, 32);
				// DecryptPassphraseKey in original source code, compute CheckBytes
				AES_set_encrypt_key(key, 256, &aes_key);
				AES_ecb_encrypt(key, (unsigned char*)crypt_out[index+i], &aes_key, AES_ENCRYPT);
			} else if (cur_salt->algorithm == 4) {
				Twofish_key tkey;

				pgpdisk_kdf(saved_key[i+index], cur_salt->salt, key, 32);
				Twofish_prepare_key(key, 32, &tkey);
				Twofish_encrypt(&tkey, key, (unsigned char*)crypt_out[index+i]);
			} else if (cur_salt->algorithm == 3) {
				CAST_KEY ck;

				pgpdisk_kdf(saved_key[i+index], cur_salt->salt, key, 16);
				CAST_set_key(&ck, 16, key);
				memset((unsigned char*)crypt_out[index+i], 0, BINARY_SIZE);
				CAST_ecb_encrypt(key, (unsigned char*)crypt_out[index+i], &ck, CAST_ENCRYPT);
			}
		}
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
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int pgpdisk_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int)cs->iterations;
}

struct fmt_main fmt_pgpdisk = {
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
			pgpdisk_iteration_count,
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

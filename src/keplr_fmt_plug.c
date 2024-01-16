///////////////////////////////////////////////////////////////////////////////////
// JtR format to crack password protected Keplr Wallets.
//
// This software is copyright (c) 2023, Alain Espinosa <alainesp at gmail.com> and it
// is hereby released to the general public under the following terms:
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.
///////////////////////////////////////////////////////////////////////////////////

#if FMT_EXTERNS_H
extern struct fmt_main fmt_keplr;
#elif FMT_REGISTERS_H
john_register_one(&fmt_keplr);
#else

#include <string.h>
#include <errno.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "yescrypt/yescrypt.h"
#include "sha2.h"
#include "jumbo.h"

/* SCRYPT_ALGORITHM_NAME taken from restic_fmt_plug.c */
#if !defined(JOHN_NO_SIMD) && defined(__XOP__)
#define SCRYPT_ALGORITHM_NAME "Salsa20/8 128/128 XOP"
#elif !defined(JOHN_NO_SIMD) && defined(__AVX__)
#define SCRYPT_ALGORITHM_NAME "Salsa20/8 128/128 AVX"
#elif !defined(JOHN_NO_SIMD) && defined(__SSE2__)
#define SCRYPT_ALGORITHM_NAME "Salsa20/8 128/128 SSE2"
#else
#define SCRYPT_ALGORITHM_NAME "Salsa20/8 32/" ARCH_BITS_STR
#endif

#define FORMAT_NAME             "Keplr Wallet"
#define FORMAT_LABEL            "keplr"
#define FORMAT_TAG              "$keplr$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "scrypt " SCRYPT_ALGORITHM_NAME ", SHA256 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       " (131072, 8, 1)"
#define BENCHMARK_LENGTH        0x507
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint16_t)
#define PLAINTEXT_LENGTH        125
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define OMP_SCALE               1

static int max_threads;
static yescrypt_local_t *local;

static struct fmt_tests keplr_tests[] = {
	// 12 words as seed
	{"$keplr$31aa4c50f62b54b4e4bf0a1f6ff38ef8bcc3902ab309533037e96ff60ecfd4a6*8a3b159e9fd7e104049aca4f432575b5bb95c7e3f6829e1549ca9066ed4fcf0a6ff4eb355923a28a4171af171bc36055a2631f10f35dd0b8a5872a51ca9c2c09e7f4e407ec614d546717e1a03c*8ed6786d2ea66ac9a2f8347b8c84ff7eb250c0d5a9aae616500f24e635a7ada7", "12345678"},
	// 24 words as seed
	{"$keplr$10bca142af812a12ac97619cdc057ef4848421e48154c58a5a6500fcdefbf813*21722449d976b56f8bb01911b7753a40ce1095509032f13b2bcc76ce13f681888d093159685a49b9a0e7a5f660044492c78e9cc3c2a02b752f849e8fd409ce2b471d7fbaeeb07daf10e82611da2742f14cfe213c908276441d054164e3f718438f6dbaf4dd2536dce07c43bc76058fd4fd2e1d5af99a35b9ae36b277927c7f41f5debd1fa50c52c2cbc9a3a57e5ff17f4f630407caecd6b0fc*069bc36e83cd8d9d85cce797b1d2f99e5f235b7619b55e95f155e67d3b0197fd", "password"},
	// 12 words as seed with rare character
	{"$keplr$8c27d4300d2de3b209541659c17bc38e63345564d49df4b32c6f20c26cb2bfb5*05dd72de944d59f908339addfd8a42c5433043057a95823a779a32052471c0a9a191099ffd478c6801307e2433a9787838c09c09e4b019e02f0cd1f61d9e0dc88765aa819fb6bcc21ba8cdefc29cb7b6a8*d370e6aa94dbfcbc3029cd41146728c7f8ef9c51a0eb4e0c336118e4a6afba99", "pässword"}, // original password is "pässword"
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;

static struct custom_salt {
	uint8_t salt[32];
	uint8_t mac[32];
	// Arbitrary size, could be any really but bigger than 256
	// have a performance hit and you need the flag FMT_HUGE_INPUT
	uint8_t ciphertext[256];
	uint16_t ciphertext_size;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifdef _OPENMP
	max_threads = omp_get_max_threads();
#else
	max_threads = 1;
#endif

	local = mem_alloc(sizeof(*local) * max_threads);
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_init_local(&local[i]);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_free_local(&local[i]);
	MEM_FREE(local);

	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	keeptr = ctcopy = xstrdup(ciphertext);
	ctcopy += TAG_LENGTH;

	// salt
	if ((p = strtokm(ctcopy, "*")) == NULL)
		goto err;
	if (hexlenl(p, &extra) != 32 * 2 || extra)
		goto err;
	// ciphertext
	if ((p = strtokm(NULL, "*")) == NULL)
		goto err;
	if (strlen(p) & 1)
		goto err;
	if (hexlenl(p, &extra) > sizeof(cur_salt->ciphertext) * 2 || extra)
		goto err;
	// mac
	if ((p = strtokm(NULL, "*")) == NULL)
		goto err;
	if (hexlenl(p, &extra) != 32 * 2 || extra)
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

	// Salt
	p = strtokm(ctcopy, "*");
	for (i = 0; i < 32; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	// Ciphertext
	p = strtokm(NULL, "*");
	size_t ciphertext_size = strlen(p) / 2;
	cs.ciphertext_size = ciphertext_size;
	for (i = 0; i < ciphertext_size; i++)
		cs.ciphertext[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	// MAC
	p = strtokm(NULL, "*");
	for (i = 0; i < 32; i++)
		cs.mac[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);
	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	int failed = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		uint8_t key[32];
		int len = strlen(saved_key[index]);

#ifdef _OPENMP
		if (cracked[index]) /* avoid false sharing of nearby elements */
#endif
			cracked[index] = 0;

#ifdef _OPENMP
		int t = omp_get_thread_num();
		if (t >= max_threads) {
			failed = -1;
			continue;
		}
#else
		const int t = 0;
#endif
		// Scrypt part
		yescrypt_params_t params = { .N = 131072, .r = 8, .p = 1 };
		if (yescrypt_kdf(NULL, &local[t],
			(const uint8_t *)saved_key[index], len,
			(const uint8_t *)cur_salt->salt, 32,
			&params, key, 32)) {
			failed = errno ? errno : EINVAL;
#ifndef _OPENMP
			break;
#endif
		}
		// Sha256 part
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key + 16, 16);
		SHA256_Update(&ctx, cur_salt->ciphertext, cur_salt->ciphertext_size);
		SHA256_Final(key, &ctx);

		// Comparison part
		if (!memcmp(key, cur_salt->mac, 32))
			cracked[index] = 1;
	}

	if (failed) {
#ifdef _OPENMP
		if (failed < 0) {
			fprintf(stderr, "OpenMP thread number out of range\n");
			error();
		}
#endif
		fprintf(stderr, "scrypt failed: %s\n", strerror(failed));
		error();
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


struct fmt_main fmt_keplr = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,// | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		keplr_tests
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

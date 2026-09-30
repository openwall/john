/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2026 (Trinity Berserker)
 *
 * Native "yescrypt" ($y$) format. yescrypt is Openwall's own KDF, used as
 * the default crypt(3) scheme on Debian 11+, Ubuntu 22.04+, Kali and recent
 * Fedora releases. Until now John could only attack $y$ hashes through the
 * slow, non-SIMD generic "crypt" format (which shells out to the system's
 * libxcrypt). This plugin calls src/yescrypt/ directly instead, the same
 * way scrypt_fmt.c already does for classic $7$/$9$ scrypt hashes.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_yescrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_yescrypt);
#else

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "yescrypt/yescrypt.h"

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "base64_convert.h"

#define FORMAT_LABEL			"yescrypt"
#define FORMAT_NAME			""
#define FMT_TAG_Y               "$y$"
#define FMT_TAG_Y_LEN           (sizeof(FMT_TAG_Y)-1)

#if !defined(JOHN_NO_SIMD) && defined(__XOP__)
#define ALGORITHM_NAME			"Salsa20/8 128/128 XOP"
#elif !defined(JOHN_NO_SIMD) && defined(__AVX512VL__)
#define ALGORITHM_NAME			"Salsa20/8 128/128 AVX512VL"
#elif !defined(JOHN_NO_SIMD) && defined(__AVX__)
#define ALGORITHM_NAME			"Salsa20/8 128/128 AVX"
#elif !defined(JOHN_NO_SIMD) && defined(__SSE2__)
#define ALGORITHM_NAME			"Salsa20/8 128/128 SSE2"
#else
#define ALGORITHM_NAME			"Salsa20/8 32/" ARCH_BITS_STR
#endif

/* matches the real-world default on Debian/Ubuntu: j9T = flavor RW, N=4096, r=32 */
#define BENCHMARK_COMMENT		" (j9T, RW, N=4096, r=32)"
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_LENGTH		MAX_PLAINTEXT_LENGTH

#define BINARY_SIZE			256
#define BINARY_ALIGN			1
#define SALT_SIZE			BINARY_SIZE
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#define OMP_SCALE			1

/*
 * Test vectors below were generated locally with:
 *   python3 -c "import crypt; print(crypt.crypt('PASSWORD','$y$j9T$SALT'))"
 * against a system whose libxcrypt supports yescrypt (Debian/Ubuntu-class).
 * Add more real-world hashes from actual /etc/shadow files as you test.
 */
static struct fmt_tests tests[] = {
	{"$y$j9T$saltsaltsalt$7ccAhkNHv5dqQP8qsoti6p7ydUMmO/WI2bstvkhptn3", "password123"},
	{"$y$j9T$aaaaaaaa$.wTlfbnwkxoWPAc6OlP.8B0/udmQBaPbTHBhhRapdj6", "test"},
	{"$y$j9T$aaaaaaaaaaaa$IL3liQzhzN1L0fvwPUV9Hcj6jPeECgJfS1MYNZoIHz0", "test"},
	{NULL}
};

static int max_threads;
static yescrypt_local_t *local;

static char saved_salt[SALT_SIZE];
static struct {
	char key[PLAINTEXT_LENGTH + 1];
	char out[BINARY_SIZE];
} *buffer;

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

	buffer = mem_alloc(sizeof(*buffer) * self->params.max_keys_per_crypt);
}

static void done(void)
{
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_free_local(&local[i]);
	MEM_FREE(local);

	MEM_FREE(buffer);
}

/*
 * NOTE on valid(): unlike classic $7$ scrypt, the $y$ parameter block
 * (flavor + N + r + optional p/t/g/NROM) is variable-length, so we can't
 * check fixed-width fields like scrypt_fmt.c does for $7$. Instead we:
 *   1. check the $y$ tag
 *   2. check every byte between the tag and the LAST '$' is a valid
 *      itoa64 char (covers both the parameter block and the salt, since
 *      both use the same alphabet)
 *   3. check the hash portion (after the last '$') decodes to >= 32 bytes
 * This is intentionally a bit looser than scrypt_fmt.c's parser; it will
 * accept a few strings the real yescrypt_r() would reject, but yescrypt_r()
 * itself is the final authority since it's what actually verifies params
 * when computing the hash. Tightening this (fully decoding flavor/N/r/p/
 * t/g/NROM here, like tunable_cost_N/r/p do for scrypt) is a good follow-up
 * once this base version works and is confirmed against real /etc/shadow
 * hashes.
 */
static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	int length;

	if (strncmp(ciphertext, FMT_TAG_Y, FMT_TAG_Y_LEN))
		return 0;

	if (strlen(ciphertext) >= BINARY_SIZE)
		return 0;

	p = strrchr(ciphertext, '$');
	if (!p || p == ciphertext + FMT_TAG_Y_LEN - 1)
		return 0;

	{
		char *mid = strchr(ciphertext + FMT_TAG_Y_LEN, '$');
		if (!mid || mid >= p)
			return 0;
		for (char *q = ciphertext + FMT_TAG_Y_LEN; q < p; q++) {
			if (q == mid)
				continue; /* the params/salt '$' separator itself */
			if (atoi64[ARCH_INDEX(*q)] == 0x7F)
				return 0;
		}
	}

	if (p - ciphertext > BINARY_SIZE - (1 + 43))
		return 0;

	++p;
	length = base64_valid_length(p, e_b64_cryptBS, flg_Base64_NO_FLAGS, 0);

	/* yescrypt hashes are 32 raw bytes -> 43 base64 chars, same alphabet as scrypt */
	return p[length] == 0 && length == 43;
}

static void *get_binary(char *ciphertext)
{
	static char out[BINARY_SIZE];
	strncpy_pad(out, ciphertext, sizeof(out), 0);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static char out[SALT_SIZE];
	char *cp;

	strncpy_pad(out, ciphertext, sizeof(out), 0);
	/* keep "$y$<params><salt>", drop the trailing "$<hash>" */
	cp = strrchr(out, '$');
	if (cp)
		*cp = 0;
	return out;
}

#define H(s, i) \
	((int)(unsigned char)(atoi64[ARCH_INDEX((s)[(i)])] ^ (s)[(i) - 1]))

#define H0(s) \
	char *cp = strrchr(s,'$')+40; \
	int i = cp-s; \
	return i > 0 ? H((s), i) & 0xF : 0
#define H1(s) \
	char *cp = strrchr(s,'$')+40; \
	int i = cp-s; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 4)) & 0xFF : 0
#define H2(s) \
	char *cp = strrchr(s,'$')+40; \
	int i = cp-s; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 6)) & 0xFFF : 0
#define H3(s) \
	char *cp = strrchr(s,'$')+40; \
	int i = cp-s; \
	return i > 4 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10)) & 0xFFFF : 0
#define H4(s) \
	char *cp = strrchr(s,'$')+40; \
	int i = cp-s; \
	return i > 6 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10) ^ (H((s), i - 6) << 15)) & 0xFFFFF : 0

static int binary_hash_0(void *binary) { H0((char *)binary); }
static int binary_hash_1(void *binary) { H1((char *)binary); }
static int binary_hash_2(void *binary) { H2((char *)binary); }
static int binary_hash_3(void *binary) { H3((char *)binary); }
static int binary_hash_4(void *binary) { H4((char *)binary); }

static int get_hash_0(int index) { H0(buffer[index].out); }
static int get_hash_1(int index) { H1(buffer[index].out); }
static int get_hash_2(int index) { H2(buffer[index].out); }
static int get_hash_3(int index) { H3(buffer[index].out); }
static int get_hash_4(int index) { H4(buffer[index].out); }

static int salt_hash(void *salt)
{
	int i, h;

	i = strlen((char *)salt) - 1;
	if (i > 1) i--;

	h = (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i])];
	h ^= ((unsigned char *)salt)[i - 1];
	h <<= 6;
	h ^= (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i - 1])];
	h ^= ((unsigned char *)salt)[i];

	return h & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	strcpy(saved_salt, salt);
}

static void set_key(char *key, int index)
{
	strnzcpy(buffer[index].key, key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return buffer[index].key;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;
	int failed = 0;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(index) shared(count, failed, max_threads, local, saved_salt, buffer)
#endif
	for (index = 0; index < count; index++) {
#ifdef _OPENMP
		int t = omp_get_thread_num();
		if (t >= max_threads) {
			failed = -1;
			continue;
		}
#else
		const int t = 0;
#endif
		uint8_t *hash;
		/* yescrypt_r() natively understands both "$7$" and "$y$"
		 * settings -- see yescrypt-common.c, it dispatches on
		 * setting[1] itself. No extra glue code needed here. */
		hash = yescrypt_r(NULL, &local[t],
		    (const uint8_t *)buffer[index].key,
		    strlen(buffer[index].key),
		    (const uint8_t *)saved_salt,
		    NULL,
		    (uint8_t *)buffer[index].out,
		    sizeof(buffer[index].out));
		if (!hash) {
			failed = errno ? errno : EINVAL;
#ifndef _OPENMP
			break;
#endif
		}
	}

	if (failed) {
#ifdef _OPENMP
		if (failed < 0) {
			fprintf(stderr, "OpenMP thread number out of range\n");
			error();
		}
#endif
		fprintf(stderr, "yescrypt failed: %s\n", strerror(failed));
		error();
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!strcmp((char *)binary, buffer[index].out))
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !strcmp((char *)binary, buffer[index].out);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_yescrypt = {
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
			/* tunable costs not yet exposed for $y$, see valid() comment above */
		},
		{ FMT_TAG_Y },
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
			NULL
		},
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			NULL,
			NULL
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

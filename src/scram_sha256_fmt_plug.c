/*
 * This software is Copyright (c) 2025, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Copyright (c) 2025 by Solar Designer (PostgreSQL SCRAM verifiers support)
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * https://github.com/mongodb/specifications/blob/master/source/auth/auth.md
 * https://datatracker.ietf.org/doc/html/rfc7677
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_scram_sha256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_scram_sha256);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "sha.h"
#include "base64_convert.h"
#include "hmac_sha.h"
#include "simd-intrinsics.h"
#include "pbkdf2_hmac_sha256.h"

#if defined SIMD_COEF_32
#define SIMD_KEYS		(SIMD_COEF_32 * SIMD_PARA_SHA256)
#endif

#define FORMAT_LABEL            "SCRAM-PBKDF2-SHA256"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "PBKDF2-SHA256/SCRAM " SHA256_ALGORITHM_NAME
#define PLAINTEXT_LENGTH        125
#define HASH_LENGTH             44
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define BINARY_SIZE             32
#define BINARY_ALIGN            sizeof(uint32_t)
#define BENCHMARK_COMMENT       " (new MongoDB, PostgreSQL)"
#define BENCHMARK_LENGTH        0x107
#define FORMAT_TAG              "$scram-pbkdf2-sha256$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)
#define FORMAT_TAG_PG           "SCRAM-SHA-256$"
#define FORMAT_TAG_PG_LENGTH    (sizeof(FORMAT_TAG_PG) - 1)
#define MAX_USERNAME_LENGTH     128

#ifndef OMP_SCALE
#define OMP_SCALE               1 // MKPC and scale tuned for i7
#endif

#if !defined(SIMD_COEF_32)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64
#else
#define MIN_KEYS_PER_CRYPT      SIMD_KEYS
#define MAX_KEYS_PER_CRYPT      (64 * SIMD_KEYS)
#endif

static struct fmt_tests tests[] = {
	/* MongoDB 8.0.6 hashes */
	{"$scram-pbkdf2-sha256$15000$OxAPvANwV/ZQXqgiW6s6o2+wPM+gfZNthjpUjw==$MenSdE9VmSij4sIKMKfRs+bHy9vkareAopWM8MB+364=", "openwall"},
	{"$scram-pbkdf2-sha256$15000$0sWhCP4Z0gjI7KY6WJ7z/Hs3SEcxC+PUSkv4og==$qnttlssP81IuwtcoZ4TV/M0SMCajePUhPP3mRrnv0aA=", "openwall@1234567890"},
	/* PostgreSQL verifiers as converted by our prepare() */
	{"$scram-pbkdf2-sha256$4096$Wn/IWH721Aj+HbEQRJiD3A==$EyLID0avoAyy1JzKwD7yKQ9HuWQ0VlSurm180/sQFYE=", "P123"},
	{"$scram-pbkdf2-sha256$4096$p2j/1lMdQF6r1dD9I9f7PQ==$5xU6Wj/GNg3UnN2uQIx3ezx7uZyzGeM5NrvSJRIxnlw=", "test"},
	{"$scram-pbkdf2-sha256$4096$L6Nhfyy6pos5mpvTRXQOTQ==$/aRx7mRpU0txwFSzZ5lcj/u/FHCc503fUfGrF12nGx0=", "test"},
	{NULL}
};

static struct custom_salt {
	int saltlen;
	int iterations;
#define MAX_SALT_LENGTH 40 /* base64 encoded */
	unsigned char salt[28 + 4 + 1]; // 4 bytes for 'startKey'
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

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

static char *prepare(char *fields[10], struct fmt_main *self)
{
/*
SCRAM-SHA-256$4096:Wn/IWH721Aj+HbEQRJiD3A==$xtjWYz23fPW4dXUZMzTup6bUOqSAVzlChcrhHCfIXfo=:EyLID0avoAyy1JzKwD7yKQ9HuWQ0VlSurm180/sQFYE=
SCRAM-SHA-256$4096:p2j/1lMdQF6r1dD9I9f7PQ==$H3xt5yh7lwSq9zUPYwHovRu3FyUCCXchG/skydJRa9o=:5xU6Wj/GNg3UnN2uQIx3ezx7uZyzGeM5NrvSJRIxnlw=
SCRAM-SHA-256$4096:L6Nhfyy6pos5mpvTRXQOTQ==$RMoA1BGLjB/LmVJ2iP5N91E0ri/9siV5E3D5DEvfqXU=:/aRx7mRpU0txwFSzZ5lcj/u/FHCc503fUfGrF12nGx0=
*/
	for (int i = 0; i < 2; i++) /* allow for username:hash or bare hash */
	if (!strncmp(fields[i], FORMAT_TAG_PG, FORMAT_TAG_PG_LENGTH)) {
		static char out[FORMAT_TAG_LENGTH + 10 + 1 + MAX_SALT_LENGTH + 1 + HASH_LENGTH + 1];
		char *saltend = strchr(fields[i + 1], '$');
		if (!saltend || !isdec(fields[i] + FORMAT_TAG_PG_LENGTH))
			break;
		if ((size_t)snprintf(out, sizeof(out), FORMAT_TAG "%s$%.*s$%s",
		    fields[i] + FORMAT_TAG_PG_LENGTH, /* iterations */
		    (int)(saltend - fields[i + 1]), /* salt length */
		    fields[i + 1], /* salt */
		    fields[i + 2]) /* serverKey */ >= sizeof(out))
			break;
		return out;
	}

	return fields[1];
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (strlen(p)-2 != base64_valid_length(p, e_b64_mime, flg_Base64_MIME_TRAIL_EQ, 0) || strlen(p) > MAX_SALT_LENGTH)
		goto err;
	if ((p = strtokm(NULL, "")) == NULL)	/* hash */
		goto err;
	if (strlen(p)-1 != base64_valid_length(p, e_b64_mime, flg_Base64_MIME_TRAIL_EQ, 0) || strlen(p) != HASH_LENGTH)
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
	char *ctcopy, *keeptr, *p;

	memset(&cs, 0, sizeof(cs));
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "$");
	cs.saltlen = base64_convert(p, e_b64_mime, strlen(p), (char *)cs.salt, e_b64_raw, sizeof(cs.salt), flg_Base64_NO_FLAGS, 0);
	cs.salt[28] = 0;
	cs.salt[29] = 0;
	cs.salt[30] = 0;
	cs.salt[31] = 1;

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

	p = strrchr(ciphertext, '$') + 1;
	base64_convert(p, e_b64_mime, strlen(p), (char*)out, e_b64_raw, sizeof(buf.c), flg_Base64_DONOT_NULL_TERMINATE, 0);

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int index;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#if !defined (SIMD_COEF_32)
		unsigned char output[BINARY_SIZE];

		pbkdf2_sha256((unsigned char *)saved_key[index], strlen(saved_key[index]),
		    cur_salt->salt, cur_salt->saltlen, cur_salt->iterations, output, BINARY_SIZE, 0);
		// ServerKey := HMAC(SaltedPassword, "Server Key")
		hmac_sha256(output, BINARY_SIZE, (unsigned char*)"Server Key", 10, (unsigned char*)crypt_out[index], BINARY_SIZE);
#else
		int i;
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT];
		union {
			uint32_t *pout[MIN_KEYS_PER_CRYPT];
			unsigned char *poutc;
		} x;

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = crypt_out[i+index];
		}
		pbkdf2_sha256_sse((const unsigned char **)pin, lens,
		    cur_salt->salt, cur_salt->saltlen, cur_salt->iterations, &(x.poutc), 32, 0);
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			hmac_sha256((unsigned char*)&crypt_out[i+index], BINARY_SIZE, (unsigned char*)"Server Key", 10, (unsigned char *)&crypt_out[index+i], BINARY_SIZE);
		}
#endif
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
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
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int tunable_cost_iterations(void *_salt)
{
	struct custom_salt *salt = (struct custom_salt *)_salt;
	return salt->iterations;
}

struct fmt_main fmt_scram_sha256 = {
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
		{"iterations"},
		{ FORMAT_TAG, FORMAT_TAG_PG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{tunable_cost_iterations},
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
		set_key,
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

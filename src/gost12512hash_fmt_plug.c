/*
 * Based on Drepper's sha2crypt spec at
 * http://www.akkadia.org/drepper/SHA-crypt.txt
 *
 * This software is Copyright (c) 2022 magnum,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if ARCH_LITTLE_ENDIAN

#if FMT_EXTERNS_H
extern struct fmt_main fmt_gost12512hash;
#elif FMT_REGISTERS_H
john_register_one(&fmt_gost12512hash);
#else

#define _GNU_SOURCE 1
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "gost3411-2012-core.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"

#ifndef OMP_SCALE
#define OMP_SCALE               4
#endif

#define FORMAT_LABEL            "streebog512crypt"
#define FORMAT_NAME             "Astra Linux $gost12512hash$"

#if !JOHN_NO_SIMD && __AVX__
#define ALGORITHM_NAME          "GOST R 34.11-2012 128/128 AVX 1x"
#elif !JOHN_NO_SIMD && __SSE2__
#define ALGORITHM_NAME          "GOST R 34.11-2012 128/128 SSE2 1x"
#else
#define ALGORITHM_NAME          "GOST R 34.11-2012 " ARCH_BITS_STR "/" ARCH_BITS_STR
#endif

#define PLAINTEXT_LENGTH        MAX_PLAINTEXT_LENGTH

#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct saltstruct)
#define SALT_ALIGN              4

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define BINARY_SIZE             64
#define SALT_LENGTH             16
#define CIPHERTEXT_LENGTH       86

/* Prefix for optional rounds specification.  */
#define ROUNDS_PREFIX           "rounds="
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT          5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN              1   /* Drepper has it as 1000 */
/* Maximum number of rounds.  */
#define ROUNDS_MAX              999999999

#define BENCHMARK_COMMENT       " (rounds=5000)"
#define BENCHMARK_LENGTH        0x107
#define FORMAT_TAG              "$gost12512hash$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

static struct fmt_tests tests[] = {
	{"$gost12512hash$salt$nwv1Oqm2zL9523APlKI6Fpmlm56UzSe.J1wDzMk61S2zxa1nWY4U9d3oP5UyOpZQvTzVPEZWRnfRd/yJZeXp2.", "magnum"},
	{"$gost12512hash$longersalt$Ru..ARXlil3CeBqecyE9EBW1tfZZoPPnnwWJKy7nbhOnzmXpldy3nt1iB1QM21KD73L1tm/zWsiyU05zHluwO1", "longerpassword"},
	{"$gost12512hash$KrmcHbeQmxiP/Ipl$uNmEQvpJ7B0jTcCkIh1IQEIRoyAXzliyt2S7VAz/xA8GNjBbFeE.c98elVBwad6y40qPNKYqYNkWZJFxpGw620", "password"},
	{NULL}
};

/* ------- Check if the ciphertext if a valid gost12512hash crypt ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
	char *pos, *start;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ciphertext += FORMAT_TAG_LEN;

	if (!strncmp(ciphertext, ROUNDS_PREFIX, sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;

		if (!strtoul(num, &endp, 10))
			return 0;
		if (*endp == '$')
			ciphertext = endp + 1;
	}
	for (pos = ciphertext; *pos && *pos != '$'; pos++);
	if (!*pos || pos < ciphertext || pos > &ciphertext[SALT_LENGTH]) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH)
		return 0;
	return 1;
}

/* ------- To binary functions ------- */
#define TO_BINARY(b1, b2, b3)	  \
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

static void *get_binary(char * ciphertext) {
	static uint32_t outbuf[64/4];
	uint32_t value;
	char *pos = strrchr(ciphertext, '$') + 1;
	unsigned char *out = (unsigned char*)outbuf;
	int i = 0;

	do {
		TO_BINARY(i, (i+21)%63, (i+42)%63);
		i = (i+22)%63;
	} while (i != 21);
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6);
	out[63] = value;
	return (void *)out;
}

static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct saltstruct {
	unsigned int len;
	unsigned int rounds;
	unsigned char salt[SALT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	// we allocate 1 more than needed, and use that 'extra' value as a zero
	// length PW to fill in the tail groups in MMX mode.
	saved_len = mem_calloc(1 + self->params.max_keys_per_crypt, sizeof(*saved_len));
	saved_key = mem_calloc(1 + self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc(1 + self->params.max_keys_per_crypt, sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char temp_result[BINARY_SIZE];
		GOST34112012Context ctx;
		GOST34112012Context alt_ctx;
		size_t cnt;
		unsigned char *cp;
		unsigned char p_bytes[PLAINTEXT_LENGTH+1];
		unsigned char s_bytes[PLAINTEXT_LENGTH+1];

		/* Prepare for the real work.  */
		GOST34112012Init(&ctx, 512);

		/* Add the key string.  */
		GOST34112012Update(&ctx, (unsigned char*)saved_key[index], saved_len[index]);

		/* The last part is the salt string.  This must be at most 16
		   characters and it ends at the first `$' character (for
		   compatibility with existing implementations).  */
		GOST34112012Update(&ctx, cur_salt->salt, cur_salt->len);


		/* Compute alternate Streebog sum with input KEY, SALT, and KEY.  The
		   final result will be added to the first context.  */
		GOST34112012Init(&alt_ctx, 512);

		/* Add key.  */
		GOST34112012Update(&alt_ctx, (unsigned char*)saved_key[index], saved_len[index]);

		/* Add salt.  */
		GOST34112012Update(&alt_ctx, cur_salt->salt, cur_salt->len);

		/* Add key again.  */
		GOST34112012Update(&alt_ctx, (unsigned char*)saved_key[index], saved_len[index]);

		/* Now get result of this (64 bytes) and add it to the other
		   context.  */
		GOST34112012Final(&alt_ctx, (unsigned char*)crypt_out[index]);

		/* Add for any character in the key one byte of the alternate sum.  */
		for (cnt = saved_len[index]; cnt > BINARY_SIZE; cnt -= BINARY_SIZE)
			GOST34112012Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);
		GOST34112012Update(&ctx, (unsigned char*)crypt_out[index], cnt);

		/* Take the binary representation of the length of the key and for every
		   1 add the alternate sum, for every 0 the key.  */
		for (cnt = saved_len[index]; cnt > 0; cnt >>= 1)
			if ((cnt & 1) != 0)
				GOST34112012Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);
			else
				GOST34112012Update(&ctx, (unsigned char*)saved_key[index], saved_len[index]);

		/* Create intermediate result.  */
		GOST34112012Final(&ctx, (unsigned char*)crypt_out[index]);

		/* Start computation of P byte sequence.  */
		GOST34112012Init(&alt_ctx, 512);

		/* For every character in the password add the entire password.  */
		for (cnt = 0; cnt < saved_len[index]; ++cnt)
			GOST34112012Update(&alt_ctx, (unsigned char*)saved_key[index], saved_len[index]);

		/* Finish the digest.  */
		GOST34112012Final(&alt_ctx, temp_result);

		/* Create byte sequence P.  */
		cp = p_bytes;
		for (cnt = saved_len[index]; cnt >= BINARY_SIZE; cnt -= BINARY_SIZE)
			cp = memcpy (cp, temp_result, BINARY_SIZE) + BINARY_SIZE;
		memcpy (cp, temp_result, cnt);

		/* Start computation of S byte sequence.  */
		GOST34112012Init(&alt_ctx, 512);

		/* repeast the following 16+A[0] times, where A[0] represents the
		   first byte in digest A interpreted as an 8-bit unsigned value */
		for (cnt = 0; cnt < 16 + ((unsigned char*)crypt_out[index])[0]; ++cnt)
			GOST34112012Update(&alt_ctx, cur_salt->salt, cur_salt->len);

		/* Finish the digest.  */
		GOST34112012Final(&alt_ctx, temp_result);

		/* Create byte sequence S.  */
		cp = s_bytes;
		for (cnt = cur_salt->len; cnt >= BINARY_SIZE; cnt -= BINARY_SIZE)
			cp = memcpy (cp, temp_result, BINARY_SIZE) + BINARY_SIZE;
		memcpy (cp, temp_result, cnt);

		/* Repeatedly run the collected hash value through Streebog to burn CPU cycles.  */
		for (cnt = 0; cnt < cur_salt->rounds; ++cnt) {
			/* New context.  */
			GOST34112012Init(&ctx, 512);

			/* Add key or last result.  */
			if ((cnt & 1) != 0)
				GOST34112012Update(&ctx, p_bytes, saved_len[index]);
			else
				GOST34112012Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);

			/* Add salt for numbers not divisible by 3.  */
			if (cnt % 3 != 0)
				GOST34112012Update(&ctx, s_bytes, cur_salt->len);

			/* Add key for numbers not divisible by 7.  */
			if (cnt % 7 != 0)
				GOST34112012Update(&ctx, p_bytes, saved_len[index]);

			/* Add key or last result.  */
			if ((cnt & 1) != 0)
				GOST34112012Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);
			else
				GOST34112012Update(&ctx, p_bytes, saved_len[index]);

			/* Create intermediate result.  */
			GOST34112012Final(&ctx, (unsigned char*)crypt_out[index]);
		}
	}
	return count;
}

static void set_salt(void *salt)
{
	cur_salt = salt;
}

static void *get_salt(char *ciphertext)
{
	static struct saltstruct out;
	int len;

	memset(&out, 0, sizeof(out));
	out.rounds = ROUNDS_DEFAULT;
	ciphertext += FORMAT_TAG_LEN;
	if (!strncmp(ciphertext, ROUNDS_PREFIX,
	             sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);
		if (*endp == '$')
		{
			ciphertext = endp + 1;
			srounds = srounds < ROUNDS_MIN ?
				ROUNDS_MIN : srounds;
			out.rounds = srounds > ROUNDS_MAX ?
				ROUNDS_MAX : srounds;
		}
	}

	for (len = 0; ciphertext[len] != '$'; len++);

	if (len > SALT_LENGTH)
		len = SALT_LENGTH;

	memcpy(out.salt, ciphertext, len);
	out.len = len;
	return &out;
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

static unsigned int iteration_count(void *salt)
{
	struct saltstruct *csalt;

	csalt = salt;
	return (unsigned int)csalt->rounds;
}

// We are hashing the entire struct
static int salt_hash(void *salt)
{
	unsigned char *s = salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < SALT_SIZE; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_gost12512hash = {
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
			iteration_count,
		},
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
		salt_hash,
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
#else
#if !defined(FMT_EXTERNS_H) && !defined(FMT_REGISTERS_H)
#ifdef __GNUC__
#warning streebog512crypt CPU format requires little-endian, format disabled
#elif _MSC_VER
#pragma message(": warning streebog512crypt CPU format requires little-endian, format disabled:")
#endif
#endif
#endif /* ARCH_LITTLE_ENDIAN */

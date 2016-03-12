/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2016, JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * This is a 'fake' format.  lists EVERY password as being successfully
 * cracked. This is used for testing things like restore mode, -fork,
 * OpenMP, etc, which are often hard to test in other manners. And in
 * helping test different 'modes', and mixes of modes and hybrid runs.
 * When complete ALL candidate passwords should be present. Also, there
 * should be no (of as few as possible) duplicate words seen at the
 * session restore locations.
 *
 * This file is almost NEVER built with JtR. It lives in unused, but
 * during testing phases, it can be copied into the src direcotry
 * and tests performed to make sure that restoring is properly working
 * for the modes needing tested.
 *
 * this format is PURPOSELY not optimized!!!  Do not try to optimize it
 * we are not looking for speed. We are looking for repeatable restore.
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_restore_tester;
extern struct fmt_main fmt_restore_tester_s;
extern struct fmt_main fmt_restore_tester_sh;
#elif FMT_REGISTERS_H
john_register_one(&fmt_restore_tester);
john_register_one(&fmt_restore_tester_s);
john_register_one(&fmt_restore_tester_sh);
#else

#include "autoconfig.h"

#include <string.h>
#include <time.h>
#if defined (_MSC_VER) || defined (__MINGW__)
#include <windows.h>
#endif
#include "common.h"
#include "formats.h"
#include "memory.h"
#ifdef _OPENMP
#include <omp.h>
#endif
#include "memdbg.h"

#define FORMAT_LABEL			"restore_tester"
#define FORMAT_VALID			"$restore_tester$valid" // the only valid hash for non-salted
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"None"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125


#define BINARY_SIZE			0
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		3
#define MAX_KEYS_PER_CRYPT		3

static struct fmt_tests tests[] = {
	{FORMAT_VALID, "any pasword will be ok"},
	{NULL}
};

static struct fmt_tests tests_s[] = {
	{FORMAT_VALID"$SLT1", "any pasword will be ok"},
	{FORMAT_VALID"$SLT2", "any pasword will be ok"},
	{FORMAT_VALID"$SLT3", "any pasword will be ok"},
	{NULL}
};
static struct fmt_tests tests_sh[] = {
	{FORMAT_VALID"*SLT1", "any pasword will be ok"},
	{FORMAT_VALID"*SLT2", "any pasword will be ok"},
	{FORMAT_VALID"*SLT3", "any pasword will be ok"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static char *cur_salt;

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strcmp(ciphertext, FORMAT_VALID);
}

static int valid_s(char *ciphertext, struct fmt_main *self)
{
	// the strncasecmp allows us to have multiple hashes with identical
	// salt.  Simply mangle the case of the FORMAT_VALID string and
	// then using the same salt will have multiple hashes with same salt.
	return !strncasecmp(ciphertext, FORMAT_VALID"$", sizeof(FORMAT_VALID));
}
static int valid_sh(char *ciphertext, struct fmt_main *self)
{
	return !strncasecmp(ciphertext, FORMAT_VALID"*", sizeof(FORMAT_VALID));
}

static void init(struct fmt_main *self)
{
	int total_cnt = MAX_KEYS_PER_CRYPT;
#ifdef _OPENMP
	total_cnt *= omp_get_max_threads();
	self->params.max_keys_per_crypt = total_cnt;
	self->params.max_keys_per_crypt = total_cnt;
#endif
	saved_key = mem_calloc(total_cnt, sizeof(*saved_key));
}

static void done(void)
{
	MEM_FREE(saved_key);
}

static void set_key(char *key, int index)
{
	strcpy(saved_key[index], key);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static char *get_key_s(int index)
{
	static char KEY[PLAINTEXT_LENGTH+20];
	extern volatile int bench_running;
	if (bench_running)
		return saved_key[index];
	sprintf(KEY, "%s salt->%s", saved_key[index], cur_salt);
	return KEY;
}

static int salt_hash(void *salt)
{
	unsigned char *p = (unsigned char *)salt;
	//unsigned v, i;
	//v = 0;
	//for (i = 0; i < 4; ++i)
	//{
	//	v <<= 3;
	//	v |= *p++;
	//	v ^= ((v >> 7) & 0x37);
	//}
	//return v & (SALT_HASH_SIZE - 1);
	return (p[3]-'0') & (SALT_HASH_SIZE - 1);
}

static char *get_key_sh(int index)
{
	static char KEY[PLAINTEXT_LENGTH+60];
	extern volatile int bench_running;
	if (bench_running)
		return saved_key[index];
	sprintf(KEY, "%s salt->%s salthash->%x", saved_key[index], cur_salt, salt_hash(cur_salt));
	return KEY;
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
#if defined (_MSC_VER) || defined (__MINGW__)
		Sleep(50);
#else
		struct timespec res, delay;

		delay.tv_sec = 0;
		delay.tv_nsec = 50000000;
		nanosleep(&delay, &res);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	return 1;
}

static int cmp_one(void *binary, int index)
{
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void *salt(char *ciphertext) {
	static char salt[5];
	char *cp = strrchr(ciphertext, '$')+1;
	int len;
	len = strlen(cp);
	if (len > 4) len = 4;
	memcpy(salt, cp, len);
	salt[len] = 0;
	return salt;
}

static void *salt_sh(char *ciphertext) {
	static char salt[5];
	char *cp = strrchr(ciphertext, '*')+1;
	int len;
	len = strlen(cp);
	if (len > 4) len = 4;
	memcpy(salt, cp, len);
	salt[len] = 0;
	return salt;
}

static void set_salt(void *salt) {
	cur_salt = (char*)salt;
}

struct fmt_main fmt_restore_tester = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		fmt_default_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash

		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
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

struct fmt_main fmt_restore_tester_s = {
	{
		FORMAT_LABEL"_salted",
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		4,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{ NULL },
		tests_s
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_s,
		fmt_default_split,
		fmt_default_binary,
		salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash

		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key_s,
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
struct fmt_main fmt_restore_tester_sh = {
	{
		FORMAT_LABEL"_salt_hashed",
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		4,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{ NULL },
		tests_sh
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_sh,
		fmt_default_split,
		fmt_default_binary,
		salt_sh,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash

		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key_sh,
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

#endif

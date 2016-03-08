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
#elif FMT_REGISTERS_H
john_register_one(&fmt_restore_tester);
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
#define FORMAT_VALID			"$restore_tester$valid" // the only valid hash ;)
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"None"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125


#define BINARY_SIZE			0
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		16
#define MAX_KEYS_PER_CRYPT		16

static struct fmt_tests tests[] = {
	{FORMAT_VALID, "any pasword will be ok"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strcmp(ciphertext, FORMAT_VALID);
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


static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
#if defined (_MSC_VER) || defined (__MINGW__)
		Sleep(20);
#else
		struct timespec res, delay;

		delay.tv_sec = 0;
		delay.tv_nsec = 20000000;
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

#endif

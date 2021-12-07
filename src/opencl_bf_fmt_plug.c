/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 by Sayantan Datta <std2048 at gmail dot com>
 * It is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_bf;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_bf);
#else

#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "opencl_bf_std.h"
#include "common.h"
#include "formats.h"
#include "config.h"
#include "loader.h"
#include "BF_common.h"

#define FORMAT_LABEL			"bcrypt-opencl"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"Blowfish OpenCL"

#define BENCHMARK_COMMENT		" (\"$2a$05\", 32 iterations)"
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_LENGTH		72
//#define CIPHERTEXT_LENGTH		60 // in BF_commmon.h

#define BINARY_SIZE			4
#define BINARY_ALIGN			4
#define SALT_SIZE			sizeof(BF_salt)
#define SALT_ALIGN			4

#define MIN_KEYS_PER_CRYPT		DEFAULT_LWS
#define MAX_KEYS_PER_CRYPT		BF_N

// static struct fmt_tests BF_common_tests[] = {  // defined in BF_common.c

static char 	(*saved_key)[PLAINTEXT_LENGTH + 1];
static char 	keys_mode;
static int 	sign_extension_bug;
static BF_salt 	saved_salt;

static void done(void) {
	BF_clear_buffer();
	MEM_FREE(saved_key);
}

static void init(struct fmt_main *self) {
	saved_key = mem_calloc(BF_N, sizeof(*saved_key));
	keys_mode = 'a';
	sign_extension_bug = 0;

	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	global_work_size = 0;

	//Prepare OpenCL environment.
	opencl_load_environment();

	// Check if specific LWS/GWS was requested
	opencl_get_user_preferences(FORMAT_LABEL);

	// BF_select_device(platform,device);
	//platform_id = get_platform_id(gpu_id);
	BF_select_device(db->format);

	//fprintf(stderr, "****Please see 'opencl_bf_std.h' for device specific optimizations****\n");
}

static int get_hash_0(int index) {
	return opencl_BF_out[index][0] & PH_MASK_0;
}

static int get_hash_1(int index) {
	return opencl_BF_out[index][0] & PH_MASK_1;
}

static int get_hash_2(int index) {
	return opencl_BF_out[index][0] & PH_MASK_2;
}

static int get_hash_3(int index) {
	return opencl_BF_out[index][0] & PH_MASK_3;
}

static int get_hash_4(int index) {
	return opencl_BF_out[index][0] & PH_MASK_4;
}

static int get_hash_5(int index) {
	return opencl_BF_out[index][0] & PH_MASK_5;
}

static int get_hash_6(int index) {
	return opencl_BF_out[index][0] & PH_MASK_6;
}

static int salt_hash(void *salt) {
	return ((BF_salt *)salt)->salt[0] & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt) {
	memcpy(&saved_salt, salt, sizeof(saved_salt));
}

static void set_key(char *key, int index) {
	opencl_BF_std_set_key(key, index, sign_extension_bug);
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index) {
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt) {
	const int count = *pcount;
	if (keys_mode != saved_salt.subtype) {
		int i;

		keys_mode = saved_salt.subtype;
		sign_extension_bug = (keys_mode == 'x');
		for (i = 0; i < count; i++)
			opencl_BF_std_set_key(saved_key[i], i, sign_extension_bug);
	}

	opencl_BF_std_crypt(&saved_salt, count);
	return count;
}

static int cmp_all(void *binary, int count) {
	int i;
	for (i = 0; i < count; i++)
		if (*(BF_word *)binary == opencl_BF_out[i][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *(BF_word *)binary == opencl_BF_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	opencl_BF_std_crypt_exact(index);

	return !memcmp(BF_common_get_binary(source), opencl_BF_out[index],
	    sizeof(BF_binary));
}

struct fmt_main fmt_opencl_bf = {
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
		FMT_TRUNC | FMT_CASE | FMT_8_BIT,
		{
			"iteration count",
		},
		{
			FORMAT_TAG,
			FORMAT_TAG2,
			FORMAT_TAG3,
			FORMAT_TAG4
		},
		BF_common_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		BF_common_valid,
		BF_common_split,
		BF_common_get_binary,
		BF_common_get_salt,
		{
			BF_common_iteration_count,
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
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */

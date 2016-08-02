/*
* This software is Copyright (c) 2011,2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_phpass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_phpass);
#else

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_phpass.h"
#include "cuda_common.h"
#include "phpass_common.h"
#include "memdbg.h"

#define FORMAT_LABEL		"phpass-cuda"
#define FORMAT_NAME		""

#define ALGORITHM_NAME		"MD5 CUDA"

#define BENCHMARK_COMMENT	" ($P$9 lengths 0 to 15)"

#define BINARY_ALIGN		1
#define SALT_ALIGN		1
#define MD5_DIGEST_LENGTH 	16

#define MIN_KEYS_PER_CRYPT	THREADS
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

static unsigned char *inbuffer;				/** plaintext ciphertexts **/
static phpass_crack *outbuffer;				/** calculated hashes **/
static phpass_salt currentsalt;

extern void gpu_phpass(uint8_t *, phpass_salt *, phpass_crack *, int count);

static void done(void)
{
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
}

static void init(struct fmt_main *self)
{
	///Allocate memory for hashes and passwords
	inbuffer =
		(uint8_t *) mem_calloc(MAX_KEYS_PER_CRYPT,
		                       sizeof(phpass_password));
	outbuffer =
		(phpass_crack *) mem_calloc(MAX_KEYS_PER_CRYPT,
		                            sizeof(phpass_crack));
	check_mem_allocation(inbuffer, outbuffer);
	///Initialize CUDA
	cuda_init();
}

static void *get_salt(char *ciphertext)
{
	static phpass_salt salt;
	salt.rounds = 1 << atoi64[ARCH_INDEX(ciphertext[3])];
	memcpy(salt.salt, &ciphertext[4], 8);
	return &salt;
}

static void set_salt(void *salt)
{
	memcpy(&currentsalt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	int i, len = strlen(key);
	inbuffer[address(15, index)] = len;
	for (i = 0; i < len; i++)
		inbuffer[address(i, index)] = key[i];
}

static char *get_key(int index)
{
	static char r[PHPASS_GPU_PLAINTEXT_LENGTH + 1];
	int i;
	for (i = 0; i < PHPASS_GPU_PLAINTEXT_LENGTH; i++)
		r[i] = inbuffer[address(i, index)];
	r[inbuffer[address(15, index)]] = '\0';
	return r;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	memset(outbuffer, 0, sizeof(phpass_crack) * KEYS_PER_CRYPT);
	gpu_phpass(inbuffer, &currentsalt, outbuffer, *pcount);
	return *pcount;
}

static int cmp_all(void *binary, int count)
{
	int i;
	unsigned int *b32 = (unsigned int *)binary;
	for(i=0; i < count; i++)
		if(outbuffer[i].hash[0] == b32[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	unsigned int *b32 = (unsigned int *)binary;
	for(i=0; i < 4; i++)
		if(outbuffer[index].hash[i] != b32[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int get_hash_0(int index) { return outbuffer[index].hash[0] & PH_MASK_0; }
static int get_hash_1(int index) { return outbuffer[index].hash[0] & PH_MASK_1; }
static int get_hash_2(int index) { return outbuffer[index].hash[0] & PH_MASK_2; }
static int get_hash_3(int index) { return outbuffer[index].hash[0] & PH_MASK_3; }
static int get_hash_4(int index) { return outbuffer[index].hash[0] & PH_MASK_4; }
static int get_hash_5(int index) { return outbuffer[index].hash[0] & PH_MASK_5; }
static int get_hash_6(int index) { return outbuffer[index].hash[0] & PH_MASK_6; }

struct fmt_main fmt_cuda_phpass = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PHPASS_GPU_PLAINTEXT_LENGTH,
		PHPASS_BINARY_SIZE,
		PHPASS_BINARY_ALIGN,
		SALT_SIZE,
		PHPASS_SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{
			"iteration count",
		},
		{ NULL },
		phpass_common_tests_15
	}, {
		init,
		done,
		fmt_default_reset,
		phpass_common_prepare,
		phpass_common_valid,
		phpass_common_split,
		phpass_common_binary,
		get_salt,
		{
			phpass_common_iteration_count,
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
		fmt_default_salt_hash,
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

#endif /* HAVE_CUDA */

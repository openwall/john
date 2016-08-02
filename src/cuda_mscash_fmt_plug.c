/*
 * This software is Copyright (c) 2011 Lukas Odzioba
 * <lukas dot odzioba at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Alain Espinosa implementation http://openwall.info/wiki/john/MSCash
 */
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_mscash;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_mscash);
#else

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_mscash.h"
#include "cuda_common.h"
#include "unicode.h"
#include "mscash_common.h"
#include "memdbg.h"

#define FORMAT_LABEL		"mscash-cuda"
#define FORMAT_NAME		"MS Cache Hash (DCC)"
#define ALGORITHM_NAME		"MD4 CUDA (inefficient, development use only)"

static mscash_password *inbuffer;
static mscash_hash *outbuffer;
static mscash_salt currentsalt;

extern void cuda_mscash(mscash_password *, mscash_hash *, mscash_salt *, int);

static void done(void)
{
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
}

static void set_key(char *_key, int index);
static void *get_salt(char *_ciphertext);

static void init(struct fmt_main *self)
{
	//Allocate memory for hashes and passwords
	inbuffer = (mscash_password *) mem_calloc(MAX_KEYS_PER_CRYPT,
	                                          sizeof(mscash_password));
	outbuffer =
	    (mscash_hash *) mem_alloc(MAX_KEYS_PER_CRYPT * sizeof(mscash_hash));
	check_mem_allocation(inbuffer, outbuffer);
	//Initialize CUDA
	cuda_init();

	mscash1_adjust_tests(self, options.target_enc, PLAINTEXT_LENGTH,
	                     set_key, set_key, get_salt, get_salt);
}

static void *get_salt(char *ciphertext)
{
	static mscash_salt salt;
	UTF8 insalt[MSCASH1_MAX_SALT_LENGTH + 1];
	char *pos = ciphertext + strlen(mscash_prefix);
	char *end = strrchr(ciphertext, '#');
	int length = 0;

	memset(&salt, 0, sizeof(salt));
	while (pos < end)
		insalt[length++] = *pos++;
	insalt[length] = 0;

	enc_to_utf16(salt.salt, MSCASH1_MAX_SALT_LENGTH, insalt, length);
	salt.length = length;

	return &salt;
}

static void set_salt(void *salt)
{
	memcpy(&currentsalt, salt, sizeof(mscash_salt));
}

static void set_key(char *key, int index)
{
	int length;

	length = enc_to_utf16(inbuffer[index].v,
	                      PLAINTEXT_LENGTH,
	                      (UTF8*)key,
	                      strlen(key));

	if (length < 0)
		length = strlen16(inbuffer[index].v);

	inbuffer[index].length = length;
}

static char *get_key(int index)
{
	UTF16 ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;

	memcpy(ret, inbuffer[index].v, 2 * length);
	ret[length] = 0;
	return (char*)utf16_to_enc(ret);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	cuda_mscash(inbuffer, outbuffer, &currentsalt, count);
	return count;
}

static int get_hash_0(int index)
{
	return outbuffer[index].v[0] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	return outbuffer[index].v[0] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	return outbuffer[index].v[0] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	return outbuffer[index].v[0] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	return outbuffer[index].v[0] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	return outbuffer[index].v[0] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	return outbuffer[index].v[0] & PH_MASK_6;
}


static int cmp_all(void *binary, int count)
{
	uint32_t i, b = ((uint32_t *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	uint32_t i, *b = (uint32_t *) binary;
	for (i = 0; i < 4; i++)
		if (b[i] != outbuffer[index].v[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_cuda_mscash = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
		{ NULL },
		{ NULL },
		mscash1_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		mscash1_common_prepare,
		mscash1_common_valid,
		mscash1_common_split,
		mscash_common_binary,
		get_salt,
		{ NULL },
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

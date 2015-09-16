/*
* This software is Copyright (c) 2011 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_cryptsha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_cryptsha512);
#else

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_cryptsha512.h"
#include "cuda_common.h"
// these MUST be defined prior to loading cryptsha512_valid.h
#define BINARY_SIZE			64
#define SALT_LENGTH			16
#define CIPHERTEXT_LENGTH		86
#define __CRYPTSHA512_CREATE_PROPER_TESTS_ARRAY__
#include "cryptsha512_common.h"
#include "memdbg.h"

#define FORMAT_LABEL		"sha512crypt-cuda"
#define FORMAT_NAME		"crypt(3) $6$"

#define ALGORITHM_NAME		"SHA512 CUDA (inefficient, please use sha512crypt-opencl instead)"

#define BENCHMARK_COMMENT	" (rounds=5000)"
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	15
#define MD5_DIGEST_LENGTH 	16

#define BINARY_ALIGN		8
#define SALT_ALIGN			sizeof(uint32_t)

#define SALT_SIZE		(3+7+9+16)

#define MIN_KEYS_PER_CRYPT	THREADS
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

static crypt_sha512_password *inbuffer;		/** plaintext ciphertexts **/
static crypt_sha512_hash *outbuffer;		/** calculated hashes **/

void sha512_crypt_gpu(crypt_sha512_password * inbuffer,
	crypt_sha512_hash *outbuffer, crypt_sha512_salt *host_salt, int count);

static char currentsalt[64];
static crypt_sha512_salt _salt;

static void done(void)
{
 MEM_FREE(inbuffer);
 MEM_FREE(outbuffer);
}

static void init(struct fmt_main *self)
{
  //Allocate memory for hashes and passwords
  inbuffer = (crypt_sha512_password*)mem_calloc(MAX_KEYS_PER_CRYPT,
                                                sizeof(crypt_sha512_password));
  outbuffer=(crypt_sha512_hash*)mem_alloc(MAX_KEYS_PER_CRYPT*sizeof(crypt_sha512_hash));
  check_mem_allocation(inbuffer,outbuffer);
  //Initialize CUDA
  cuda_init();
}

static void *get_salt(char *ciphertext)
{
	int end = 0, i, len = strlen(ciphertext);
	static unsigned char ret[50];

	memset(ret, 0, sizeof(ret));
	for (i = len - 1; i >= 0; i--)
		if (ciphertext[i] == '$') {
			end = i;
			break;
		}

	for (i = 0; i < end; i++)
		ret[i] = ciphertext[i];
	ret[end] = 0;
	return (void *) ret;
}

static void set_salt(void *salt)
{
	unsigned char *s = salt;
	int len = strlen(salt);
	unsigned char offset = 0;
	_salt.rounds = ROUNDS_DEFAULT;
	memcpy(currentsalt,s,len+1);

	if (strncmp((char *) "$6$", (char *) currentsalt, 3) == 0)
		offset += 3;

	if (strncmp((char *) currentsalt + offset, (char *) "rounds=", 7) == 0) {
		const char *num = currentsalt + offset + 7;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			endp += 1;
			_salt.rounds =
			    MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
		}
		offset = endp - currentsalt;
	}
	memcpy(_salt.salt, currentsalt + offset, 16);
	_salt.saltlen = strlen(_salt.salt);
}

static void set_key(char *key, int index)
{
	int len = strlen(key);
	inbuffer[index].length = len;
	memcpy(inbuffer[index].v, key, len);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, PLAINTEXT_LENGTH);
	ret[inbuffer[index].length] = '\0';
	return ret;
}


static void gpu_crypt_all(int count)
{
	sha512_crypt_gpu(inbuffer, outbuffer, &_salt, count);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	gpu_crypt_all(count);
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
	uint32_t i;
	uint64_t b = ((uint64_t *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint64_t *t = (uint64_t *) binary;
	for (i = 0; i < 8; i++) {
		if (t[i] != outbuffer[index].v[i])
			return 0;
	}
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

/*
// iteration count as tunable cost parameter
static unsigned int iteration_count(void *salt)
{
	crypt_sha512_salt *sha512crypt_salt;

	sha512crypt_salt = salt;
	return (unsigned int)sha512crypt_salt->rounds;
}
*/

struct fmt_main fmt_cuda_cryptsha512 = {
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
		FMT_CASE | FMT_8_BIT,
		{
			NULL, //"iteration count"
		},
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
			NULL, //iteration_count,
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

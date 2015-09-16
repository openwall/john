/*
* This software is Copyright (c) 2011 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_cryptsha256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_cryptsha256);
#else

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <string.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_common.h"

#define __CRYPTSHA256_CREATE_PROPER_TESTS_ARRAY__
#include "cuda_cryptsha256.h"
#include "cryptsha256_common.h"
#include "memdbg.h"

#define FORMAT_LABEL		"sha256crypt-cuda"
#define ALGORITHM_NAME		"SHA256 CUDA (inefficient, please use sha256crypt-opencl instead)"

#define SALT_SIZE		(3+7+9+16)

#define MIN_KEYS_PER_CRYPT	THREADS
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

extern void sha256_crypt_gpu(crypt_sha256_password * inbuffer,
	uint32_t * outbuffer, crypt_sha256_salt * host_salt, int count);

static crypt_sha256_password *inbuffer;//[MAX_KEYS_PER_CRYPT];			/** plaintext ciphertexts **/
static uint32_t *outbuffer;//[MAX_KEYS_PER_CRYPT * 8];				/** calculated hashes **/

static char currentsalt[64];
static crypt_sha256_salt host_salt;

void sha256_crypt_cpu(crypt_sha256_password * passwords,
    crypt_sha256_hash * output, crypt_sha256_salt * salt);

static void done(void)
{
 MEM_FREE(inbuffer);
 MEM_FREE(outbuffer);
}

static void init(struct fmt_main *self)
{
  //Allocate memory for hashes and passwords
  inbuffer=(crypt_sha256_password*)mem_calloc(MAX_KEYS_PER_CRYPT,
                                              sizeof(crypt_sha256_password));
  outbuffer=(uint32_t*)mem_alloc(MAX_KEYS_PER_CRYPT*sizeof(uint32_t)*8);
  check_mem_allocation(inbuffer,outbuffer);
  //Initialize CUDA
  cuda_init();
}

static void *get_salt(char *ciphertext)
{
	int end = 0, i, len = strlen(ciphertext);
	static unsigned char ret[SALT_SIZE];

	memset(ret, 0, sizeof(ret));
	for (i = len - 1; i >= 0; i--)
		if (ciphertext[i] == '$') {
			end = i;
			break;

		}

	if (end > SALT_LENGTH + 3) /* +3 for $5$ */
		end = SALT_LENGTH + 3;

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
	memcpy(currentsalt,s,len+1);
	host_salt.rounds = ROUNDS_DEFAULT;

	if (strncmp((char *) "$5$", (char *) currentsalt, 3) == 0)
		offset += 3;

	if (strncmp((char *) currentsalt + offset, (char *) "rounds=", 7) == 0)
	{
		const char *num = currentsalt + offset + 7;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			endp += 1;
			host_salt.rounds =
			    MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
		}
		offset = endp - currentsalt;
	}
	memcpy(host_salt.salt, currentsalt + offset, 16);
	host_salt.saltlen = strlen(host_salt.salt);
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	sha256_crypt_gpu(inbuffer, outbuffer, &host_salt, count);
	return count;
}

static int get_hash_0(int index)
{

	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & PH_MASK_6;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i;
	uint32_t b = ((uint32_t *) binary)[0];
	uint32_t *out = outbuffer;
	for (i = 0; i < count; i++)
		if (b == out[hash_addr(0, i)])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	uint32_t *out = outbuffer;

	for (i = 0; i < 8; i++)
		if (t[i] != out[hash_addr(i, index)])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

/* Commented out due to bugs
// iteration count as tunable cost parameter
static unsigned int iteration_count(void *salt)
{
	crypt_sha256_salt *sha256crypt_salt;

	sha256crypt_salt = salt;
	return (unsigned int)sha256crypt_salt->rounds;
}
*/

struct fmt_main fmt_cuda_cryptsha256 = {
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
		MEM_ALIGN_NONE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{
			NULL, //"iteration count",
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

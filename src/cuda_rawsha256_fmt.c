/*
* This software is Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* This file is shared by raw-sha224-cuda and raw-sha256-cuda formats,
* SHA256 definition is used to distinguish between them.
*/
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_common.h"
#include "cuda_rawsha256.h"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1	/// Raw benchmark
#define PLAINTEXT_LENGTH	19
#define SALT_SIZE		0

#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

#ifdef SHA256
#define FORMAT_LABEL		"raw-sha256-cuda"
#define FORMAT_NAME		"Raw SHA-256"
#define CIPHERTEXT_LENGTH	64	///256bit
#define BINARY_SIZE		32
#define SHA_HASH		sha256_hash
#define TESTS			sha256_tests
#define FMT_MAIN		fmt_cuda_rawsha256
static struct fmt_tests sha256_tests[] = {
	{"a49c2c9d0c006c8cb55a9a7a38822b83e0cd442614cb416af952fa50156761dc",
	    "openwall"},
	{NULL}
};
#endif
#ifdef SHA224
#define FORMAT_LABEL		"raw-sha224-cuda"
#define FORMAT_NAME		"Raw SHA-224"
#define CIPHERTEXT_LENGTH	56	///224bit
#define BINARY_SIZE		32
#define SHA_HASH 		sha224_hash
#define TESTS			sha224_tests
#define FMT_MAIN		fmt_cuda_rawsha224
static struct fmt_tests sha224_tests[] = {
	{"d6d8ff02342ea04cf65f8ab446b22c4064984c29fe86f858360d0319",
	    "openwall"},
	{NULL}
};
#endif
#define ALGORITHM_NAME		"CUDA"

extern void gpu_rawsha256(sha256_password *, SHA_HASH *, int);
extern void gpu_rawsha224(sha256_password *, SHA_HASH *, int);
extern void *cuda_pageLockedMalloc(void *, unsigned int);
extern void cuda_pageLockedFree(void *);
extern int cuda_getAsyncEngineCount();

static sha256_password *inbuffer;			/** binary ciphertexts **/
static SHA_HASH *outbuffer;				/** calculated hashes **/
static int overlap;
static void cleanup()
{
	if (overlap) {
		cuda_pageLockedFree(inbuffer);
		cuda_pageLockedFree(outbuffer);
	} else {
		free(inbuffer);
		free(outbuffer);
	}
}

static void init(struct fmt_main *pFmt)
{
	cuda_init(gpu_id);
	if (cuda_getAsyncEngineCount() > 0) {
		overlap = 1;
		inbuffer =
		    cuda_pageLockedMalloc(inbuffer,
		    sizeof(sha256_password) * MAX_KEYS_PER_CRYPT);
		outbuffer =
		    cuda_pageLockedMalloc(outbuffer,
		    sizeof(SHA_HASH) * MAX_KEYS_PER_CRYPT);
	} else {
		overlap = 0;
		//device does not support overlaping memcpy and kernel execution
		inbuffer =
		    (sha256_password *) malloc(sizeof(sha256_password) *
		    MAX_KEYS_PER_CRYPT);
		outbuffer =
		    (SHA_HASH *) malloc(sizeof(SHA_HASH) * MAX_KEYS_PER_CRYPT);
	}
	check_mem_allocation(inbuffer, outbuffer);
	atexit(cleanup);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++) {
		if (!((ciphertext[i] >= '0' && ciphertext[i] <= '9') ||
			(ciphertext[i] >= 'a' && ciphertext[i] <= 'f') ||
			(ciphertext[i] >= 'A' && ciphertext[i] <= 'Z')))
			return 0;
	}
	return 1;
};


static void *binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	int i;
	memset(realcipher, 0, BINARY_SIZE);
	for (i = 0; i < BINARY_SIZE; i += 4) {
		realcipher[i] =
		    atoi16[ARCH_INDEX(ciphertext[(i + 3) * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[(i + 3) * 2 + 1])];
		realcipher[i + 1] =
		    atoi16[ARCH_INDEX(ciphertext[(i + 2) * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[(i + 2) * 2 + 1])];
		realcipher[i + 2] =
		    atoi16[ARCH_INDEX(ciphertext[(i + 1) * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[(i + 1) * 2 + 1])];
		realcipher[i + 3] =
		    atoi16[ARCH_INDEX(ciphertext[(i) * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[(i) * 2 + 1])];
	}
	return (void *) realcipher;
}

static int binary_hash_0(void *binary)
{
	return (((ARCH_WORD_32 *) binary)[0] & 0xf);
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0x7ffffff;
}

static void set_salt(void *salt)
{
}

static void set_key(char *key, int index)
{
	memset(inbuffer[index].v, 0, PLAINTEXT_LENGTH);
	memcpy(inbuffer[index].v, key, PLAINTEXT_LENGTH);
	inbuffer[index].length = strlen(key);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, inbuffer[index].length);
	ret[inbuffer[index].length] = 0;
	return ret;
}

static void crypt_all(int count)
{
#ifdef SHA256
	gpu_rawsha256(inbuffer, outbuffer, overlap);
#else
	gpu_rawsha224(inbuffer, outbuffer, overlap);
#endif
}

static int get_hash_0(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xf;
}

static int get_hash_1(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xff;
}

static int get_hash_2(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xfff;
}

static int get_hash_3(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xffff;
}

static int get_hash_4(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xfffff;
}

static int get_hash_5(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xffffff;
}

static int get_hash_6(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i;
	uint32_t b = ((uint32_t *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	for (i = 0; i < CIPHERTEXT_LENGTH / 8; i++)
		if (t[i] != outbuffer[index].v[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

struct fmt_main FMT_MAIN = {
	{
		    FORMAT_LABEL,
		    FORMAT_NAME,
		    ALGORITHM_NAME,
		    BENCHMARK_COMMENT,
		    BENCHMARK_LENGTH,
		    PLAINTEXT_LENGTH,
		    BINARY_SIZE,
		    SALT_SIZE,
		    MIN_KEYS_PER_CRYPT,
		    MAX_KEYS_PER_CRYPT,
		    FMT_CASE | FMT_8_BIT,
		    TESTS
	},
	{
		    init,
		    fmt_default_prepare,
		    valid,
		    fmt_default_split,
		    binary,
		    fmt_default_salt,
		    {
				binary_hash_0,
				binary_hash_1,
				binary_hash_2,
				binary_hash_3,
				binary_hash_4,
				binary_hash_5,
				binary_hash_6
		    },
		    fmt_default_salt_hash,
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

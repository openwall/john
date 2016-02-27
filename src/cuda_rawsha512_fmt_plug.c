/*
 * SHA-512 hashing, CUDA interface.
 * Please note that in current comparison function, we use computed a77
 * compares with ciphertext d80. For more details, refer to:
 * http://www.openwall.com/lists/john-dev/2012/04/11/13
 *
 * Copyright (c) 2012 myrice (interfacing to CUDA)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_rawsha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_rawsha512);
#else

#include <string.h>

#include "stdint.h"
#include "arch.h"
#include "sha2.h"
#include "cuda_rawsha512.h"
#include "cuda_common.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "rawSHA512_common.h"
#include "memdbg.h"

#define FORMAT_LABEL			"Raw-SHA512-cuda"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"SHA512 CUDA (inefficient, development use mostly)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define BINARY_ALIGN		sizeof(uint64_t)
#define SALT_ALIGN			1


extern void cuda_sha512(sha512_key *host_password, sha512_hash* host_hash,
                        int count);
extern void cuda_sha512_init();
extern int cuda_sha512_cmp_all(void *binary, int count);
extern void cuda_sha512_cpy_hash(sha512_hash* host_hash);

static sha512_key *gkey;
static sha512_hash *ghash;
uint8_t sha512_key_changed;
static uint8_t hash_copy_back;

static void done(void)
{
	MEM_FREE(ghash);
	MEM_FREE(gkey);
}

static void init(struct fmt_main *self)
{
	gkey = mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(sha512_key));
	ghash = mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(sha512_hash));

	cuda_init();
	cuda_sha512_init();
}

static void copy_hash_back()
{
    if (!hash_copy_back) {
        cuda_sha512_cpy_hash(ghash);
        hash_copy_back = 1;
    }
}

static int binary_hash_0(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_0;
}

static int binary_hash_1(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_1;
}

static int binary_hash_2(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_2;
}

static int binary_hash_3(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_3;
}

static int binary_hash_4(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_4;
}

static int binary_hash_5(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_5;
}

static int binary_hash_6(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_6;
}

static int get_hash_0(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_6;
}

static void set_key(char *key, int index)
{
	int length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	gkey[index].length = length;
	memcpy(gkey[index].v, key, length);
	sha512_key_changed = 1;
}

static char *get_key(int index)
{
	gkey[index].v[gkey[index].length] = 0;
	return gkey[index].v;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	cuda_sha512(gkey, ghash, count);
	sha512_key_changed = 0;
	hash_copy_back = 0;
	return count;
}

static int cmp_all(void *binary, int count)
{
	return cuda_sha512_cmp_all(binary, count);
}

static int cmp_one(void *binary, int index)
{
	uint64_t *t,*b = (uint64_t *) binary;
	copy_hash_back();
	t = (uint64_t *)ghash;
	if (b[3] != t[hash_addr(0, index)])
		return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	SHA512_CTX ctx;
	uint64_t crypt_out[8];
	int i;
	uint64_t *b,*c;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, gkey[index].v, gkey[index].length);
	SHA512_Final((unsigned char *)(crypt_out), &ctx);
#ifdef SIMD_COEF_64
	alter_endianity_to_BE64(crypt_out, 8);
#endif

	b = (uint64_t *)sha512_common_binary(source);
	c = (uint64_t *)crypt_out;

	for (i = 0; i < FULL_BINARY_SIZE / 8; i++) { //examin 512bits
		if (b[i] != c[i])
			return 0;
	}
	return 1;

}

struct fmt_main fmt_cuda_rawsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		FULL_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		sha512_common_tests_rawsha512_20
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		sha512_common_valid,
		sha512_common_split,
		sha512_common_binary_rev,
		fmt_default_salt,
		{ NULL },
		fmt_default_source,
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
		NULL,
		fmt_default_set_salt,
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

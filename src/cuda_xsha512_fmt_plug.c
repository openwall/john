/*
 * Mac OS X 10.7+ salted SHA-512 password hashing, CUDA interface.
 * Please note that in current comparison function, we use computed a77
 * compares with ciphertext d80. For more details, refer to:
 * http://www.openwall.com/lists/john-dev/2012/04/11/13
 *
 * Copyright (c) 2008,2011 Solar Designer (original CPU-only code)
 * Copyright (c) 2012 myrice (interfacing to CUDA)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_xsha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_xsha512);
#else

#include <string.h>
#include <assert.h>

#include "stdint.h"
#include "arch.h"
#include "sha2.h"
#include "cuda_xsha512.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "cuda_common.h"
#include "rawSHA512_common.h"
#include "memdbg.h"

#define FORMAT_LABEL			"xsha512-cuda"
#define FORMAT_NAME			"Mac OS X 10.7+"
#define ALGORITHM_NAME			"SHA512 CUDA (efficient at \"many salts\" only)"

#define BENCHMARK_COMMENT		""

extern void cuda_xsha512(xsha512_key * host_password,
    xsha512_salt * host_salt,
    xsha512_hash * host_hash,
    xsha512_extend_key * host_ext_password, int count);

extern void cuda_xsha512_init();
extern int cuda_cmp_all(void *binary, int count);
extern void cuda_xsha512_cpy_hash(xsha512_hash * host_hash);

static xsha512_key *gkey;
static xsha512_extend_key *g_ext_key;
static xsha512_hash *ghash;
static xsha512_salt gsalt;
uint8_t xsha512_key_changed = 0;
uint8_t use_extend = 0;

static void done(void)
{
	/* FIXME: How do we de-init cuda stuff? */
	MEM_FREE(ghash);
	MEM_FREE(g_ext_key);
	MEM_FREE(gkey);
}

static void init(struct fmt_main *self)
{
	gkey = mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(xsha512_key));
	g_ext_key = mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(xsha512_extend_key));
	ghash = mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(xsha512_hash));

	cuda_init();
	cuda_xsha512_init();
}

static void *get_salt(char *ciphertext)
{
	static unsigned char out[SALT_SIZE];
	char *p;
	int i;

	ciphertext += 6;
	p = ciphertext;
	for (i = 0; i < sizeof(out); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary)
{
	return *((ARCH_WORD_32 *) binary + 6) & PH_MASK_0;
}

static int binary_hash_1(void *binary)
{
	return *((ARCH_WORD_32 *) binary + 6) & PH_MASK_1;
}

static int binary_hash_2(void *binary)
{
	return *((ARCH_WORD_32 *) binary + 6) & PH_MASK_2;
}

static int binary_hash_3(void *binary)
{
	return *((ARCH_WORD_32 *) binary + 6) & PH_MASK_3;
}

static int binary_hash_4(void *binary)
{
	return *((ARCH_WORD_32 *) binary + 6) & PH_MASK_4;
}

static int binary_hash_5(void *binary)
{
	return *((ARCH_WORD_32 *) binary + 6) & PH_MASK_5;
}

static int binary_hash_6(void *binary)
{
	return *((ARCH_WORD_32 *) binary + 6) & PH_MASK_6;
}

static int get_hash_0(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t *) ghash)[hash_addr(0, index)] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t *) ghash)[hash_addr(0, index)] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t *) ghash)[hash_addr(0, index)] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t *) ghash)[hash_addr(0, index)] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t *) ghash)[hash_addr(0, index)] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t *) ghash)[hash_addr(0, index)] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t *) ghash)[hash_addr(0, index)] & PH_MASK_6;
}

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32 *) salt & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	memcpy(gsalt.v, (uint8_t *) salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	int length = strlen(key);
	if (index == 0)
		use_extend = 0;
	if (length > MAX_PLAINTEXT_LENGTH)
		length = MAX_PLAINTEXT_LENGTH;
	gkey[index].length = length;
	if (length > PLAINTEXT_LENGTH) {
		memcpy(gkey[index].v, key, PLAINTEXT_LENGTH);
		key += PLAINTEXT_LENGTH;
		memcpy(g_ext_key[index], key, length - PLAINTEXT_LENGTH);
		if (!use_extend)
			use_extend = 1;
	} else
		memcpy(gkey[index].v, key, length);
	if (!xsha512_key_changed)
		xsha512_key_changed = 1;
}

static char *get_key(int index)
{
	static char key[MAX_PLAINTEXT_LENGTH + 1];
	if (gkey[index].length > PLAINTEXT_LENGTH) {
		memcpy(key, gkey[index].v, PLAINTEXT_LENGTH);
		memcpy(key+PLAINTEXT_LENGTH, g_ext_key[index], EXTEND_PLAINTEXT_LENGTH);
		key[gkey[index].length] = 0;
		return key;
	}
	else {
		gkey[index].v[gkey[index].length] = 0;
		return gkey[index].v;
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	cuda_xsha512(gkey, &gsalt, ghash, g_ext_key, count);
	xsha512_key_changed = 0;
        return count;
}

static int cmp_all(void *binary, int count)
{
	int t1 = cuda_cmp_all(binary, count);
	return t1;
}

static int cmp_one(void *binary, int index)
{
	uint64_t *b = (uint64_t *) binary;
	uint64_t *t = (uint64_t *) ghash;
	cuda_xsha512_cpy_hash(ghash);
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
	SHA512_Update(&ctx, gsalt.v, SALT_SIZE);
	if (gkey[index].length > PLAINTEXT_LENGTH) {
		SHA512_Update(&ctx, gkey[index].v, PLAINTEXT_LENGTH);
		SHA512_Update(&ctx, g_ext_key[index],
		    gkey[index].length - PLAINTEXT_LENGTH);
	} else
		SHA512_Update(&ctx, gkey[index].v, gkey[index].length);
	SHA512_Final((unsigned char *) (crypt_out), &ctx);
#ifdef SIMD_COEF_64
	alter_endianity_to_BE64(crypt_out, 8);
#endif

	b = (uint64_t *) sha512_common_binary_xsha512(source);
	c = (uint64_t *) crypt_out;

	for (i = 0; i < FULL_BINARY_SIZE / 8; i++) {	//examin 512bits
		if (b[i] != c[i])
			return 0;
	}
	return 1;

}

struct fmt_main fmt_cuda_xsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		XSHA512_BENCHMARK_LENGTH,
		0,
		MAX_PLAINTEXT_LENGTH,
		FULL_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		sha512_common_tests_xsha512
	}, {
		init,
		done,
		fmt_default_reset,
		sha512_common_prepare_xsha512,
		sha512_common_valid_xsha512,
		sha512_common_split_xsha512,
		sha512_common_binary_xsha512_rev,
		get_salt,
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

#endif /* HAVE_CUDA */

/*
 * This software is Copyright (c) 2012, 2013 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 *
 * Originally based on hmac-md5 by Bartavelle
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt__hmacSHA1;
#elif FMT_REGISTERS_H
john_register_one(&fmt__hmacSHA1);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL            "HMAC-SHA1"
#define FORMAT_NAME             ""

#ifdef SIMD_COEF_32
#define SHA1_N                  (SIMD_PARA_SHA1 * SIMD_COEF_32)
#endif

#define ALGORITHM_NAME          "password is key, SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7

#define PLAINTEXT_LENGTH        125

#define PAD_SIZE                64
#define BINARY_SIZE             20
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_LENGTH             PAD_SIZE
#define SALT_ALIGN              MEM_ALIGN_NONE
#define CIPHERTEXT_LENGTH       (2 * SALT_LENGTH + 2 * BINARY_SIZE)

#define HEXCHARS                "0123456789abcdef"

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SHA1_N
#define MAX_KEYS_PER_CRYPT      (SHA1_N * 1024)
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i) & (0xffffffff - 3)) * SIMD_COEF_32 + (3 - ((i) & 3)) + (unsigned int)index/SIMD_COEF_32 * SHA_BUF_SIZ * 4 * SIMD_COEF_32)
#else
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i) & (0xffffffff - 3)) * SIMD_COEF_32 + ((i) & 3) + (unsigned int)index/SIMD_COEF_32 * SHA_BUF_SIZ * 4 * SIMD_COEF_32)
#endif

#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      512
#endif

#ifndef OMP_SCALE
#define OMP_SCALE 4 // tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	{"The quick brown fox jumps over the lazy dog#de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9", "key"},
	{"#fbdb1d1b18aa6c08324b7d64b71fb76370690e1d", ""},
	{"Beppe#Grillo#DEBBDB4D549ABE59FAB67D0FB76B76FDBC4431F1", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	{"7oTwG04WUjJ0BTDFFIkTJlgl#293b75c1f28def530c17fc8ae389008179bf4091", "late*night"}, // from the test suite
	{"D2hIU7fdd78WARm5dt95k6MD#e741a6100ccfd1205a8ffe1321b61fc5aa06f6db", "123"},
	{"6Fv5kYoxuEuroTkagbf3ZRsV#370edad3540b1ad3e96b03ccf3956645306074b7", "123456789"},
	{"3uqqtMBC7vzh9tdVMPJ9bAwE#65ed35cf94e2180d6a797e5ad5e4175891427572", "passWOrd"},
	{NULL}
};

#ifdef SIMD_COEF_32
#define cur_salt hmacsha1_cur_salt
static unsigned char *crypt_key;
static unsigned char *ipad, *prep_ipad;
static unsigned char *opad, *prep_opad;
JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char cur_salt[SHA_BUF_SIZ * 4 * SHA1_N];
static int bufsize;
#else
static unsigned char cur_salt[SALT_LENGTH];

static uint32_t (*crypt_key)[BINARY_SIZE / sizeof(uint32_t)];
static unsigned char (*ipad)[PAD_SIZE];
static unsigned char (*opad)[PAD_SIZE];
static SHA_CTX *ipad_ctx;
static SHA_CTX *opad_ctx;
#endif
static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int new_keys;

#define SALT_SIZE               sizeof(cur_salt)

#ifdef SIMD_COEF_32
static void clear_keys(void)
{
	memset(ipad, 0x36, bufsize);
	memset(opad, 0x5C, bufsize);
}
#endif

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_32
	unsigned int i;
#endif

	omp_autotune(self, OMP_SCALE);

#ifdef SIMD_COEF_32
	bufsize = sizeof(*opad) * self->params.max_keys_per_crypt * SHA_BUF_SIZ * 4;
	crypt_key = mem_calloc_align(1, bufsize, MEM_ALIGN_SIMD);
	ipad = mem_calloc_align(1, bufsize, MEM_ALIGN_SIMD);
	opad = mem_calloc_align(1, bufsize, MEM_ALIGN_SIMD);
	prep_ipad = mem_calloc_align(self->params.max_keys_per_crypt *
	                             BINARY_SIZE,
	                             sizeof(*prep_ipad), MEM_ALIGN_SIMD);
	prep_opad = mem_calloc_align(self->params.max_keys_per_crypt *
	                             BINARY_SIZE,
	                             sizeof(*prep_opad), MEM_ALIGN_SIMD);
	for (i = 0; i < self->params.max_keys_per_crypt; ++i) {
		crypt_key[GETPOS(BINARY_SIZE, i)] = 0x80;
		((unsigned int*)crypt_key)[15 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32] = (BINARY_SIZE + 64) << 3;
	}
	clear_keys();
#else
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
	ipad = mem_calloc(self->params.max_keys_per_crypt, sizeof(*ipad));
	opad = mem_calloc(self->params.max_keys_per_crypt, sizeof(*opad));
	ipad_ctx = mem_calloc(self->params.max_keys_per_crypt,
	                      sizeof(*ipad_ctx));
	opad_ctx = mem_calloc(self->params.max_keys_per_crypt,
	                      sizeof(*opad_ctx));
#endif
	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
}

static void done(void)
{
	MEM_FREE(saved_plain);
#ifdef SIMD_COEF_32
	MEM_FREE(prep_opad);
	MEM_FREE(prep_ipad);
#else
	MEM_FREE(opad_ctx);
	MEM_FREE(ipad_ctx);
#endif
	MEM_FREE(opad);
	MEM_FREE(ipad);
	MEM_FREE(crypt_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	int extra;

	p = strrchr(ciphertext, '#'); /* search backwards to allow '#' in salt */
	if (!p)
		return 0;
	if (p - ciphertext > SALT_LENGTH)
		return 0;
#if SIMD_COEF_32
	if (p - ciphertext > 55)
		return 0;
#endif
	if (hexlen(++p, &extra) != BINARY_SIZE * 2 || extra)
		return 0;
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	if (strnlen(ciphertext, LINE_BUFFER_SIZE) < LINE_BUFFER_SIZE &&
	    strstr(ciphertext, "$SOURCE_HASH$"))
		return ciphertext;

	strnzcpy(out, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(strrchr(out, '#'));

	return out;
}

static void set_salt(void *salt)
{
	memcpy(&cur_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	int len;
#ifdef SIMD_COEF_32
#if ARCH_LITTLE_ENDIAN==1
	uint32_t *ipadp = (uint32_t*)&ipad[GETPOS(3, index)];
	uint32_t *opadp = (uint32_t*)&opad[GETPOS(3, index)];
#else
	uint32_t *ipadp = (uint32_t*)&ipad[GETPOS(0, index)];
	uint32_t *opadp = (uint32_t*)&opad[GETPOS(0, index)];
#endif
	const uint32_t *keyp = (uint32_t*)key;
	unsigned int temp;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	if (len > PAD_SIZE) {
		unsigned char k0[BINARY_SIZE];
		SHA_CTX ctx;
		int i;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, key, len);
		SHA1_Final(k0, &ctx);

		keyp = (unsigned int*)k0;
		for (i = 0; i < BINARY_SIZE / 4; i++, ipadp += SIMD_COEF_32, opadp += SIMD_COEF_32)
		{
#if ARCH_LITTLE_ENDIAN==1
			temp = JOHNSWAP(*keyp++);
#else
			temp = *keyp++;
#endif
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	}
	else
#if ARCH_LITTLE_ENDIAN==1
	while(((temp = JOHNSWAP(*keyp++)) & 0xff000000)) {
#else
	while(((temp = *keyp++) & 0xff000000)) {
#endif
		if (!(temp & 0x00ff0000) || !(temp & 0x0000ff00))
		{
#if ARCH_LITTLE_ENDIAN==1
			((unsigned short*)ipadp)[1] ^=
				(unsigned short)(temp >> 16);
			((unsigned short*)opadp)[1] ^=
				(unsigned short)(temp >> 16);
#else
			((unsigned short*)ipadp)[0] ^=
				(unsigned short)(temp >> 16);
			((unsigned short*)opadp)[0] ^=
				(unsigned short)(temp >> 16);
#endif
			break;
		}
		*ipadp ^= temp;
		*opadp ^= temp;
		if (!(temp & 0x000000ff))
			break;
		ipadp += SIMD_COEF_32;
		opadp += SIMD_COEF_32;
	}
#else
	int i;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	memset(ipad[index], 0x36, PAD_SIZE);
	memset(opad[index], 0x5C, PAD_SIZE);

	if (len > PAD_SIZE) {
		SHA_CTX ctx;
		unsigned char k0[BINARY_SIZE];

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, key, len);
		SHA1_Final(k0, &ctx);

		len = BINARY_SIZE;

		for (i = 0; i < len; i++)
		{
			ipad[index][i] ^= k0[i];
			opad[index][i] ^= k0[i];
		}
	}
	else
	for (i = 0; i < len; i++)
	{
		ipad[index][i] ^= key[i];
		opad[index][i] ^= key[i];
	}
#endif
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_plain[index];
}

static int cmp_all(void *binary, int count)
{
#ifdef SIMD_COEF_32
	unsigned int x, y;

	for (y = 0; y < (unsigned int)(count + SIMD_COEF_32 - 1) / SIMD_COEF_32; y++) {
		for (x = 0; x < SIMD_COEF_32; x++) {
			// NOTE crypt_key is in input format (4 * SHA_BUF_SIZ * SIMD_COEF_32)
			if (((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[x + y * SIMD_COEF_32 * SHA_BUF_SIZ])
				return 1;
		}
	}

	return 0;
#else
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_key[index][0])
			return 1;
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	int i;

	for (i = 0; i < (BINARY_SIZE/4); i++)
		// NOTE crypt_key is in input format (4 * SHA_BUF_SIZ * SIMD_COEF_32)
		if (((uint32_t*)binary)[i] != ((uint32_t*)crypt_key)[i * SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32])
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#if _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		if (new_keys) {
			SIMDSHA1body(&ipad[index * SHA_BUF_SIZ * 4],
			            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
			SIMDSHA1body(&opad[index * SHA_BUF_SIZ * 4],
			            (unsigned int*)&prep_opad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
		}
		SIMDSHA1body(cur_salt,
		            (unsigned int*)&crypt_key[index * SHA_BUF_SIZ * 4],
		            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
		SIMDSHA1body(&crypt_key[index * SHA_BUF_SIZ * 4],
		            (unsigned int*)&crypt_key[index * SHA_BUF_SIZ * 4],
		            (unsigned int*)&prep_opad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
#else
		SHA_CTX ctx;

		if (new_keys) {
			SHA1_Init(&ipad_ctx[index]);
			SHA1_Update(&ipad_ctx[index], ipad[index], PAD_SIZE);
			SHA1_Init(&opad_ctx[index]);
			SHA1_Update(&opad_ctx[index], opad[index], PAD_SIZE);
		}

		memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
		SHA1_Update(&ctx, cur_salt, strlen((char*)cur_salt));
		SHA1_Final((unsigned char*) crypt_key[index], &ctx);

		memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
		SHA1_Update(&ctx, crypt_key[index], BINARY_SIZE);
		SHA1_Final((unsigned char*) crypt_key[index], &ctx);
#endif
	}
	new_keys = 0;

	return count;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	// allow # in salt
	p = strrchr(ciphertext, '#') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN==1
	alter_endianity(out, BINARY_SIZE);
#endif
	return (void*)out;
}

static void *get_salt(char *ciphertext)
{
	static unsigned char salt[SALT_LENGTH];
#ifdef SIMD_COEF_32
	unsigned int i = 0;
	unsigned int j;
	unsigned total_len = 0;
#endif
	memset(salt, 0, sizeof(salt));
	// allow # in salt
	memcpy(salt, ciphertext, strrchr(ciphertext, '#') - ciphertext);
#ifdef SIMD_COEF_32
	while(((unsigned char*)salt)[total_len])
	{
		for (i = 0; i < SHA1_N; ++i)
			cur_salt[GETPOS(total_len, i)] = ((unsigned char*)salt)[total_len];
		++total_len;
	}
	for (i = 0; i < SHA1_N; ++i)
		cur_salt[GETPOS(total_len, i)] = 0x80;
	for (j = total_len + 1; j < SALT_LENGTH; ++j)
		for (i = 0; i < SHA1_N; ++i)
			cur_salt[GETPOS(j, i)] = 0;
	for (i = 0; i < SHA1_N; ++i)
		((unsigned int*)cur_salt)[15 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32] = (total_len + 64) << 3;
	return cur_salt;
#else
	return salt;
#endif
}

struct fmt_main fmt__hmacSHA1 = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD | FMT_SPLIT_UNIFIES_CASE | FMT_HUGE_INPUT,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
#ifdef SIMD_COEF_32
		clear_keys,
#else
		fmt_default_clear_keys,
#endif
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

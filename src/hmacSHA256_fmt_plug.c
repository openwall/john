/*
 * This software is Copyright (c) 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * Based on hmac-md5 by Bartavelle
 *
 * SIMD added Feb, 2015, JimF.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt__hmacSHA224;
extern struct fmt_main fmt__hmacSHA256;
#elif FMT_REGISTERS_H
john_register_one(&fmt__hmacSHA224);
john_register_one(&fmt__hmacSHA256);
#else

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "base64_convert.h"
#include "formats.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL			"HMAC-SHA256"
#define FORMAT_LABEL_224		"HMAC-SHA224"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"password is key, SHA256 " SHA256_ALGORITHM_NAME
#define ALGORITHM_NAME_224		"password is key, SHA224 " SHA256_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		125

#define PAD_SIZE			64
#define PAD_SIZE_W			(PAD_SIZE/4)
#define BINARY_SIZE			(256/8)
#define BINARY_SIZE_224			(224/8)
#define BINARY_ALIGN			4

#ifndef SIMD_COEF_32
#define SALT_LENGTH			1023
#define SALT_ALIGN			1
#else
#define SALT_LIMBS			12  /* 12*64-9 == 759 bytes */
#define SALT_LENGTH			(SALT_LIMBS * PAD_SIZE - 9)
#define SALT_ALIGN			MEM_ALIGN_SIMD
#endif

#define CIPHERTEXT_LENGTH		(SALT_LENGTH + 1 + BINARY_SIZE * 2)
#define CIPHERTEXT_LENGTH_224		(SALT_LENGTH + 1 + BINARY_SIZE_224 * 2)

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256 * 64)
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i&63) & (0xffffffff - 3)) * SIMD_COEF_32 + (3 - ((i&63) & 3)) + (unsigned int)index/SIMD_COEF_32 * PAD_SIZE * SIMD_COEF_32)
#else
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i&63) & (0xffffffff - 3)) * SIMD_COEF_32 + ((i&63) & 3) + (unsigned int)index/SIMD_COEF_32 * PAD_SIZE * SIMD_COEF_32)
#endif
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      128
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	{"The quick brown fox jumps over the lazy dog#f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", "key"},
	{"#b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", ""},
	{"Beppe#Grillo#14651BA87C7F7DA88BCE0DF1F89C223975AC0FDF9C35378CB0857A81DFD5C408", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	{"jquYnUyWT5NsbvjQDZXyCxMJB6PryALZdYOZ1bEuagcUmYcbqpx5vOvpxj7VEhqW7OIzHR2O9JLDKrhuDfZxQk9jOENQb4OzEkRZmN8czdGdo7nshdYU1zcdoDGVb3YTCbjeZvazi#c8b4b8a7888787eebca16099fd076092269919bb032bfec48eed7f41d42eba9a", "magnum"},
	/* JWT hashes */
	{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts", "secret"},
	{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ", "secret"},
	{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9.gzSraSYS8EXBxLN_oWnFSRgCzcmJmMjLiuyu5CSpyHI", "secretkey"},
	{"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MjQyIiwibmFtZSI6Ikplc3NpY2EgVGVtcG9yYWwiLCJuaWNrbmFtZSI6Ikplc3MifQ.EDkUUxaM439gWLsQ8a8mJWIvQtgZe0et3O3z4Fd_J8o", "my_super_secret"},
#ifndef SIMD_COEF_32
	{"12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012#ff504b06ee64f3ba7fe503496b451cf46ee34109a62d55cd4bf4f38077ee8145","1234567890" },
	{"012345678901234567890123456789012345678901234567890123456789#6ec69f97e81e58b4a28ee13537c84df316cf8a6250e932de1d375e72843b8f9c", "123456"},
	{"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123#389c4d8db62dea4c108cf12662da3c9440149800cd1e74f3738ba804024343b7","1234567890" },
	{"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789#090487f586965594ae55d366cc9bc96d9f0ce44e253e975a1ed004c8a5edcf24", "123456"},
#endif
	{NULL}
};
static struct fmt_tests tests_224[] = {
	{"what do ya want for nothing?#a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44", "Jefe"},
	{"Beppe#Grillo#926E4A97B401242EF674CEE4C60D9FC6FF73007F871008D4C11F5B95", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	{NULL}
};

#ifdef SIMD_COEF_32
static unsigned char *crypt_key;
static unsigned char *ipad, *prep_ipad;
static unsigned char *opad, *prep_opad;
typedef struct cur_salt_t {
	unsigned char salt[SALT_LIMBS][PAD_SIZE * MAX_KEYS_PER_CRYPT];
	int salt_len;
} cur_salt_t;
static cur_salt_t *cur_salt;
static int bufsize;
#define SALT_SIZE               sizeof(cur_salt_t)
#else
static uint32_t (*crypt_key)[BINARY_SIZE / sizeof(uint32_t)];
static unsigned char (*opad)[PAD_SIZE];
static unsigned char (*ipad)[PAD_SIZE];
static unsigned char cur_salt[SALT_LENGTH+1];
static SHA256_CTX *ipad_ctx;
static SHA256_CTX *opad_ctx;
#define SALT_SIZE               sizeof(cur_salt)
#endif

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int new_keys;

#ifdef SIMD_COEF_32
static void clear_keys(void)
{
	memset(ipad, 0x36, bufsize);
	memset(opad, 0x5C, bufsize);
}
#endif

static void init(struct fmt_main *self, const int B_LEN)
{
#ifdef SIMD_COEF_32
	int i;
#endif

	omp_autotune(self, OMP_SCALE);

#ifdef SIMD_COEF_32
	bufsize = sizeof(*opad) * self->params.max_keys_per_crypt * PAD_SIZE;
	crypt_key = mem_calloc_align(1, bufsize, MEM_ALIGN_SIMD);
	ipad = mem_calloc_align(1, bufsize, MEM_ALIGN_SIMD);
	opad = mem_calloc_align(1, bufsize, MEM_ALIGN_SIMD);
	prep_ipad = mem_calloc_align(self->params.max_keys_per_crypt,
	                             BINARY_SIZE, MEM_ALIGN_SIMD);
	prep_opad = mem_calloc_align(self->params.max_keys_per_crypt,
	                             BINARY_SIZE, MEM_ALIGN_SIMD);
	for (i = 0; i < self->params.max_keys_per_crypt; ++i) {
		crypt_key[GETPOS(B_LEN, i)] = 0x80;
		((unsigned int*)crypt_key)[15 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + (i/SIMD_COEF_32) * PAD_SIZE_W * SIMD_COEF_32] = (B_LEN + PAD_SIZE) << 3;
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

static void init_256(struct fmt_main *self) {
	init(self, BINARY_SIZE);
}
static void init_224(struct fmt_main *self) {
	init(self, BINARY_SIZE_224);
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

static char *split(char *ciphertext, int index, struct fmt_main *self, const int B_LEN, const int CT_LEN)
{
	static char out[(BINARY_SIZE * 2 + 1) + (CIPHERTEXT_LENGTH + 1) + 2];

	if (strnlen(ciphertext, LINE_BUFFER_SIZE) < LINE_BUFFER_SIZE &&
	    strstr(ciphertext, "$SOURCE_HASH$"))
		return ciphertext;

	if (!strchr(ciphertext, '#')) {
		// Treat this like a JWT hash. Convert into 'normal' hmac-sha256 format.
		char buf[BINARY_SIZE * 2 + 1], tmp[CIPHERTEXT_LENGTH + 1], *cpi;

		strnzcpy(tmp, ciphertext, sizeof(tmp));
		cpi = strchr(tmp, '.');
		cpi = strchr(&cpi[1], '.');
		if (cpi - tmp + B_LEN * 2 + 1  > CT_LEN)
			return ciphertext;
		*cpi++ = 0;
		memset(buf, 0, sizeof(buf));
		base64_convert(cpi, e_b64_mime, strlen(cpi), buf, e_b64_hex,
		               sizeof(buf), flg_Base64_NO_FLAGS, 0);
		if (strlen(buf) != B_LEN * 2)
			return ciphertext;
		sprintf(out, "%s#%s", tmp, buf);
	} else
		strnzcpy(out, ciphertext, sizeof(out));
	strlwr(strrchr(out, '#'));

	return out;
}

static char *split_256(char *ciphertext, int index, struct fmt_main *self) {
	return split(ciphertext, index, self, BINARY_SIZE, CIPHERTEXT_LENGTH);
}
static char *split_224(char *ciphertext, int index, struct fmt_main *self) {
	return split(ciphertext, index, self, BINARY_SIZE_224, CIPHERTEXT_LENGTH_224);
}

static int valid_jwt(const char *ciphertext, const int B_LEN)
{
	static const char * const base64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const char *p = ciphertext;
	if (*p++ != 'e') /* Assume no whitespace before JSON's "{" */
		return 0;
	p += strspn(p, base64url);
	if (*p++ != '.')
		return 0;
	p += strspn(p, base64url);
	if (*p++ != '.')
		return 0;
	const int E_LEN = (B_LEN * 8 + 5) / 6;
	if (strspn(p, base64url) != E_LEN)
		return 0;
	return !p[E_LEN];
}

static int valid(char *ciphertext, struct fmt_main *self, const int B_LEN, const int CT_LEN)
{
	char *p;
	int extra;

	p = strrchr(ciphertext, '#'); /* search backwards to allow '#' in salt */
	if (!p && valid_jwt(ciphertext, B_LEN)) {
		if (strlen(ciphertext) > CT_LEN)
			return 0;
		ciphertext = split(ciphertext, 0, self, B_LEN, CT_LEN);
		p = strrchr(ciphertext, '#');
	}
	if (!p)
		return 0;
	if (p - ciphertext > SALT_LENGTH)
		return 0;
	if (hexlen(++p, &extra) != B_LEN * 2 || extra)
		return 0;
	return 1;
}

static int valid_256(char *ciphertext, struct fmt_main *self) {
	return valid(ciphertext, self, BINARY_SIZE, CIPHERTEXT_LENGTH);
}
static int valid_224(char *ciphertext, struct fmt_main *self) {
	return valid(ciphertext, self, BINARY_SIZE_224, CIPHERTEXT_LENGTH_224);
}
static void set_salt(void *salt)
{
#ifdef SIMD_COEF_32
	cur_salt = salt;
#else
	strcpy((char*)cur_salt, (char*)salt);
#endif
}

static MAYBE_INLINE void set_key(char *key, int index, const int B_LEN)
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
		SHA256_CTX ctx;
		int i;

		if (B_LEN == BINARY_SIZE) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, key, len);
			SHA256_Final(k0, &ctx);
		} else {
			SHA224_Init(&ctx);
			SHA224_Update(&ctx, key, len);
			SHA224_Final(k0, &ctx);
		}

		keyp = (unsigned int*)k0;
		for (i = 0; i < B_LEN / 4; i++, ipadp += SIMD_COEF_32, opadp += SIMD_COEF_32)
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
		SHA256_CTX ctx;
		unsigned char k0[BINARY_SIZE];

		if (B_LEN == BINARY_SIZE) {
			SHA256_Init( &ctx );
			SHA256_Update( &ctx, key, len);
			SHA256_Final( k0, &ctx);
		} else {
			SHA224_Init( &ctx );
			SHA224_Update( &ctx, key, len);
			SHA224_Final( k0, &ctx);
		}

		len = B_LEN;

		for (i=0;i<len;i++)
		{
			ipad[index][i] ^= k0[i];
			opad[index][i] ^= k0[i];
		}
	}
	else
	for (i=0;i<len;i++)
	{
		ipad[index][i] ^= key[i];
		opad[index][i] ^= key[i];
	}
#endif
	new_keys = 1;
}

static void set_key_256(char *key, int index) {
	set_key(key, index, BINARY_SIZE);
}
static void set_key_224(char *key, int index) {
	set_key(key, index, BINARY_SIZE_224);
}

static char *get_key(int index)
{
	return saved_plain[index];
}

static int cmp_all(void *binary, int count)
{
	unsigned int index;

#ifdef SIMD_COEF_32

	for (index = 0; index < count; index++) {
		// NOTE crypt_key is in input format (PAD_SIZE * SIMD_COEF_32)
		if (((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1))+index/SIMD_COEF_32*PAD_SIZE_W*SIMD_COEF_32])
			return 1;
	}
	return 0;
#else
	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_key[index][0])
			return 1;
	return 0;
#endif
}

static MAYBE_INLINE int cmp_one(void *binary, int index, const int B_LEN)
{
#ifdef SIMD_COEF_32
	int i;
	for (i = 0; i < (B_LEN/4); i++)
		// NOTE crypt_key is in input format (PAD_SIZE * SIMD_COEF_32)
		if (((uint32_t*)binary)[i] != ((uint32_t*)crypt_key)[i * SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32 * PAD_SIZE_W * SIMD_COEF_32])
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], B_LEN);
#endif
}

static int cmp_one_256(void *binary, int index) {
	return cmp_one(binary, index, BINARY_SIZE);
}
static int cmp_one_224(void *binary, int index) {
	return cmp_one(binary, index, BINARY_SIZE_224);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt,
#ifdef SIMD_COEF_32
	const unsigned EX_FLAGS
#else
	const int B_LEN
#endif
	)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		unsigned int i, *pclear;

		if (new_keys) {
			SIMDSHA256body(&ipad[index * PAD_SIZE],
			            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN|EX_FLAGS);
			SIMDSHA256body(&opad[index * PAD_SIZE],
			            (unsigned int*)&prep_opad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN|EX_FLAGS);
		}

		SIMDSHA256body(cur_salt->salt[0],
			        (unsigned int*)&crypt_key[index * PAD_SIZE],
			        (unsigned int*)&prep_ipad[index * BINARY_SIZE],
			        SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT|EX_FLAGS);
		for (i = 1; i <= (cur_salt->salt_len + 8) / PAD_SIZE; i++)
			SIMDSHA256body(cur_salt->salt[i],
			        (unsigned int*)&crypt_key[index * PAD_SIZE],
			        (unsigned int*)&crypt_key[index * PAD_SIZE],
			         SSEi_MIXED_IN|SSEi_RELOAD_INP_FMT|SSEi_OUTPUT_AS_INP_FMT|EX_FLAGS);

		if (EX_FLAGS) {
			// NOTE, SSESHA224 will output 32 bytes. We need the first 28 (plus the 0x80 padding).
			// so we are forced to 'clean' this crap up, before using the crypt as the input.
			pclear = (unsigned int*)&crypt_key[(unsigned int)index/SIMD_COEF_32*PAD_SIZE_W*SIMD_COEF_32*4];
			for (i = 0; i < MIN_KEYS_PER_CRYPT; i++)
				pclear[28/4*SIMD_COEF_32+(i&(SIMD_COEF_32-1))+i/SIMD_COEF_32*PAD_SIZE_W*SIMD_COEF_32] = 0x80000000;
		}
		SIMDSHA256body(&crypt_key[index * PAD_SIZE],
		            (unsigned int*)&crypt_key[index * PAD_SIZE],
		            (unsigned int*)&prep_opad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT|EX_FLAGS);
#else
		SHA256_CTX ctx;
		// Note, for oSSL, we really only need SHA256_Init and SHA224_Init.  From that point
		// on, SHA256_Update/SHA256_Final can be used.  Also, jtr internal sha2.c file works
		// like that. BUT I am not sure every hash engine works that way, so we are keeping
		// the 'full' block.
		if (B_LEN == BINARY_SIZE) {
			if (new_keys) {
				SHA256_Init(&ipad_ctx[index]);
				SHA256_Update(&ipad_ctx[index], ipad[index], PAD_SIZE);
				SHA256_Init(&opad_ctx[index]);
				SHA256_Update(&opad_ctx[index], opad[index], PAD_SIZE);
			}

			memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
			SHA256_Update( &ctx, cur_salt, strlen( (char*) cur_salt) );
			SHA256_Final( (unsigned char*) crypt_key[index], &ctx);

			memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
			SHA256_Update( &ctx, crypt_key[index], B_LEN);
			SHA256_Final( (unsigned char*) crypt_key[index], &ctx);
		} else {
			if (new_keys) {
				SHA224_Init(&ipad_ctx[index]);
				SHA224_Update(&ipad_ctx[index], ipad[index], PAD_SIZE);
				SHA224_Init(&opad_ctx[index]);
				SHA224_Update(&opad_ctx[index], opad[index], PAD_SIZE);
			}

			memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
			SHA224_Update( &ctx, cur_salt, strlen( (char*) cur_salt) );
			SHA224_Final( (unsigned char*) crypt_key[index], &ctx);

			memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
			SHA224_Update( &ctx, crypt_key[index], B_LEN);
			SHA224_Final( (unsigned char*) crypt_key[index], &ctx);
		}
#endif
	}
	new_keys = 0;
	return count;
}

static int crypt_all_256(int *pcount, struct db_salt *salt) {
#ifdef SIMD_COEF_32
	return crypt_all(pcount, salt, 0);
#else
	return crypt_all(pcount, salt, BINARY_SIZE);
#endif
}
static int crypt_all_224(int *pcount, struct db_salt *salt) {
#ifdef SIMD_COEF_32
	return crypt_all(pcount, salt, SSEi_CRYPT_SHA224);
#else
	return crypt_all(pcount, salt, BINARY_SIZE_224);
#endif
}

static void *get_binary(char *ciphertext, const int B_LEN)
{
	static union toalign {
		unsigned char c[BINARY_SIZE];
		uint32_t a[1];
	} a;
	unsigned char *realcipher = a.c;
	int i,pos;

	for (i=strlen(ciphertext);ciphertext[i]!='#';i--); // allow # in salt
	pos=i+1;
	for (i=0;i<B_LEN;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];

#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN==1
	alter_endianity(realcipher, B_LEN);
#endif
	return (void*)realcipher;
}

static void *get_binary_256(char *ciphertext) {
	return get_binary(ciphertext, BINARY_SIZE);
}
static void *get_binary_224(char *ciphertext) {
	return get_binary(ciphertext, BINARY_SIZE_224);
}


static void *get_salt(char *ciphertext)
{
	static unsigned char salt[SALT_LENGTH+1];
	int len;
#ifdef SIMD_COEF_32
	unsigned int i = 0;
	static JTR_ALIGN(MEM_ALIGN_SIMD) cur_salt_t cur_salt;
	int salt_len = 0;
#endif

	// allow # in salt
	len = strrchr(ciphertext, '#') - ciphertext;
	memset(salt, 0, sizeof(salt));
	memcpy(salt, ciphertext, len);
#ifdef SIMD_COEF_32
	memset(&cur_salt, 0, sizeof(cur_salt));
	while(((unsigned char*)salt)[salt_len])
	{
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			cur_salt.salt[salt_len / PAD_SIZE][GETPOS(salt_len, i)] =
				((unsigned char*)salt)[salt_len];
		++salt_len;
	}
	cur_salt.salt_len = salt_len;
	for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
		cur_salt.salt[salt_len / PAD_SIZE][GETPOS(salt_len, i)] = 0x80;
		((unsigned int*)cur_salt.salt[(salt_len + 8) / PAD_SIZE])[15 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32 * PAD_SIZE_W * SIMD_COEF_32] = (salt_len + PAD_SIZE) << 3;
	}
	return &cur_salt;
#else
	return salt;
#endif
}

struct fmt_main fmt__hmacSHA256 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ NULL },
		tests
	}, {
		init_256,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_256,
		split_256,
		get_binary_256,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key_256,
		get_key,
#ifdef SIMD_COEF_32
		clear_keys,
#else
		fmt_default_clear_keys,
#endif
		crypt_all_256,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one_256,
		cmp_exact
	}
};

struct fmt_main fmt__hmacSHA224 = {
	{
		FORMAT_LABEL_224,
		FORMAT_NAME,
		ALGORITHM_NAME_224,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE_224,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ NULL },
		tests_224
	}, {
		init_224,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_224,
		split_224,
		get_binary_224,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key_224,
		get_key,
#ifdef SIMD_COEF_32
		clear_keys,
#else
		fmt_default_clear_keys,
#endif
		crypt_all_224,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one_224,
		cmp_exact
	}
};

#endif /* plugin stanza */

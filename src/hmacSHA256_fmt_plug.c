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
extern struct fmt_main fmt_hmacSHA256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_hmacSHA256);
#else

#include "sha2.h"

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#ifdef _OPENMP
#include <omp.h>
#ifdef SIMD_COEF_32
#ifndef OMP_SCALE
#define OMP_SCALE               2048 // scaled on scaled core i7-quad HT
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               512 // scaled K8-dual HT
#endif
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL			"HMAC-SHA256"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"password is key, SHA256 " SHA256_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125

#define PAD_SIZE			64
#define BINARY_SIZE			(256/8)
#define BINARY_ALIGN			4

#ifndef SIMD_COEF_32
#define SALT_LENGTH			1024
#else
#define SALT_LIMBS			3  /* 3 limbs, 183 bytes */
#define SALT_LENGTH			(SALT_LIMBS * 64 - 9)
#endif
#define SALT_ALIGN			1
#define CIPHERTEXT_LENGTH		(SALT_LENGTH + 1 + BINARY_SIZE * 2)

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256)
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i&63) & (0xffffffff - 3)) * SIMD_COEF_32 + (3 - ((i&63) & 3)) + (unsigned int)index/SIMD_COEF_32 * SHA_BUF_SIZ * 4 * SIMD_COEF_32)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static struct fmt_tests tests[] = {
	{"The quick brown fox jumps over the lazy dog#f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", "key"},
	{"#b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", ""},
	{"Beppe#Grillo#14651BA87C7F7DA88BCE0DF1F89C223975AC0FDF9C35378CB0857A81DFD5C408", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	{"jquYnUyWT5NsbvjQDZXyCxMJB6PryALZdYOZ1bEuagcUmYcbqpx5vOvpxj7VEhqW7OIzHR2O9JLDKrhuDfZxQk9jOENQb4OzEkRZmN8czdGdo7nshdYU1zcdoDGVb3YTCbjeZvazi#c8b4b8a7888787eebca16099fd076092269919bb032bfec48eed7f41d42eba9a", "magnum"},
#ifndef SIMD_COEF_32
	{"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234#5ad2e1646ed45675e2df32e5fcbf37d6c8830a814c4af0c166fe69a2ef1f277c","1234567890" },
	{"12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012#ff504b06ee64f3ba7fe503496b451cf46ee34109a62d55cd4bf4f38077ee8145","1234567890" },
	{"012345678901234567890123456789012345678901234567890123456789#6ec69f97e81e58b4a28ee13537c84df316cf8a6250e932de1d375e72843b8f9c", "123456"},
	{"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123#389c4d8db62dea4c108cf12662da3c9440149800cd1e74f3738ba804024343b7","1234567890" },
	{"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789#090487f586965594ae55d366cc9bc96d9f0ce44e253e975a1ed004c8a5edcf24", "123456"},
#endif
	{NULL}
};

#ifdef SIMD_COEF_32
#define cur_salt hmacsha256_cur_salt
static unsigned char *crypt_key;
static unsigned char *ipad, *prep_ipad;
static unsigned char *opad, *prep_opad;
JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char cur_salt[SALT_LIMBS][64 * MAX_KEYS_PER_CRYPT];
static int salt_len;
static int bufsize;
#else
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static unsigned char (*opad)[PAD_SIZE];
static unsigned char (*ipad)[PAD_SIZE];
static unsigned char cur_salt[SALT_LENGTH+1];
static SHA256_CTX *ipad_ctx;
static SHA256_CTX *opad_ctx;
#endif

#define SALT_SIZE               sizeof(cur_salt)

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int new_keys;

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
	int i;
#endif
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
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
		((unsigned int*)crypt_key)[15 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32] = (BINARY_SIZE + PAD_SIZE) << 3;
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
	int pos, i;
	char *p;

	p = strrchr(ciphertext, '#'); // allow # in salt
	if (!p || p > &ciphertext[strlen(ciphertext)-1]) return 0;
	i = (int)(p - ciphertext);
	if (i > SALT_LENGTH) return 0;
	pos = i+1;
	if (strlen(ciphertext+pos) != BINARY_SIZE*2) return 0;
	for (i = pos; i < BINARY_SIZE*2+pos; i++)
	{
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
		        (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		        || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(strrchr(out, '#'));

	return out;
}

static void set_salt(void *salt)
{
	memcpy(cur_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	int len;

#ifdef SIMD_COEF_32
	ARCH_WORD_32 *ipadp = (ARCH_WORD_32*)&ipad[GETPOS(3, index)];
	ARCH_WORD_32 *opadp = (ARCH_WORD_32*)&opad[GETPOS(3, index)];
	const ARCH_WORD_32 *keyp = (ARCH_WORD_32*)key;
	unsigned int temp;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	if (len > PAD_SIZE) {
		unsigned char k0[BINARY_SIZE];
		SHA256_CTX ctx;
		int i;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, len);
		SHA256_Final(k0, &ctx);

		keyp = (unsigned int*)k0;
		for(i = 0; i < BINARY_SIZE / 4; i++, ipadp += SIMD_COEF_32, opadp += SIMD_COEF_32)
		{
			temp = JOHNSWAP(*keyp++);
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	}
	else
	while(((temp = JOHNSWAP(*keyp++)) & 0xff000000)) {
		if (!(temp & 0x00ff0000) || !(temp & 0x0000ff00))
		{
			((unsigned short*)ipadp)[1] ^=
				(unsigned short)(temp >> 16);
			((unsigned short*)opadp)[1] ^=
				(unsigned short)(temp >> 16);
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

		SHA256_Init( &ctx );
		SHA256_Update( &ctx, key, len);
		SHA256_Final( k0, &ctx);

		len = BINARY_SIZE;

		for(i=0;i<len;i++)
		{
			ipad[index][i] ^= k0[i];
			opad[index][i] ^= k0[i];
		}
	}
	else
	for(i=0;i<len;i++)
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
	unsigned int index;

	for(index = 0; index < count; index++) {
		// NOTE crypt_key is in input format (4 * SHA_BUF_SIZ * SIMD_COEF_32)
		if(((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[(index&(SIMD_COEF_32-1))+index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32])
			return 1;
	}
	return 0;
#else
	int index = 0;

#if defined(_OPENMP) || (MAX_KEYS_PER_CRYPT > 1)
	for (; index < count; index++)
#endif
		if (((ARCH_WORD_32*)binary)[0] == crypt_key[index][0])
			return 1;
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	int i;
	for(i = 0; i < (BINARY_SIZE/4); i++)
		// NOTE crypt_key is in input format (4 * SHA_BUF_SIZ * SIMD_COEF_32)
		if (((ARCH_WORD_32*)binary)[i] != ((ARCH_WORD_32*)crypt_key)[i * SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32])
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return (1);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
#ifdef SIMD_COEF_32
		int i;

		if (new_keys) {
			SIMDSHA256body(&ipad[index * SHA_BUF_SIZ * 4],
			            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
			SIMDSHA256body(&opad[index * SHA_BUF_SIZ * 4],
			            (unsigned int*)&prep_opad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
		}

		for (i = 0; i < (salt_len + 9) / 64; i++)
			SIMDSHA256body(cur_salt[i],
			        (unsigned int*)&crypt_key[index * SHA_BUF_SIZ * 4],
			        i ? (unsigned int*)&crypt_key[index * SHA_BUF_SIZ * 4] :
			            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
			            SSEi_MIXED_IN|SSEi_RELOAD);
		SIMDSHA256body(cur_salt[i],
			        (unsigned int*)&crypt_key[index * SHA_BUF_SIZ * 4],
			        i ? (unsigned int*)&crypt_key[index * SHA_BUF_SIZ * 4] :
			            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
			            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);

		SIMDSHA256body(&crypt_key[index * SHA_BUF_SIZ * 4],
		            (unsigned int*)&crypt_key[index * SHA_BUF_SIZ * 4],
		            (unsigned int*)&prep_opad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
#else
		SHA256_CTX ctx;

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
		SHA256_Update( &ctx, crypt_key[index], BINARY_SIZE);
		SHA256_Final( (unsigned char*) crypt_key[index], &ctx);
#endif
	}
	new_keys = 0;
	return count;
}

static void *get_binary(char *ciphertext)
{
	static union toalign {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD_32 a[1];
	} a;
	unsigned char *realcipher = a.c;
	int i,pos;

	for(i=strlen(ciphertext);ciphertext[i]!='#';i--); // allow # in salt
	pos=i+1;
	for(i=0;i<BINARY_SIZE;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];

#ifdef SIMD_COEF_32
	alter_endianity(realcipher, BINARY_SIZE);
#endif
	return (void*)realcipher;
}

static void *get_salt(char *ciphertext)
{
	static unsigned char salt[SALT_LENGTH+1];
	int len;
#ifdef SIMD_COEF_32
	unsigned int i = 0;

	salt_len = 0;
#endif

	// allow # in salt
	len = strrchr(ciphertext, '#') - ciphertext;
	memset(salt, 0, SALT_LENGTH+1);
	memcpy(salt, ciphertext, len);
#ifdef SIMD_COEF_32
	memset(cur_salt, 0, sizeof(cur_salt));
	while(((unsigned char*)salt)[salt_len])
	{
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
			cur_salt[salt_len / 64][GETPOS(salt_len, i)] =
				((unsigned char*)salt)[salt_len];
		++salt_len;
	}
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
		cur_salt[salt_len / 64][GETPOS(salt_len, i)] = 0x80;
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
		((unsigned int*)cur_salt[(salt_len + 9) / 64])[15 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32] = (salt_len + 64) << 3;
	return cur_salt;
#else
	return salt;
#endif
}

#ifdef SIMD_COEF_32
// NOTE crypt_key is in input format (4 * SHA_BUF_SIZ * SIMD_COEF_32)
#define HASH_OFFSET (index & (SIMD_COEF_32 - 1)) + ((unsigned int)index / SIMD_COEF_32) * SIMD_COEF_32 * SHA_BUF_SIZ
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & PH_MASK_0; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & PH_MASK_1; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & PH_MASK_2; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & PH_MASK_3; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & PH_MASK_4; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & PH_MASK_5; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return crypt_key[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_key[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_key[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_key[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_key[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_key[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_key[index][0] & PH_MASK_6; }
#endif

struct fmt_main fmt_hmacSHA256 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
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
#ifdef SIMD_COEF_32
		clear_keys,
#else
		fmt_default_clear_keys,
#endif
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

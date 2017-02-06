/*
 * This software is Copyright (c) 2004 bartavelle, <simon at banquise.net>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Optimised set_key() and reduced binary size by magnum, 2012
 *
 * OMP added May 2013, JimF
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA1;
extern struct fmt_main fmt_rawSHA1_axcrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA1);
john_register_one(&fmt_rawSHA1_axcrypt);
#else

#include <string.h>

#include "arch.h"

#include "sha.h"
#include "common.h"
#include "formats.h"
#include "base64_convert.h"
#include "rawSHA1_common.h"
#include "johnswap.h"

#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif

//#undef SIMD_COEF_32
//#undef SIMD_PARA_SHA1

/*
 * Only effective for SIMD.
 * Undef to disable reversing steps for benchmarking.
 */
#define REVERSE_STEPS

#ifdef _OPENMP
#ifdef SIMD_COEF_32
#ifndef OMP_SCALE
#define OMP_SCALE               1024
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE				2048
#endif
#endif
#include <omp.h>
#endif
#include "simd-intrinsics.h"
#include "memdbg.h"

#define AX_FORMAT			1
#define RAW_FORMAT			2

#define AX_FORMAT_LABEL			"Raw-SHA1-AxCrypt"
#define FORMAT_LABEL			"Raw-SHA1"
#define FORMAT_NAME				""
#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define BINARY_SIZE				DIGEST_SIZE
#define BINARY_ALIGN			4

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH		55
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 ) //for endianity conversion
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#ifdef SIMD_COEF_32
static uint32_t (*saved_key)[SHA_BUF_SIZ*NBKEYS];
static uint32_t (*crypt_key)[DIGEST_SIZE/4*NBKEYS];
#else
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_key)[DIGEST_SIZE / 4];
#endif

static unsigned algo;
static unsigned digest_size;
static unsigned pos;
static unsigned SSEi_flags;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef SIMD_COEF_32
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*crypt_key), MEM_ALIGN_SIMD);
#else
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#endif
}


#ifndef REVERSE_STEPS
#undef SSEi_REVERSE_STEPS
#define SSEi_REVERSE_STEPS 0
#undef SSEi_REVERSE_3STEPS
#define SSEi_REVERSE_3STEPS 0
#endif

static void init_raw(struct fmt_main *self)
{
    algo = RAW_FORMAT;
    digest_size = DIGEST_SIZE;
    pos = 4;
    SSEi_flags = SSEi_REVERSE_STEPS | SSEi_MIXED_IN;

    init(self);
}

static void init_ax(struct fmt_main *self)
{
    algo = AX_FORMAT;
    digest_size = AX_DIGEST_SIZE;
    pos = 3;
    SSEi_flags = SSEi_REVERSE_3STEPS | SSEi_MIXED_IN;

    init(self);
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}


#ifdef SIMD_COEF_32
#define HASH_OFFSET	(index&(SIMD_COEF_32-1))+(((unsigned int)index%NBKEYS)/SIMD_COEF_32)*SIMD_COEF_32*5+pos*SIMD_COEF_32
static int get_hash_0(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return crypt_key[index][pos] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_key[index][pos] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_key[index][pos] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_key[index][pos] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_key[index][pos] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_key[index][pos] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_key[index][pos] & PH_MASK_6; }
#endif

static int binary_hash_0(void *binary) { return ((uint32_t*)binary)[pos] & PH_MASK_0; }
static int binary_hash_1(void *binary) { return ((uint32_t*)binary)[pos] & PH_MASK_1; }
static int binary_hash_2(void *binary) { return ((uint32_t*)binary)[pos] & PH_MASK_2; }
static int binary_hash_3(void *binary) { return ((uint32_t*)binary)[pos] & PH_MASK_3; }
static int binary_hash_4(void *binary) { return ((uint32_t*)binary)[pos] & PH_MASK_4; }
static int binary_hash_5(void *binary) { return ((uint32_t*)binary)[pos] & PH_MASK_5; }
static int binary_hash_6(void *binary) { return ((uint32_t*)binary)[pos] & PH_MASK_6; }

#ifdef SIMD_COEF_32
static void set_key(char *key, int index)
{
#if ARCH_ALLOWS_UNALIGNED
	const uint32_t *wkey = (uint32_t*)key;
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint32_t));
	const uint32_t *wkey = (uint32_t*)(is_aligned(key, sizeof(uint32_t)) ?
	                                       key : strcpy(buf_aligned, key));
#endif
	uint32_t *keybuffer = &((uint32_t*)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32];
	uint32_t *keybuf_word = keybuffer;
	unsigned int len;
	uint32_t temp;

	len = 0;
	while((unsigned char)(temp = *wkey++)) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = JOHNSWAP((temp & 0xff) | (0x80 << 8));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = JOHNSWAP((temp & 0xffff) | (0x80 << 16));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = JOHNSWAP(temp | (0x80U << 24));
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = JOHNSWAP(temp);
		len += 4;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80000000;

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	keybuffer[15*SIMD_COEF_32] = len << 3;
}
#else
static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH+1);
}
#endif

#ifdef SIMD_COEF_32
static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int i;
	uint32_t len = ((uint32_t*)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] >> 3;

	for (i=0;i<len;i++)
		out[i] = ((char*)saved_key)[GETPOS(i, index)];
	out[i] = 0;
	return (char*)out;
}
#else
static char *get_key(int index) {
	return saved_key[index];
}
#endif

static void *get_binary(char *ciphertext)
{
	static uint32_t full[DIGEST_SIZE / 4];
	unsigned char *realcipher = (unsigned char*)full;

	memset(full, 0, sizeof(full)); // since ax-crypt 'may' be short.
	ciphertext += TAG_LENGTH;
	base64_convert(ciphertext, e_b64_hex, HASH_LENGTH,
	               realcipher, e_b64_raw, sizeof(full),
	               flg_Base64_MIME_TRAIL_EQ, 0);

#ifdef SIMD_COEF_32
	alter_endianity(realcipher, DIGEST_SIZE);
#ifdef REVERSE_STEPS
	if (algo == RAW_FORMAT)
		sha1_reverse(full);
	else
		sha1_reverse3(full);
#endif
#endif

	return (void*)realcipher;
}

static char *source(char *source, void *binary)
{
	static char hex[CIPHERTEXT_LENGTH + 1] = FORMAT_TAG;
	uint32_t hash[DIGEST_SIZE / 4];
	char *p;
	int i, j;

	memcpy(hash, binary, DIGEST_SIZE);

	/* Un-reverse binary */
#ifdef SIMD_COEF_32
#ifdef REVERSE_STEPS
	if (algo == RAW_FORMAT)
		sha1_unreverse(hash);
	else {
		hash[4] = 0;
		sha1_unreverse3(hash);
	}
#endif
	alter_endianity(hash, DIGEST_SIZE);
#else
	if (algo == AX_FORMAT)
		hash[4] = 0;
#endif

#if ARCH_LITTLE_ENDIAN==0
	alter_endianity(hash, DIGEST_SIZE);
#endif

	/* Convert to hex string */
	p = hex + TAG_LENGTH;
	for (i = 0; i < 5; i++)
		for (j = 0; j < 8; j++)
			*p++ = itoa16[(hash[i] >> ((j ^ 1) * 4)) & 0xf];
	*p = 0;

	return hex;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
	int loops = (count + MAX_KEYS_PER_CRYPT - 1) / MAX_KEYS_PER_CRYPT;

#pragma omp parallel for
	for (index = 0; index < loops; ++index)
#endif
	{
#if SIMD_COEF_32
		SIMDSHA1body(saved_key[index], crypt_key[index], NULL, SSEi_flags);
#else
		SHA_CTX ctx;

		SHA1_Init( &ctx );
		SHA1_Update( &ctx, (unsigned char*) saved_key[index], strlen( saved_key[index] ) );
		SHA1_Final( (unsigned char*) crypt_key[index], &ctx);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count) {
	int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
		if (((uint32_t*)binary)[pos] == ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32 + pos*SIMD_COEF_32])
#else
		if ( ((uint32_t*)binary)[0] == crypt_key[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	return (((uint32_t *) binary)[pos] == ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32 + pos*SIMD_COEF_32]);
#else
	return !memcmp(binary, crypt_key[index], digest_size);
#endif
}

static int cmp_exact(char *source, int index)
{
#ifdef SIMD_COEF_32
	uint32_t crypt_key[DIGEST_SIZE / 4];
	SHA_CTX ctx;
	char *key = get_key(index);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, key, strlen(key));
	SHA1_Final((void*)crypt_key, &ctx);

	alter_endianity(crypt_key, DIGEST_SIZE);
#ifdef REVERSE_STEPS
	if (algo == RAW_FORMAT)
		sha1_reverse(crypt_key);
	else
		sha1_reverse3(crypt_key);
#endif
	return !memcmp(get_binary(source), crypt_key, digest_size);
#else
	return 1;
#endif
}

struct fmt_main fmt_rawSHA1 = {
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG, FORMAT_TAG_OLD },
		rawsha1_common_tests
	}, {
		init_raw,
		done,
		fmt_default_reset,
		rawsha1_common_prepare,
		rawsha1_common_valid,
		rawsha1_common_split,
		get_binary,
		fmt_default_salt,
		{ NULL },
		source,
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

struct fmt_main fmt_rawSHA1_axcrypt = {
	{
		AX_FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		DIGEST_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ NULL },
		axcrypt_common_tests
	}, {
		init_ax,
		done,
		fmt_default_reset,
		rawsha1_common_prepare,
		rawsha1_axcrypt_valid,
		rawsha1_axcrypt_split,
		get_binary,
		fmt_default_salt,
		{ NULL },
		source,
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

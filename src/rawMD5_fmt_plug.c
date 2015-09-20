/*
 * Raw-MD5 (thick) based on Raw-MD4 w/ mmx/sse/intrinsics
 * This software is Copyright (c) 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * OMP added May 2013, JimF
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawMD5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawMD5);
#else

#include <string.h>

#include "arch.h"

#include "md5.h"
#include "common.h"
#include "johnswap.h"
#include "formats.h"

#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif

//#undef SIMD_COEF_32
//#undef SIMD_PARA_MD5

/*
 * Only effective for SIMD.
 * Undef to disable reversing steps for benchmarking.
 */
#define REVERSE_STEPS

#ifdef _OPENMP
#ifdef SIMD_COEF_32
#ifndef OMP_SCALE
#define OMP_SCALE               256 // core i7
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

#define FORMAT_LABEL			"Raw-MD5"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"MD5 " MD5_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_MD5)
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1
#ifndef MD5_BUF_SIZ
#define MD5_BUF_SIZ				16
#endif

#define CIPHERTEXT_LENGTH		32

#define DIGEST_SIZE				16
#define BINARY_SIZE				16
#define BINARY_ALIGN			4
#define SALT_SIZE				0
#define SALT_ALIGN				1

#define FORMAT_TAG				"$dynamic_0$"
#define TAG_LENGTH				(sizeof(FORMAT_TAG) - 1)

static struct fmt_tests tests[] = {
	{"5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{FORMAT_TAG "5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{"098f6bcd4621d373cade4e832627b4f6", "test"},
	{FORMAT_TAG "378e2c4a07968da2eca692320136433d", "thatsworking"},
	{FORMAT_TAG "8ad8757baa8564dc136c1e07507f4a98", "test3"},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
#ifdef DEBUG
	{FORMAT_TAG "c9ccf168914a1bcfc3229f1948e67da0","1234567890123456789012345678901234567890123456789012345"},
#if PLAINTEXT_LENGTH >= 80
	{FORMAT_TAG "57edf4a22be3c955ac49da2e2107b67a","12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
#endif
	{NULL}
};

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH		55
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*MD5_BUF_SIZ*4*SIMD_COEF_32 )
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#ifdef SIMD_COEF_32
static ARCH_WORD_32 (*saved_key)[MD5_BUF_SIZ*NBKEYS];
static ARCH_WORD_32 (*crypt_key)[DIGEST_SIZE/4*NBKEYS];
#else
static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_key)[4];
#endif

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#else
	self->params.max_keys_per_crypt *= 10;
#endif
#ifndef SIMD_COEF_32
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#else
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*crypt_key), MEM_ALIGN_SIMD);
#endif
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
#ifndef SIMD_COEF_32
	MEM_FREE(saved_len);
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (*p == '$' && !strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = p;
	while (atoi16l[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1] = FORMAT_TAG;

	if (ciphertext[0] == '$' &&
	    !strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH);

	return out;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned long dummy;
		unsigned int i[DIGEST_SIZE/sizeof(unsigned int)];
	} _out;
	unsigned int *out = _out.i;
	unsigned int i;
	unsigned int temp;

	ciphertext += TAG_LENGTH;
	for (i=0; i<4; i++)
	{
		temp  = (atoi16[ARCH_INDEX(ciphertext[i*8+0])])<<4;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+1])]);

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+2])])<<12;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+3])])<<8;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+4])])<<20;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+5])])<<16;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+6])])<<28;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+7])])<<24;

#if ARCH_LITTLE_ENDIAN
		out[i]=temp;
#else
		out[i]=JOHNSWAP(temp);
#endif
	}

#if SIMD_COEF_32 && defined(REVERSE_STEPS)
	md5_reverse(out);
#endif

	return out;
}

static char *source(char *source, void *binary)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1] = FORMAT_TAG;
	ARCH_WORD_32 b[4];
	char *p;
	int i, j;

	memcpy(b, binary, sizeof(b));

#if SIMD_COEF_32 && defined(REVERSE_STEPS)
	md5_unreverse(b);
#endif

	p = &out[TAG_LENGTH];
	for (i = 0; i < 4; i++)
		for (j = 0; j < 8; j++)
			*p++ = itoa16[(b[i] >> ((j ^ 1) * 4)) & 0xf];

	return out;
}

#ifdef SIMD_COEF_32
static void set_key(char *_key, int index)
{
#if ARCH_ALLOWS_UNALIGNED
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint32_t));
	const ARCH_WORD_32 *key = (uint32_t*)(is_aligned(_key, sizeof(uint32_t)) ?
	                                      _key : strcpy(buf_aligned, _key));
#endif
	ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32*)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*MD5_BUF_SIZ*SIMD_COEF_32];
	ARCH_WORD_32 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_32 temp;

	len = 0;
	while((temp = *key++) & 0xff) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = (temp & 0xff) | (0x80 << 8);
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = (temp & 0xffff) | (0x80 << 16);
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = temp | (0x80 << 24);
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = temp;
		len += 4;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80;
#ifdef DEBUG
	/* This function is higly optimized and assumes that we are
	   never ever given a key longer than fmt_params.plaintext_length.
	   If we are, buffer overflows WILL happen */
	if (len > PLAINTEXT_LENGTH) {
		fprintf(stderr, "\n** Core bug: got len %u\n'%s'\n", len, _key);
		error();
	}
#endif
key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	keybuffer[14*SIMD_COEF_32] = len << 3;
}
#else
static void set_key(char *key, int index)
{
	int len = strlen(key);
	saved_len[index] = len;
	memcpy(saved_key[index], key, len);
}
#endif

#ifdef SIMD_COEF_32
static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int i;
	ARCH_WORD_32 len = ((ARCH_WORD_32*)saved_key)[14*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*MD5_BUF_SIZ*SIMD_COEF_32] >> 3;

	for(i=0;i<len;i++)
		out[i] = ((char*)saved_key)[GETPOS(i, index)];
	out[i] = 0;
	return (char*)out;
}
#else
static char *get_key(int index)
{
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
}
#endif

#ifndef REVERSE_STEPS
#undef SSEi_REVERSE_STEPS
#define SSEi_REVERSE_STEPS 0
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	int loops = (count + MAX_KEYS_PER_CRYPT - 1) / MAX_KEYS_PER_CRYPT;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < loops; index++) {
#if SIMD_COEF_32
		SIMDmd5body(saved_key[index], crypt_key[index], NULL, SSEi_REVERSE_STEPS | SSEi_MIXED_IN);
#else
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[index], saved_len[index]);
		MD5_Final((unsigned char *)crypt_key[index], &ctx);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x, y;
#if 1
	const unsigned int c = (count + SIMD_COEF_32 - 1) / SIMD_COEF_32;
#else
	const unsigned int c = SIMD_PARA_MD5;
#endif
	for(y = 0; y < c; y++)
		for(x = 0; x < SIMD_COEF_32; x++)
		{
			if( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[y*SIMD_COEF_32*4+x] )
				return 1;
		}
	return 0;
#else
	unsigned int index = 0;

#if 1
	for (index = 0; index < count; index++)
#endif
		if (!memcmp(binary, crypt_key[index], BINARY_SIZE))
			return 1;
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x = index&(SIMD_COEF_32-1);
	unsigned int y = (unsigned int)index/SIMD_COEF_32;

	return ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*4];
#else
	return !memcmp(binary, crypt_key[index], DIGEST_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
#ifdef SIMD_COEF_32
	ARCH_WORD_32 crypt_key[DIGEST_SIZE / 4];
	MD5_CTX ctx;
	char *key = get_key(index);

	MD5_Init(&ctx);
	MD5_Update(&ctx, key, strlen(key));
	MD5_Final((void*)crypt_key, &ctx);

#ifdef REVERSE_STEPS
	md5_reverse(crypt_key);
#endif
	return !memcmp(get_binary(source), crypt_key, DIGEST_SIZE);
#else
	return 1;
#endif
}

#ifdef SIMD_COEF_32
#define SIMD_INDEX (index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*SIMD_COEF_32*4
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_0; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_1; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_2; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_3; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_4; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_5; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return crypt_key[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_key[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_key[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_key[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_key[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_key[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_key[index][0] & PH_MASK_6; }
#endif

struct fmt_main fmt_rawMD5 = {
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
		FMT_CASE | FMT_8_BIT,
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
		fmt_default_salt,
		{ NULL },
		source,
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

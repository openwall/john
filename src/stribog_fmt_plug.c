/*
 * GOST R 34.11-2012 cracker patch for JtR. Hacked together during
 * the Hash Runner 2015 contest by Dhiru Kholia and Aleksey Cherepanov.
 *
 * Based on https://www.streebog.net/ and https://github.com/sjinks/php-stribog
 * code. See "LICENSE.gost" for licensing details of the original code.
 */

#include "arch.h"

#if __SSE4_1__

#if FMT_EXTERNS_H
extern struct fmt_main fmt_stribog_256;
extern struct fmt_main fmt_stribog_512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_stribog_256);
john_register_one(&fmt_stribog_512);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "gost3411-2012-sse41.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               512 // XXX
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"stribog"
#define FORMAT_NAME		""

#define ALGORITHM_NAME		"GOST R 34.11-2012 128/128 SSE4.1 1x"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	64 - 1
#define CIPHERTEXT256_LENGTH	64
#define CIPHERTEXT512_LENGTH	64
#define BINARY_SIZE_256		32
#define BINARY_SIZE_512		64
#define SALT_SIZE		0
#define SALT_ALIGN		1
#define BINARY_ALIGN		sizeof(ARCH_WORD_32)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests stribog_256_tests[] = {
	{"$stribog256$bbe19c8d2025d99f943a932a0b365a822aa36a4c479d22cc02c8973e219a533f", ""},
	/* {"3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb", ""}, */
	/* 9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500 */
	{"$stribog256$00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d", "012345678901234567890123456789012345678901234567890123456789012"},
	{NULL}
};


static struct fmt_tests stribog_512_tests[] = {
	/* 8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a */
	{"$stribog512$8a1a1c4cbf909f8ecb81cd1b5c713abad26a4cac2a5fda3ce86e352855712f36a7f0be98eb6cf51553b507b73a87e97946aebc29859255049f86aa09a25d948e", ""},
	{NULL}
};


#define make_full_static_buf(type, var, len) static type (var)[(len)]
#define make_dynamic_static_buf(type, var, len)         \
    static type *var;                                   \
    if (!var)                                           \
        var = mem_alloc_tiny((len), MEM_ALIGN_WORD)

#if 1
#define make_static_buf make_dynamic_static_buf
#else
#define make_static_buf make_full_static_buf
#endif


static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE_512 / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	if (!saved_key) {
		// saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
		saved_key = mem_alloc_tiny(self->params.max_keys_per_crypt * sizeof(*saved_key), MEM_ALIGN_SIMD);
	}
	if (!crypt_out)
		crypt_out = mem_calloc(self->params.max_keys_per_crypt,	sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
}
#define TAG256 "$stribog256$"
#define TAG256_LENGTH strlen(TAG256)

#define TAG512 "$stribog512$"
#define TAG512_LENGTH strlen(TAG512)

#define TAG_LENGTH TAG256_LENGTH
#define FORMAT_TAG TAG256
#define CIPHERTEXT_LENGTH 64

static char *split_256(char *ciphertext, int index, struct fmt_main *self)
{
	make_static_buf(char, out, TAG_LENGTH + CIPHERTEXT_LENGTH + 1);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + TAG_LENGTH);
	return out;
}


static int valid_256(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	/* else */
	/* 	return 0; */
	if (strlen(p) != CIPHERTEXT_LENGTH)
		return 0;
	while(*p)
		if(atoi16[ARCH_INDEX(*p++)]==0x7f)
			return 0;
	return 1;
}

static void *get_binary_256(char *ciphertext)
{
	static unsigned char *out;
	char *p = ciphertext;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE_256, MEM_ALIGN_WORD);

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;

	for (i = 0; i < BINARY_SIZE_256; i++) {
		out[BINARY_SIZE_256 - i - 1] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#undef TAG_LENGTH
#undef FORMAT_TAG
#undef CIPHERTEXT_LENGTH

#define TAG_LENGTH TAG512_LENGTH
#define FORMAT_TAG TAG512
#define CIPHERTEXT_LENGTH 128

static char *split_512(char *ciphertext, int index, struct fmt_main *self)
{
	make_static_buf(char, out, TAG_LENGTH + CIPHERTEXT_LENGTH + 1);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + TAG_LENGTH);
	return out;
}


static int valid_512(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	/* else */
	/* 	return 0; */
	if (strlen(p) != CIPHERTEXT_LENGTH)
		return 0;
	while(*p)
		if(atoi16[ARCH_INDEX(*p++)]==0x7f)
			return 0;
	return 1;
}

static void *get_binary_512(char *ciphertext)
{
	static unsigned char *out;
	char *p = ciphertext;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE_512, MEM_ALIGN_WORD);

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = ciphertext + TAG_LENGTH;

	for (i = 0; i < BINARY_SIZE_512; i++) {
		out[BINARY_SIZE_512 - i - 1] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}


#undef TAG_LENGTH
#undef FORMAT_TAG
#undef CIPHERTEXT_LENGTH


/* static int valid_256(char *ciphertext, struct fmt_main *self) */
/* { */
/* 	return valid(ciphertext, self, 64); */
/* } */
/* static int valid_512(char *ciphertext, struct fmt_main *self) */
/* { */
/* 	return valid(ciphertext, self, 128); */
/* } */

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void stribog256_init(void* context)
{
	size_t offset = (((size_t)context + 15) & ~0x0F) - (size_t)context;
	void *ctx     = (char*)context + offset;
	GOST34112012Init(ctx, 256);
}

static void stribog512_init(void* context)
{
	size_t offset = (((size_t)context + 15) & ~0x0F) - (size_t)context;
	void *ctx     = (char*)context + offset;
	GOST34112012Init(ctx, 512);
}

static void stribog_update(void* context, const unsigned char* buf, unsigned int count)
{
	size_t offset = (((size_t)context + 15) & ~0x0F) - (size_t)context;
	void *ctx     = (char*)context + offset;

	offset = (((size_t)buf + 15) & ~0x0F) - (size_t)buf;
	if (!offset) {
		GOST34112012Update(ctx, buf, count);
	}
	else {
		ALIGN(16) unsigned char tmp[15];
		assert(offset < 16);
		memcpy(tmp, buf, offset);
		GOST34112012Update(ctx, tmp, offset);
		GOST34112012Update(ctx, buf + offset, count - offset);
	}
}

static void stribog_final(unsigned char* digest, void* context)
{
	size_t offset = (((size_t)context + 15) & ~0x0F) - (size_t)context;
	void *ctx     = (char*)context + offset;
	GOST34112012Final(ctx, digest);
}

static int crypt_256(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		/* GOST34112012Context ctx;

		GOST34112012Init(&ctx, 256);
		GOST34112012Update(&ctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
		GOST34112012Final(&ctx, (unsigned char*)crypt_out[index]); */

		GOST34112012Context ctx[2]; // alignment stuff

		stribog256_init((void *)ctx);
		stribog_update(&ctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
		stribog_final((unsigned char*)crypt_out[index], &ctx);
	}
	return count;
}

static int crypt_512(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		/* GOST34112012Context ctx;

		GOST34112012Init(&ctx, 512);
		GOST34112012Update(&ctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
		GOST34112012Final(&ctx, (unsigned char*)crypt_out[index]); */

		GOST34112012Context ctx[2]; // alignment stuff

		stribog512_init((void *)ctx);
		stribog_update(&ctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
		stribog_final((unsigned char*)crypt_out[index], &ctx);

	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one_256(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE_256);
}

static int cmp_one_512(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE_512);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void stribog_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_stribog_256 = {
	{
		"Stribog-256",
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE_256,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		stribog_256_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_256,
		split_256,
		get_binary_256,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
		fmt_default_set_salt,
		stribog_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_256,
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
		cmp_one_256,
		cmp_exact
	}
};

struct fmt_main fmt_stribog_512 = {
	{
		"Stribog-512",
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE_512,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		stribog_512_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_512,
		split_512,
		get_binary_512,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
		fmt_default_set_salt,
		stribog_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_512,
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
		cmp_one_512,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* __SSE4_1__ */

/*
 * GOST R 34.11-2012 cracker patch for JtR. Hacked together during
 * the Hash Runner 2015 contest by Dhiru Kholia and Aleksey Cherepanov.
 *
 * Based on https://www.streebog.net/ and https://github.com/sjinks/php-stribog
 * code. See "LICENSE.gost" for licensing details of the original code.
 */

#include "arch.h"

#if ARCH_LITTLE_ENDIAN

#if FMT_EXTERNS_H
extern struct fmt_main fmt_stribog_256;
extern struct fmt_main fmt_stribog_512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_stribog_256);
john_register_one(&fmt_stribog_512);
#else

#include <string.h>
#include <assert.h> // "needed" for alignment check

#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "gost3411-2012-core.h"

#define FORMAT_LABEL_256        "Stribog-256"
#define FORMAT_LABEL_512        "Stribog-512"
#define FORMAT_NAME             "raw Streebog"
#define TAG256                  "$stribog256$"
#define TAG256_LENGTH           (sizeof(TAG256)-1)
#define TAG512                  "$stribog512$"
#define TAG512_LENGTH           (sizeof(TAG512)-1)
#if !JOHN_NO_SIMD && __AVX__
#define ALGORITHM_NAME          "GOST R 34.11-2012 128/128 AVX 1x"
#elif !JOHN_NO_SIMD && __SSE2__
#define ALGORITHM_NAME          "GOST R 34.11-2012 128/128 SSE2 1x"
#else
#define ALGORITHM_NAME          "GOST R 34.11-2012 64/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        64 - 1
#define CIPHERTEXT256_LENGTH    64
#define CIPHERTEXT512_LENGTH    128
#define BINARY_SIZE_256         32
#define BINARY_SIZE_512         64
#define SALT_SIZE               0
#define SALT_ALIGN              1
#define BINARY_ALIGN            sizeof(uint32_t)

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif

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
	/* 1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48 */
	{"$stribog512$486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b", "012345678901234567890123456789012345678901234567890123456789012"},
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
static uint32_t (*crypt_out)[BINARY_SIZE_512 / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	if (!saved_key) {
		saved_key = mem_calloc_align(self->params.max_keys_per_crypt, sizeof(*saved_key), MEM_ALIGN_SIMD);
	}
	if (!crypt_out)
		crypt_out = mem_calloc(self->params.max_keys_per_crypt,	sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

#define FORMAT_TAG              TAG256
#define TAG_LENGTH              TAG256_LENGTH
#define CIPHERTEXT_LENGTH       CIPHERTEXT256_LENGTH

static char *split_256(char *ciphertext, int index, struct fmt_main *self)
{
	make_static_buf(char, out, TAG_LENGTH + CIPHERTEXT_LENGTH + 1);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpylwr(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
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
		if (atoi16[ARCH_INDEX(*p++)]==0x7f)
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

#undef FORMAT_TAG
#undef TAG_LENGTH
#undef CIPHERTEXT_LENGTH

#define FORMAT_TAG TAG512
#define TAG_LENGTH TAG512_LENGTH
#define CIPHERTEXT_LENGTH CIPHERTEXT512_LENGTH

static char *split_512(char *ciphertext, int index, struct fmt_main *self)
{
	make_static_buf(char, out, TAG_LENGTH + CIPHERTEXT_LENGTH + 1);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;
	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpylwr(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
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
		if (atoi16[ARCH_INDEX(*p++)]==0x7f)
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

static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }

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
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
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
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		GOST34112012Context ctx[2]; // alignment stuff

		stribog512_init((void *)ctx);
		stribog_update(&ctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
		stribog_final((unsigned char*)crypt_out[index], &ctx);

	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
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
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_stribog_256 = {
	{
		FORMAT_LABEL_256,
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
		{ NULL },
		{ TAG256 },
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
		FORMAT_LABEL_512,
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
		{ NULL },
		{ TAG512 },
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

#else
#if !defined(FMT_EXTERNS_H) && !defined(FMT_REGISTERS_H)
#ifdef __GNUC__
#warning Stribog-256 and Stribog-512 formats require little-endian, formats disabled
#elif _MSC_VER
#pragma message(": warning Stribog-256 and Stribog-512 formats require little-endian, formats disabled:")
#endif
#endif
#endif /* ARCH_LITTLE_ENDIAN */

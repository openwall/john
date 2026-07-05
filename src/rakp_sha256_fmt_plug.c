/*
 * IPMI 2.0 RAKP (RMCP+) with HMAC-SHA256 key-exchange authentication code
 * (RAKP auth algorithm 3). Same $rakp$<salt>$<hmac> hash format -- the
 * 64-hex (32-byte) HMAC length selects this vs RAKP (40) / RAKP-MD5 (32).
 *
 * Derived from rakp_fmt_plug.c (HMAC-SHA1 RAKP, (c) 2013 magnum) and the SIMD
 * HMAC-SHA256 engine of hmacSHA256_fmt_plug.c ((c) 2012 magnum, SIMD 2015 JimF).
 * Released to the general public under the same terms: redistribution and use
 * in source and binary forms, with or without modification, permitted.
 *
 * RAKP salts are BINARY (contain NUL bytes), so the salt is hex-encoded in the
 * hash and loaded by known length -- never null-terminated -- in both paths.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rakp_sha256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rakp_sha256);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL            "RAKP-SHA256"
#define FORMAT_NAME             "IPMI 2.0 RAKP (RMCP+)"
#define ALGORITHM_NAME          "HMAC-SHA256 " SHA256_ALGORITHM_NAME
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        MAX_PLAINTEXT_LENGTH
#define PAD_SIZE                64
#define PAD_SIZE_W              (PAD_SIZE / 4)
#define BINARY_SIZE             (256 / 8)
#define BINARY_ALIGN            4
#ifdef SIMD_COEF_32
#define SALT_LIMBS              2  /* RAKP salt <= ~74 bytes -> 2 limbs */
#define SALT_LENGTH             (SALT_LIMBS * PAD_SIZE - 9)
#define SALT_ALIGN              MEM_ALIGN_SIMD
#else
#define SALT_LENGTH             (2 * PAD_SIZE)
#define SALT_ALIGN              MEM_ALIGN_NONE
#endif
#define SALT_MIN_SIZE           (PAD_SIZE - 8)
#define SALT_MAX_SIZE           (2 * PAD_SIZE - 8 - 1)
#define FORMAT_TAG              "$rakp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#ifndef OMP_SCALE
#define OMP_SCALE               4
#endif

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_32 * SIMD_PARA_SHA256)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_32 * SIMD_PARA_SHA256 * 64)
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i&63) & (0xffffffff - 3)) * SIMD_COEF_32 + (3 - ((i&63) & 3)) + (unsigned int)index/SIMD_COEF_32 * PAD_SIZE * SIMD_COEF_32)
#else
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i&63) & (0xffffffff - 3)) * SIMD_COEF_32 + ((i&63) & 3) + (unsigned int)index/SIMD_COEF_32 * PAD_SIZE * SIMD_COEF_32)
#endif
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      128
#endif

static struct fmt_tests tests[] = {
	{"$rakp$1eaf72c001407792e65364f6100997e2946b8d9c2a57a4a8574b99694ca321f30401769c58cfbcd09cc2c43a2c74de030010debf6022a771140474657374$669c87a9a6871f77134f3159c9f421a571723f5493fdeec173309b362ee8b259", "1234"},
	{"$rakp$41987b483ceaad20ffa718e58a99c6ae7ade09383b49f50a70c44febde6e2c7665896457e8b583f10102030405060708090a0b0c0d0e0f101404726f6f74$6a7ad41787afe8831a759c98d65b12f0f52726bb1b020819c29a695376410997", "0penBmc"},
	{"$rakp$4b85d9c83828f0ce031267bc45d72f928f50185296bf7b8fb62eacbe91d2667ee63b5a507f79c758000000000000d7030010debf80adac6b140561646d696e$374bb6a0cc22dc88087fd3638f73584905f7c69fd8ed57decbe93e71c688d107", "admin"},
	{NULL}
};

typedef struct {
	int length;
	unsigned char salt[SALT_LENGTH + 1];
} rakp_salt;

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
static rakp_salt cur_salt;
static uint32_t (*crypt_key)[BINARY_SIZE / sizeof(uint32_t)];
static unsigned char (*ipad)[PAD_SIZE];
static unsigned char (*opad)[PAD_SIZE];
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

static void init(struct fmt_main *self)
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
	prep_ipad = mem_calloc_align(self->params.max_keys_per_crypt, BINARY_SIZE, MEM_ALIGN_SIMD);
	prep_opad = mem_calloc_align(self->params.max_keys_per_crypt, BINARY_SIZE, MEM_ALIGN_SIMD);
	for (i = 0; i < self->params.max_keys_per_crypt; ++i) {
		crypt_key[GETPOS(BINARY_SIZE, i)] = 0x80;
		((unsigned int*)crypt_key)[15 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + (i/SIMD_COEF_32) * PAD_SIZE_W * SIMD_COEF_32] = (BINARY_SIZE + PAD_SIZE) << 3;
	}
	clear_keys();
#else
	crypt_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_key));
	ipad = mem_calloc(self->params.max_keys_per_crypt, sizeof(*ipad));
	opad = mem_calloc(self->params.max_keys_per_crypt, sizeof(*opad));
	ipad_ctx = mem_calloc(self->params.max_keys_per_crypt, sizeof(*ipad_ctx));
	opad_ctx = mem_calloc(self->params.max_keys_per_crypt, sizeof(*opad_ctx));
#endif
	saved_plain = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_plain));
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
	char *p, *q;
	int len;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = strrchr(ciphertext, '$');
	if (!q)
		return 0;
	q = q + 1;
	if ((q - p - 1) > SALT_MAX_SIZE * 2)
		return 0;
	if ((q - p - 1) < SALT_MIN_SIZE * 2)
		return 0;

	len = strspn(q, HEXCHARS_lc);
	if (len != BINARY_SIZE * 2 || len != strlen(q))
		return 0;
	if (strspn(p, HEXCHARS_lc) != q - p - 1)
		return 0;

	return 1;
}

static void set_salt(void *salt)
{
#ifdef SIMD_COEF_32
	cur_salt = salt;
#else
	memcpy(&cur_salt, salt, SALT_SIZE);
#endif
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
		SHA256_CTX ctx;
		int i;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, len);
		SHA256_Final(k0, &ctx);

		keyp = (unsigned int*)k0;
		for (i = 0; i < BINARY_SIZE / 4; i++, ipadp += SIMD_COEF_32, opadp += SIMD_COEF_32) {
#if ARCH_LITTLE_ENDIAN==1
			temp = JOHNSWAP(*keyp++);
#else
			temp = *keyp++;
#endif
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	} else
#if ARCH_LITTLE_ENDIAN==1
		while(((temp = JOHNSWAP(*keyp++)) & 0xff000000)) {
#else
		while(((temp = *keyp++) & 0xff000000)) {
#endif
		if (!(temp & 0x00ff0000) || !(temp & 0x0000ff00)) {
#if ARCH_LITTLE_ENDIAN==1
			((unsigned short*)ipadp)[1] ^= (unsigned short)(temp >> 16);
			((unsigned short*)opadp)[1] ^= (unsigned short)(temp >> 16);
#else
			((unsigned short*)ipadp)[0] ^= (unsigned short)(temp >> 16);
			((unsigned short*)opadp)[0] ^= (unsigned short)(temp >> 16);
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

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, len);
		SHA256_Final(k0, &ctx);

		len = BINARY_SIZE;
		for (i = 0; i < len; i++) {
			ipad[index][i] ^= k0[i];
			opad[index][i] ^= k0[i];
		}
	} else
		for (i = 0; i < len; i++) {
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
	unsigned int index;

#ifdef SIMD_COEF_32
	for (index = 0; index < (unsigned int)count; index++)
		if (((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + index/SIMD_COEF_32 * PAD_SIZE_W * SIMD_COEF_32])
			return 1;
	return 0;
#else
	for (index = 0; index < (unsigned int)count; index++)
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
		if (((uint32_t*)binary)[i] != ((uint32_t*)crypt_key)[i * SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32 * PAD_SIZE_W * SIMD_COEF_32])
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

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		unsigned int i;

		if (new_keys) {
			SIMDSHA256body(&ipad[index * PAD_SIZE],
			            (unsigned int*)&prep_ipad[index * BINARY_SIZE], NULL, SSEi_MIXED_IN);
			SIMDSHA256body(&opad[index * PAD_SIZE],
			            (unsigned int*)&prep_opad[index * BINARY_SIZE], NULL, SSEi_MIXED_IN);
		}
		SIMDSHA256body(cur_salt->salt[0],
		            (unsigned int*)&crypt_key[index * PAD_SIZE],
		            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
		for (i = 1; i <= (cur_salt->salt_len + 8) / PAD_SIZE; i++)
			SIMDSHA256body(cur_salt->salt[i],
			            (unsigned int*)&crypt_key[index * PAD_SIZE],
			            (unsigned int*)&crypt_key[index * PAD_SIZE],
			            SSEi_MIXED_IN|SSEi_RELOAD_INP_FMT|SSEi_OUTPUT_AS_INP_FMT);
		SIMDSHA256body(&crypt_key[index * PAD_SIZE],
		            (unsigned int*)&crypt_key[index * PAD_SIZE],
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
		SHA256_Update(&ctx, cur_salt.salt, cur_salt.length);
		SHA256_Final((unsigned char*) crypt_key[index], &ctx);

		memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
		SHA256_Update(&ctx, crypt_key[index], BINARY_SIZE);
		SHA256_Final((unsigned char*) crypt_key[index], &ctx);
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

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN==1
	alter_endianity(out, BINARY_SIZE);
#endif
	return out;
}

static void *get_salt(char *ciphertext)
{
	unsigned char salt[SALT_LENGTH + 1];
	unsigned int i, len;
#ifdef SIMD_COEF_32
	unsigned int j;
	static JTR_ALIGN(MEM_ALIGN_SIMD) cur_salt_t cs;
#else
	static rakp_salt out;
#endif

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	len = (strrchr(ciphertext, '$') - ciphertext) / 2;
	memset(salt, 0, sizeof(salt));
	for (i = 0; i < len; i++)
		salt[i] = (atoi16[ARCH_INDEX(ciphertext[2 * i])] << 4) |
			atoi16[ARCH_INDEX(ciphertext[2 * i + 1])];

#ifdef SIMD_COEF_32
	memset(&cs, 0, sizeof(cs));
	for (i = 0; i < len; i++)
		for (j = 0; j < MIN_KEYS_PER_CRYPT; ++j)
			cs.salt[i / PAD_SIZE][GETPOS(i, j)] = salt[i];
	cs.salt_len = len;
	for (j = 0; j < MIN_KEYS_PER_CRYPT; ++j) {
		cs.salt[len / PAD_SIZE][GETPOS(len, j)] = 0x80;
		((unsigned int*)cs.salt[(len + 8) / PAD_SIZE])[15 * SIMD_COEF_32 + (j&(SIMD_COEF_32-1)) + j/SIMD_COEF_32 * PAD_SIZE_W * SIMD_COEF_32] = (len + PAD_SIZE) << 3;
	}
	return &cs;
#else
	memset(&out, 0, sizeof(out));
	out.length = len;
	memcpy(out.salt, salt, len);
	return &out;
#endif
}

/*
 * crypt_key is kept in SIMD "input format" (SSEi_OUTPUT_AS_INP_FMT), so the
 * per-hash stride is PAD_SIZE_W (16) words, not BINARY_SIZE/4.
 */
#define COMMON_GET_HASH_SIMD32 PAD_SIZE_W
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

struct fmt_main fmt_rakp_sha256 = {
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
		/* RAKP salts are bounded (<= ~119 bytes) so FMT_HUGE_INPUT is not needed;
		 * omitting it enables the per-hash binary-hash table, which matters when
		 * loading large RAKP hash sets. */
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
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
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

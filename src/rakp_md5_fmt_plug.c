/*
 * IPMI 2.0 RAKP (RMCP+) with HMAC-MD5 key-exchange authentication code
 * (RAKP auth algorithm 2). Same $rakp$<salt>$<hmac> hash format -- the
 * 32-hex (16-byte) HMAC length selects this vs RAKP (40) / RAKP-SHA256 (64).
 *
 * Derived from rakp_fmt_plug.c (HMAC-SHA1 RAKP, (c) 2013 magnum) and the SIMD
 * HMAC-MD5 engine of hmacMD5_fmt_plug.c ((c) 2010 bartavelle, (c) 2011-2015
 * magnum). Released to the general public under the same terms: redistribution
 * and use in source and binary forms, with or without modification, permitted.
 *
 * The key difference from generic HMAC-MD5: RAKP salts are BINARY (contain NUL
 * bytes), so the salt is hex-encoded in the hash and loaded by known length --
 * never null-terminated -- in both the SIMD and non-SIMD paths.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rakp_md5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rakp_md5);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"
#include "aligned.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL            "RAKP-MD5"
#define FORMAT_NAME             "IPMI 2.0 RAKP (RMCP+)"

#ifdef SIMD_COEF_32
#define MD5_N                   (SIMD_PARA_MD5 * SIMD_COEF_32)
#endif
#define ALGORITHM_NAME          "HMAC-MD5 " MD5_ALGORITHM_NAME
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        MAX_PLAINTEXT_LENGTH
#define PAD_SIZE                64
#define PAD_SIZE_W              (PAD_SIZE / 4)
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
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
#define OMP_SCALE               2
#endif

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      MD5_N
#define MAX_KEYS_PER_CRYPT      (MD5_N * 128)
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i&63) & (0xffffffff - 3)) * SIMD_COEF_32 + ((i&63) & 3) + (unsigned int)index/SIMD_COEF_32 * PAD_SIZE * SIMD_COEF_32)
#else
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i&63) & (0xffffffff - 3)) * SIMD_COEF_32 + (3-((i&63)&3)) + (unsigned int)index/SIMD_COEF_32 * PAD_SIZE * SIMD_COEF_32)
#endif
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      256
#endif

static struct fmt_tests tests[] = {
	{"$rakp$000476044b237ebb4f2a415ce488ebc91996043c8011e26079633b706424119e09dcaad4acf21b10535000000000000000000000000000001404726f6f74$102546a8888f78d420fc48ba84108ee2", "superuser"},
	{"$rakp$000aae1770480e004b31afa4a6e13297b09fc5d60b4a018b4fc50ecf9a8963745bf6a56a6873f50f000000000000000000000000000000001400$ef1f3c6c029975343a4d1195dee130da", "admin"},
	{"$rakp$001108876d5e010001e176e46f686d5e296145b5d6454181da9a9e2f0e9eba82b7c6c1c83dcf3a5a000000000000000000000000000000001400$3ea2e6b997bc34959ef1617fd4be1348", "admin"},
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
static MD5_CTX *ipad_ctx;
static MD5_CTX *opad_ctx;
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
		((unsigned int*)crypt_key)[14 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + (i/SIMD_COEF_32) * PAD_SIZE_W * SIMD_COEF_32] = (BINARY_SIZE + PAD_SIZE) << 3;
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
	uint32_t *ipadp = (uint32_t*)&ipad[GETPOS(0, index)];
	uint32_t *opadp = (uint32_t*)&opad[GETPOS(0, index)];
#else
	uint32_t *ipadp = (uint32_t*)&ipad[GETPOS(3, index)];
	uint32_t *opadp = (uint32_t*)&opad[GETPOS(3, index)];
#endif
	const uint32_t *keyp = (uint32_t*)key;
	unsigned int temp;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	if (len > PAD_SIZE) {
		unsigned char k0[BINARY_SIZE];
		MD5_CTX ctx;
		int i;

		MD5_Init(&ctx);
		MD5_Update(&ctx, key, len);
		MD5_Final(k0, &ctx);

		keyp = (unsigned int*)k0;
		for (i = 0; i < BINARY_SIZE / 4; i++, ipadp += SIMD_COEF_32, opadp += SIMD_COEF_32) {
#if ARCH_LITTLE_ENDIAN==1
			temp = *keyp++;
#else
			temp = JOHNSWAP(*keyp++);
#endif
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	} else {
#if ARCH_LITTLE_ENDIAN==1
		while((unsigned char)(temp = *keyp++)) {
			if (!(temp & 0xff00) || !(temp & 0xff0000)) {
				*ipadp ^= (unsigned short)temp;
				*opadp ^= (unsigned short)temp;
				break;
			}
			*ipadp ^= temp;
			*opadp ^= temp;
			if (!(temp & 0xff000000))
				break;
			ipadp += SIMD_COEF_32;
			opadp += SIMD_COEF_32;
		}
#else
		while((temp = *keyp++) & 0xff000000) {
			if (!(temp & 0xff0000) || !(temp & 0xff00)) {
				*ipadp ^= (unsigned short)JOHNSWAP(temp);
				*opadp ^= (unsigned short)JOHNSWAP(temp);
				break;
			}
			*ipadp ^= JOHNSWAP(temp);
			*opadp ^= JOHNSWAP(temp);
			if (!(temp & 0xff))
				break;
			ipadp += SIMD_COEF_32;
			opadp += SIMD_COEF_32;
		}
#endif
	}
#else
	int i;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	memset(ipad[index], 0x36, PAD_SIZE);
	memset(opad[index], 0x5C, PAD_SIZE);

	if (len > PAD_SIZE) {
		MD5_CTX ctx;
		unsigned char k0[BINARY_SIZE];

		MD5_Init(&ctx);
		MD5_Update(&ctx, key, len);
		MD5_Final(k0, &ctx);

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
#ifdef SIMD_COEF_32
	unsigned int x, y;

	for (y = 0; y < (unsigned int)(count + SIMD_COEF_32 - 1) / SIMD_COEF_32; y++)
		for (x = 0; x < SIMD_COEF_32; x++)
			if (((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[x + y * SIMD_COEF_32 * PAD_SIZE_W])
				return 1;
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

#if _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		int i;

		if (new_keys) {
			SIMDmd5body(&ipad[index * PAD_SIZE],
			            (unsigned int*)&prep_ipad[index * BINARY_SIZE], NULL, SSEi_MIXED_IN);
			SIMDmd5body(&opad[index * PAD_SIZE],
			            (unsigned int*)&prep_opad[index * BINARY_SIZE], NULL, SSEi_MIXED_IN);
		}
		SIMDmd5body(cur_salt->salt[0],
		            (unsigned int*)&crypt_key[index * PAD_SIZE],
		            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
		for (i = 1; i <= (cur_salt->salt_len + 8) / PAD_SIZE; i++)
			SIMDmd5body(cur_salt->salt[i],
			            (unsigned int*)&crypt_key[index * PAD_SIZE],
			            (unsigned int*)&crypt_key[index * PAD_SIZE],
			            SSEi_MIXED_IN|SSEi_RELOAD_INP_FMT|SSEi_OUTPUT_AS_INP_FMT);
		SIMDmd5body(&crypt_key[index * PAD_SIZE],
		            (unsigned int*)&crypt_key[index * PAD_SIZE],
		            (unsigned int*)&prep_opad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
#else
		MD5_CTX ctx;

		if (new_keys) {
			MD5_Init(&ipad_ctx[index]);
			MD5_Update(&ipad_ctx[index], ipad[index], PAD_SIZE);
			MD5_Init(&opad_ctx[index]);
			MD5_Update(&opad_ctx[index], opad[index], PAD_SIZE);
		}

		memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
		MD5_Update(&ctx, cur_salt.salt, cur_salt.length);
		MD5_Final((unsigned char*) crypt_key[index], &ctx);

		memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
		MD5_Update(&ctx, crypt_key[index], BINARY_SIZE);
		MD5_Final((unsigned char*) crypt_key[index], &ctx);
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
#if !ARCH_LITTLE_ENDIAN && defined(SIMD_COEF_32)
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
		((unsigned int*)cs.salt[(len + 8) / PAD_SIZE])[14 * SIMD_COEF_32 + (j&(SIMD_COEF_32-1)) + j/SIMD_COEF_32 * PAD_SIZE_W * SIMD_COEF_32] = (len + PAD_SIZE) << 3;
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

struct fmt_main fmt_rakp_md5 = {
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

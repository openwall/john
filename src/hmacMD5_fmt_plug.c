/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>
 * and (c) magnum 2011-2015,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt__hmacMD5;
#elif FMT_REGISTERS_H
john_register_one(&fmt__hmacMD5);
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
#include "base64_convert.h"

#define FORMAT_LABEL            "HMAC-MD5"
#define FORMAT_NAME             ""

#ifdef SIMD_COEF_32
#define MD5_N                   (SIMD_PARA_MD5 * SIMD_COEF_32)
#endif

#define ALGORITHM_NAME          "password is key, MD5 " MD5_ALGORITHM_NAME

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7

#define PLAINTEXT_LENGTH        125

#define PAD_SIZE                64
#define PAD_SIZE_W              (PAD_SIZE/4)
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#ifdef SIMD_COEF_32
#define SALT_LIMBS              3  /* 3 limbs, 183 bytes */
#define SALT_LENGTH             (SALT_LIMBS * PAD_SIZE - 9)
#define SALT_ALIGN              MEM_ALIGN_SIMD
#else
#define SALT_LENGTH             1023
#define SALT_ALIGN              1
#endif
#define CIPHERTEXT_LENGTH       (2 * SALT_LENGTH + 2 * BINARY_SIZE)

#define HEXCHARS                "0123456789abcdef"

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

#ifndef OMP_SCALE
#define OMP_SCALE 2 // tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	{"what do ya want for nothing?#750c783e6ab0b503eaa86e310a5db738", "Jefe"},
	{"YT1m11GDMm3oze0EdqO3FZmATSrxhquB#6c97850b296b34719b7cea5c0c751e22", ""},
	{"2shXeqDlLdZ2pSMc0CBHfTyA5a9TKuSW#dfeb02c6f8a9ce89b554be60db3a2333", "magnum"},
	{"#74e6f7298a9c2d168935f58c001bad88", ""},
	{"The quick brown fox jumps over the lazy dog#80070713463e7749b90c2dc24911e275", "key"},
	{"Beppe Grillo#F8457C3046C587BBCBD6D7036BA42C81", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	{"$cram_md5$PG5vLXJlcGx5QGhhc2hjYXQubmV0Pg==$dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ==", "hashcat"},
	{"MEaEObR2JNXgchVn93GLLH1Ud4qTzuC0#9a80bea0acd72231ea043210a173ec7f", "123"},
	{"d2BbCbiSXTlglEstbFFlrRgPhR1KUa2s#7a553738bc4997e656329c1b1ef99e4f", "123456789"},
	{"dBTmX1AdmnWyVkMKp7BEt4O3eBktdN2S#f6af0afd4f397504c3bfa3836bc04a0f", "passWOrd"},
	{"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789#050a9dee01b2302914b2a78346721d9b", "magnum"},
	{"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123#e4d0097fdc52f6fc50545d832784232d", "MaxLenSaltUsed"},
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
static unsigned char (*ipad)[PAD_SIZE];
static unsigned char (*opad)[PAD_SIZE];
static unsigned char cur_salt[SALT_LENGTH+1];
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
	unsigned int i;
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
		crypt_key[GETPOS(BINARY_SIZE, i)] = 0x80;
		((unsigned int*)crypt_key)[14 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + (i/SIMD_COEF_32) * PAD_SIZE_W * SIMD_COEF_32] = (BINARY_SIZE + PAD_SIZE) << 3;
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

/* Convert from Base64 format with tag to our legacy format */
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *p = split_fields[1];

	if (!strncmp(p, "$cram_md5$", 10)) {
		static char out[256];
		int len, len2;
		char *d, *o = out;

		p += 10;
		memset(out, 0, sizeof(out));
		if (!(d = strchr(p, '$')))
			return split_fields[1];
		len = base64_convert(p, e_b64_mime, (int)(d - p - 1),
		                     o, e_b64_raw,
		                     sizeof(out),
		                     flg_Base64_MIME_TRAIL_EQ|flg_Base64_DONOT_NULL_TERMINATE, 0);
		if (len > sizeof(out)-2)
			return split_fields[1];
		o += len;
		*o++ = '#';
		d++;
		len2 = base64_convert(d, e_b64_mime, strlen(d),
		                     o, e_b64_raw,
		                     sizeof(out) - len - 2,
		                     flg_Base64_MIME_TRAIL_EQ, 0);
		if (len2 > sizeof(out) - len - 3)
			return split_fields[1];
		o[len = len2] = 0;
		if (!(p = strchr(o, ' ')))
			return split_fields[1];
		p++;
		if (p-o >= len)
			return split_fields[1];
		memmove(o, p, len - (p - o) + 1);
		if (strlen(o) == BINARY_SIZE * 2)
			return out;
	}
	return p;
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

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	int extra;

	if (!strncmp(ciphertext, "$cram_md5$", 10)) {
		char *f[10];
		f[1] = ciphertext;
		ciphertext = prepare(f, self);
	}

	p = strrchr(ciphertext, '#'); /* search backwards to allow '#' in salt */
	if (!p)
		return 0;
	if (p - ciphertext > SALT_LENGTH)
		return 0;
	if (hexlen(++p, &extra) != BINARY_SIZE * 2 || extra)
		return 0;
	return 1;
}

static void set_salt(void *salt)
{
#ifdef SIMD_COEF_32
	cur_salt = salt;
#else
	strcpy((char*)cur_salt, (char*)salt);
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
		for (i = 0; i < BINARY_SIZE / 4; i++, ipadp += SIMD_COEF_32, opadp += SIMD_COEF_32)
		{
#if ARCH_LITTLE_ENDIAN==1
			temp = *keyp++;
#else
			temp = JOHNSWAP(*keyp++);
#endif
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	}
	else {
#if ARCH_LITTLE_ENDIAN==1
		while((unsigned char)(temp = *keyp++)) {
			if (!(temp & 0xff00) || !(temp & 0xff0000))
			{
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
			if (!(temp & 0xff0000) || !(temp & 0xff00))
			{
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

	for (y = 0 ; y < (unsigned int)(count + SIMD_COEF_32 - 1) / SIMD_COEF_32; y++) {
		for (x = 0; x < SIMD_COEF_32; x++) {
			// NOTE crypt_key is in input format (PAD_SIZE * SIMD_COEF_32)
			if (((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[x + y * SIMD_COEF_32 * PAD_SIZE_W])
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
		// NOTE crypt_key is in input format (PAD_SIZE * SIMD_COEF_32)
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
			            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
			SIMDmd5body(&opad[index * PAD_SIZE],
			            (unsigned int*)&prep_opad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
		}
		SIMDmd5body(cur_salt->salt[0],
		            (unsigned int*)&crypt_key[index * PAD_SIZE],
		            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
		for (i = 1; i <= (cur_salt->salt_len + 8) / PAD_SIZE; i++) {
			SIMDmd5body(cur_salt->salt[i],
				    (unsigned int*)&crypt_key[index * PAD_SIZE],
				    (unsigned int*)&crypt_key[index * PAD_SIZE],
				    SSEi_MIXED_IN|SSEi_RELOAD_INP_FMT|SSEi_OUTPUT_AS_INP_FMT);
		}
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
		MD5_Update(&ctx, cur_salt, strlen((char*)cur_salt));
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

	// allow # in salt
	p = strrchr(ciphertext, '#') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if !ARCH_LITTLE_ENDIAN && defined(SIMD_COEF_32)
	alter_endianity(out, BINARY_SIZE);
#endif
	return (void*)out;
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
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
			cur_salt.salt[salt_len / PAD_SIZE][GETPOS(salt_len, i)] =
				((unsigned char*)salt)[salt_len];
		++salt_len;
	}
	cur_salt.salt_len = salt_len;
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
		cur_salt.salt[salt_len / PAD_SIZE][GETPOS(salt_len, i)] = 0x80;
		((unsigned int*)cur_salt.salt[(salt_len + 8) / PAD_SIZE])[14 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32 * PAD_SIZE_W * SIMD_COEF_32] = (salt_len + PAD_SIZE) << 3;
	}
	return &cur_salt;
#else
	return salt;
#endif
}

struct fmt_main fmt__hmacMD5 = {
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
		prepare,
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

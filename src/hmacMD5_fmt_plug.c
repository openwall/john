/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>
 * and (c) magnum 2011-2015,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_hmacMD5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_hmacMD5);
#else

#include <string.h>

#include "arch.h"

#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE 2048 // tuned for i7 using SSE2 and w/o HT
#endif
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"
#include "aligned.h"
#include "sse-intrinsics.h"
#include "base64_convert.h"
#include "memdbg.h"

#define FORMAT_LABEL            "HMAC-MD5"
#define FORMAT_NAME             ""

#ifdef SIMD_COEF_32
#define MD5_N                   (SIMD_PARA_MD5 * SIMD_COEF_32)
#endif

#define ALGORITHM_NAME          "password is key, MD5 " MD5_ALGORITHM_NAME

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0

#define PLAINTEXT_LENGTH        125

#define PAD_SIZE                64
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define SALT_LENGTH             PAD_SIZE
#define SALT_ALIGN              MEM_ALIGN_NONE
#define CIPHERTEXT_LENGTH       (2 * SALT_LENGTH + 2 * BINARY_SIZE)

#define HEXCHARS                "0123456789abcdef"

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      MD5_N
#define MAX_KEYS_PER_CRYPT      MD5_N
#define GETPOS(i, index)        ((index & (SIMD_COEF_32 - 1)) * 4 + ((i) & (0xffffffff - 3)) * SIMD_COEF_32 + ((i) & 3) + (unsigned int)index/SIMD_COEF_32 * 64 * SIMD_COEF_32)

#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static struct fmt_tests tests[] = {
	{"what do ya want for nothing?#750c783e6ab0b503eaa86e310a5db738", "Jefe"},
	{"YT1m11GDMm3oze0EdqO3FZmATSrxhquB#6c97850b296b34719b7cea5c0c751e22", ""},
	{"2shXeqDlLdZ2pSMc0CBHfTyA5a9TKuSW#dfeb02c6f8a9ce89b554be60db3a2333", "magnum"},
	{"#74e6f7298a9c2d168935f58c001bad88", ""},
	{"The quick brown fox jumps over the lazy dog#80070713463e7749b90c2dc24911e275", "key"},
	{"Beppe Grillo#F8457C3046C587BBCBD6D7036BA42C81", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	{"$cram_md5$PG5vLXJlcGx5QGhhc2hjYXQubmV0Pg==$dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ==", "hashcat"},
	{NULL}
};

#ifdef SIMD_COEF_32
#define cur_salt hmacmd5_cur_salt
static unsigned char *crypt_key;
static unsigned char *ipad, *prep_ipad;
static unsigned char *opad, *prep_opad;
JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char cur_salt[PAD_SIZE * MD5_N];
static int bufsize;
#else
static unsigned char cur_salt[SALT_LENGTH];

static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static unsigned char (*ipad)[PAD_SIZE];
static unsigned char (*opad)[PAD_SIZE];
static MD5_CTX *ipad_ctx;
static MD5_CTX *opad_ctx;
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
#ifdef _OPENMP
	int omp_t = omp_get_num_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef SIMD_COEF_32
	bufsize = sizeof(*opad) * self->params.max_keys_per_crypt * PAD_SIZE;
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
		((unsigned int*)crypt_key)[14 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32 * 16 * SIMD_COEF_32] = (BINARY_SIZE + 64) << 3;
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
		int len;
		char *d, *o = out;

		p += 10;
		if (!(d = strchr(p, '$')))
			return split_fields[1];
		len = base64_convert(p, e_b64_mime, (int)(d - p - 1),
		                     o, e_b64_raw,
#if SIMD_COEF_32
		                     55,
#else
		                     SALT_LENGTH,
#endif
		                     flg_Base64_MIME_TRAIL_EQ);
		o += len;
		*o++ = '#';
		d++;
		len = base64_convert(d, e_b64_mime, strlen(d),
		                     o, e_b64_raw,
		                     sizeof(out) - len - 2,
		                     flg_Base64_MIME_TRAIL_EQ);
		if (!(p = strchr(o, ' ')))
			return split_fields[1];
		p++;
		memmove(o, p, len - (p - o) + 1);
		if (strlen(o) == BINARY_SIZE * 2)
			return out;
	}
	return p;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int pos, i;
	char *p;

	if (!strncmp(ciphertext, "$cram_md5$", 10)) {
		char *f[10];
		f[1] = ciphertext;
		ciphertext = prepare(f, self);
	}

	p = strrchr(ciphertext, '#'); // allow # in salt
	if (!p || p > &ciphertext[strlen(ciphertext) - 1]) return 0;
	i = (int)(p - ciphertext);
#if SIMD_COEF_32
	if(i > 55) return 0;
#else
	if(i > SALT_LENGTH) return 0;
#endif
	pos = i + 1;
	if (strlen(ciphertext+pos) != BINARY_SIZE * 2) return 0;
	for (i = pos; i < BINARY_SIZE*2+pos; i++)
	{
		if (!((('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
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
	memcpy(&cur_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	int len;
#ifdef SIMD_COEF_32
	ARCH_WORD_32 *ipadp = (ARCH_WORD_32*)&ipad[GETPOS(0, index)];
	ARCH_WORD_32 *opadp = (ARCH_WORD_32*)&opad[GETPOS(0, index)];
	const ARCH_WORD_32 *keyp = (ARCH_WORD_32*)key;
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
		for(i = 0; i < BINARY_SIZE / 4; i++, ipadp += SIMD_COEF_32, opadp += SIMD_COEF_32)
		{
			temp = *keyp++;
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	}
	else
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

		for(i = 0; i < len; i++)
		{
			ipad[index][i] ^= k0[i];
			opad[index][i] ^= k0[i];
		}
	}
	else
	for(i = 0; i < len; i++)
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
	unsigned int x, y = 0;

	for(; y < (unsigned int)(count + SIMD_COEF_32 - 1) / SIMD_COEF_32; y++)
		for(x = 0; x < SIMD_COEF_32; x++)
		{
			// NOTE crypt_key is in input format (64 * SIMD_COEF_32)
			if(((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[x + y * SIMD_COEF_32 * 16])
				return 1;
		}
	return 0;
#else
	int index = 0;

#if defined(_OPENMP) || (MAX_KEYS_PER_CRYPT > 1)
	for (index = 0; index < count; index++)
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
		// NOTE crypt_key is in input format (64 * SIMD_COEF_32)
		if (((ARCH_WORD_32*)binary)[i] != ((ARCH_WORD_32*)crypt_key)[i * SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + index/SIMD_COEF_32 * 16 * SIMD_COEF_32])
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

#if _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
#ifdef SIMD_COEF_32
		if (new_keys) {
			SSEmd5body(&ipad[index * PAD_SIZE],
			            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
			SSEmd5body(&opad[index * PAD_SIZE],
			            (unsigned int*)&prep_opad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
		}
		SSEmd5body(cur_salt,
		            (unsigned int*)&crypt_key[index * PAD_SIZE],
		            (unsigned int*)&prep_ipad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
		SSEmd5body(&crypt_key[index * PAD_SIZE],
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
		ARCH_WORD_32 dummy;
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

	return (void*)out;
}

static void *get_salt(char *ciphertext)
{
	static unsigned char salt[SALT_LENGTH];
#ifdef SIMD_COEF_32
	int i = 0;
	int j;
	unsigned total_len = 0;
#endif
	memset(salt, 0, sizeof(salt));
	// allow # in salt
	memcpy(salt, ciphertext, strrchr(ciphertext, '#') - ciphertext);
#ifdef SIMD_COEF_32
	while(((unsigned char*)salt)[total_len])
	{
		for (i = 0; i < MD5_N; ++i)
			cur_salt[GETPOS(total_len, i)] = ((unsigned char*)salt)[total_len];
		++total_len;
	}
	for (i = 0; i < MD5_N; ++i)
		cur_salt[GETPOS(total_len, i)] = 0x80;
	for (j = total_len + 1; j < SALT_LENGTH; ++j)
		for (i = 0; i < MD5_N; ++i)
			cur_salt[GETPOS(j, i)] = 0;
	for (i = 0; i < MD5_N; ++i)
		((unsigned int*)cur_salt)[14 * SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32 * 16 * SIMD_COEF_32] = (total_len + 64) << 3;
	return cur_salt;
#else
	return salt;
#endif
}

#ifdef SIMD_COEF_32
// NOTE crypt_key is in input format (64 * SIMD_COEF_32)
#define HASH_OFFSET (index & (SIMD_COEF_32 - 1)) + ((unsigned int)index / SIMD_COEF_32) * SIMD_COEF_32 * 16
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return crypt_key[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_key[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_key[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[index][0] & 0x7ffffff; }
#endif

struct fmt_main fmt_hmacMD5 = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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

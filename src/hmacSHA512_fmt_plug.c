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
extern struct fmt_main fmt_hmacSHA512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_hmacSHA512);
#else

#include "sha2.h"

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "aligned.h"
#include "johnswap.h"
#include "sse-intrinsics.h"

#ifdef _OPENMP
#include <omp.h>
#ifdef SIMD_COEF_64
#ifndef OMP_SCALE
#define OMP_SCALE               1024 // scaled on core i7-quad HT
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               512 // scaled K8-dual HT
#endif
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL			"HMAC-SHA512"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"password is key, SHA512 " SHA512_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125

#define PAD_SIZE			128
#define BINARY_SIZE			(512/8)
#define BINARY_ALIGN			8

#ifndef SIMD_COEF_64
#define SALT_LENGTH			1024
#else
#define SALT_LENGTH			111
#endif
#define SALT_ALIGN			1
#define CIPHERTEXT_LENGTH		(SALT_SIZE + 1 + BINARY_SIZE * 2)

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define GETPOS(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static struct fmt_tests tests[] = {
	{"what do ya want for nothing?#164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", "Jefe"},
	{"Reference hashes are keys to success#73a5eff716d0147a440fdf5aff187c52deab8c4dc55073be3d5742e788a99fd6b53a5894725f0f88f3486b5bb63d2af930a0cf6267af572128273daf8eee4cfa", "The magnum"},
	{"Beppe#Grillo#AB08C46822313481D548412A084F08C7CA3BBF8A98D901D14698759F4C36ADB07528348D56CAF4F6AF654E14FC102FF10DCF50794A82544426386C7BE238CEAF", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	{"hjXNSoAhq2YLm2vSFtc7BCJNUS9RNPcl#1c10f4d7237b034f27e7af81705e6cb0acecac395086e81e55a391a12b60b49e375b2de39c94f4989a50604754ffeea0b379ae1d4cc6b3550cd0a24a582ef351", "1"},
	{"JkbHdY2Biype3gv2TpG2Wnv68OF7p6cl#a1f6e131e2fe1f728c5f2b8d0d8af9a6e202868ab9abef0e8f9126a712a4ae7f10533bbdedb710f6a521302c48a743caab1715aa85c4a57fbd51fde5e07945d9", "22"},
	{"X4eOvWZw1b9L1NiND4vQxutubtrGhzNe#5a6002cedb05b97ce13393acab09767005a611dfc3e306305772c614ff4869077b3080f23694d3efc6d1998b4514fe8316389edb5f61dbcea8bd3b4d01595ae1", "333"},
	{"VYG7HeRZLyie5jdzDRaqfd0yYX8PFstX#dd2b8b8a97c56af68fef5e73bf1eceec0c951084f97b66196b32758ed8b34a8d2f0e10663acac662e393fd42c0043e4cedf0d3c617ed43ba61b0297353fc2e2a", "4444"},
	{"x8nIFPPTMJMEZLMSELpEub6bQjQzyjkq#fb92efe7d0abff004c8dc94c64356536df65dd42c323da1de4c583c255135b1a15002efc0b794683e7ac4ea7e7ae3813fb132b43c86a6951059a1574908987fb", "55555"},
	{"Hr8KfafSSsEJfp5HZRLVAGQFrEPTDiSi#752e874177fc0f31149ebc699c32b2f7f600ad4d28f1fc27eb715a328100e6e67ff2845b20acd9ebc4befc7a629f1bd9a5b96abf981dcaba71317dcbb8cfdfba", "666666"},
	{"UH0LvhZUihMMECAW0Ummw2OSgAOzV0i9#de3d4986007b1f45542f1d38d294ac69a0e23e2985103082a6ee134d4c786cfcb61d90be72388280e119e047bab32e68c6615d45d21895e5b8ef2b7eaf7258fd", "7777777"},
	{"hX4OqAvhCjwEPwsi9I7SlIQbmlDb6LDh#cbf4fbb0721c9ec00af347d78046c314087efcbce47ef732e119433dc6f7fe3d2788e0a20d76bd2b1f9b199c9914eeaee0a51a2fb88cfbb7472b538e45b53711", "88888888"},
	{"gOONPyTnQVKWMvh61x8Y1JGlDalKCBAE#9d4d34c76cb2a4cbecb8929be61dd4af5088a055bd338cd245311786c4119a5b526b72646626fff1cb4931eb0fe05d8a7648a66f0db1f2522b8af1cfc2ac8e74", "999999999"},
	{"F3WBOJKUyVWbnqtGZ2ur8uW0nqIBpObK#6043dd6dd3dd96699db8351b0db762af27a5db06169ec6668e9f464fcc3fdf1d7deafaccb67e5ef7f5ee96b2a5efad33a8af20eb19fe60d8b20e7994c76a0610", "0000000000"},
	{"pfZzfOSVpQvuILYEIAeCT8Xnj7eQnR2w#ff80da7bbcdb11fd8bb282a80603ed34847d897701fd547d06f4438072ecd43058a3b7c0b3a296f7c5dbbf06beb3825d1eb7122f01ad78ef2afc5ab09c46ca45", "11111111111"},
	{NULL}
};

#ifdef SIMD_COEF_64
#define cur_salt hmacsha512_cur_salt
static unsigned char *crypt_key;
static unsigned char *ipad, *prep_ipad;
static unsigned char *opad, *prep_opad;
JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char cur_salt[SALT_LENGTH * 8 * MAX_KEYS_PER_CRYPT];
static int bufsize;
#else
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static unsigned char (*opad)[PAD_SIZE];
static unsigned char (*ipad)[PAD_SIZE];
static unsigned char cur_salt[SALT_LENGTH+1];
static SHA512_CTX *ipad_ctx;
static SHA512_CTX *opad_ctx;
#endif

#define SALT_SIZE               sizeof(cur_salt)

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int new_keys;

#ifdef SIMD_COEF_64
static void clear_keys(void)
{
	memset(ipad, 0x36, bufsize);
	memset(opad, 0x5C, bufsize);
}
#endif

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_64
	int i;
#endif
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef SIMD_COEF_64
	bufsize = self->params.max_keys_per_crypt * SHA_BUF_SIZ * 8;
	crypt_key = mem_calloc_align(bufsize, 1, MEM_ALIGN_SIMD);
	ipad = mem_calloc_align(bufsize, 1, MEM_ALIGN_SIMD);
	opad = mem_calloc_align(bufsize, 1, MEM_ALIGN_SIMD);
	prep_ipad = mem_calloc_align(self->params.max_keys_per_crypt,
	                             BINARY_SIZE, MEM_ALIGN_SIMD);
	prep_opad = mem_calloc_align(self->params.max_keys_per_crypt,
	                             BINARY_SIZE, MEM_ALIGN_SIMD);
	for (i = 0; i < self->params.max_keys_per_crypt; ++i) {
		crypt_key[GETPOS(BINARY_SIZE, i)] = 0x80;
		((ARCH_WORD_64*)crypt_key)[15 * SIMD_COEF_64 + (i & (SIMD_COEF_64-1)) + (i/SIMD_COEF_64) * SHA_BUF_SIZ * SIMD_COEF_64] = (BINARY_SIZE + PAD_SIZE) << 3;
	}
	clear_keys();
#else
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
	ipad = mem_calloc(self->params.max_keys_per_crypt,
	                  sizeof(*opad));
	opad = mem_calloc(self->params.max_keys_per_crypt,
	                  sizeof(*opad));
	ipad_ctx = mem_calloc(self->params.max_keys_per_crypt,
	                      sizeof(*opad_ctx));
	opad_ctx = mem_calloc(self->params.max_keys_per_crypt,
	                      sizeof(*opad_ctx));
#endif
	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
}

static void done(void)
{
	MEM_FREE(saved_plain);
#ifdef SIMD_COEF_64
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
#if SIMD_COEF_64
	if(i > 111) return 0;
#else
	if(i > SALT_LENGTH) return 0;
#endif
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

#ifdef SIMD_COEF_64
	ARCH_WORD_64 *ipadp = (ARCH_WORD_64*)&ipad[GETPOS(7, index)];
	ARCH_WORD_64 *opadp = (ARCH_WORD_64*)&opad[GETPOS(7, index)];
	const ARCH_WORD_64 *keyp = (ARCH_WORD_64*)key;
	ARCH_WORD_64 temp;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

#if PAD_SIZE < PLAINTEXT_LENGTH
	if (len > PAD_SIZE) {
		unsigned char k0[BINARY_SIZE];
		SHA512_CTX ctx;
		int i;

		SHA512_Init(&ctx);
		SHA512_Update(&ctx, key, len);
		SHA512_Final(k0, &ctx);

		keyp = (ARCH_WORD_64*)k0;
		for(i = 0; i < BINARY_SIZE / 8; i++, ipadp += SIMD_COEF_64, opadp += SIMD_COEF_64)
		{
			temp = JOHNSWAP64(*keyp++);
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	}
	else
#endif
	while(((temp = JOHNSWAP64(*keyp++)) & 0xff00000000000000)) {
		if (!(temp & 0x00ff000000000000) || !(temp & 0x0000ff0000000000))
		{
			((unsigned short*)ipadp)[3] ^=
				(unsigned short)(temp >> 48);
			((unsigned short*)opadp)[3] ^=
				(unsigned short)(temp >> 48);
			break;
		}
		if (!(temp & 0x00ff00000000) || !(temp & 0x0000ff000000))
		{
			((ARCH_WORD_32*)ipadp)[1] ^=
				(ARCH_WORD_32)(temp >> 32);
			((ARCH_WORD_32*)opadp)[1] ^=
				(ARCH_WORD_32)(temp >> 32);
			break;
		}
		if (!(temp & 0x00ff0000) || !(temp & 0x0000ff00))
		{
			((ARCH_WORD_32*)ipadp)[1] ^=
				(ARCH_WORD_32)(temp >> 32);
			((ARCH_WORD_32*)opadp)[1] ^=
				(ARCH_WORD_32)(temp >> 32);
			((unsigned short*)ipadp)[1] ^=
				(unsigned short)(temp >> 16);
			((unsigned short*)opadp)[1] ^=
				(unsigned short)(temp >> 16);
			break;
		}
		*ipadp ^= temp;
		*opadp ^= temp;
		if (!(temp & 0xff))
			break;
		ipadp += SIMD_COEF_64;
		opadp += SIMD_COEF_64;
	}
#else
	int i;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	memset(ipad[index], 0x36, PAD_SIZE);
	memset(opad[index], 0x5C, PAD_SIZE);

#if PAD_SIZE < PLAINTEXT_LENGTH
	if (len > PAD_SIZE) {
		SHA512_CTX ctx;
		unsigned char k0[BINARY_SIZE];

		SHA512_Init( &ctx );
		SHA512_Update( &ctx, key, len);
		SHA512_Final( k0, &ctx);

		len = BINARY_SIZE;

		for(i=0;i<len;i++)
		{
			ipad[index][i] ^= k0[i];
			opad[index][i] ^= k0[i];
		}
	}
	else
#endif
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
#ifdef SIMD_COEF_64
	unsigned int x, y = 0;

	for(; y < (unsigned int)(count + SIMD_COEF_64 - 1) / SIMD_COEF_64; y++)
		for(x = 0; x < SIMD_COEF_64; x++)
		{
			// NOTE crypt_key is in input format (8 * SHA_BUF_SIZ * SIMD_COEF_64)
			if(((ARCH_WORD_64*)binary)[0] == ((ARCH_WORD_64*)crypt_key)[x + y * SIMD_COEF_64 * SHA_BUF_SIZ])
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
#ifdef SIMD_COEF_64
	int i;
	for(i = 0; i < (BINARY_SIZE/8); i++)
		// NOTE crypt_key is in input format (8 * SHA_BUF_SIZ * SIMD_COEF_64)
		if (((ARCH_WORD_64*)binary)[i] != ((ARCH_WORD_64*)crypt_key)[i * SIMD_COEF_64 + (index & (SIMD_COEF_64-1)) + (index/SIMD_COEF_64) * SHA_BUF_SIZ * SIMD_COEF_64])
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
#ifdef SIMD_COEF_64
		if (new_keys) {
			SSESHA512body(&ipad[index * SHA_BUF_SIZ * 8],
			            (ARCH_WORD_64*)&prep_ipad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
			SSESHA512body(&opad[index * SHA_BUF_SIZ * 8],
			            (ARCH_WORD_64*)&prep_opad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN);
		}
		SSESHA512body(cur_salt,
		            (ARCH_WORD_64*)&crypt_key[index * SHA_BUF_SIZ * 8],
		            (ARCH_WORD_64*)&prep_ipad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
		SSESHA512body(&crypt_key[index * SHA_BUF_SIZ * 8],
		            (ARCH_WORD_64*)&crypt_key[index * SHA_BUF_SIZ * 8],
		            (ARCH_WORD_64*)&prep_opad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
#else
		SHA512_CTX ctx;

		if (new_keys) {
			SHA512_Init(&ipad_ctx[index]);
			SHA512_Update(&ipad_ctx[index], ipad[index], PAD_SIZE);
			SHA512_Init(&opad_ctx[index]);
			SHA512_Update(&opad_ctx[index], opad[index], PAD_SIZE);
		}

		memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
		SHA512_Update( &ctx, cur_salt, strlen( (char*) cur_salt) );
		SHA512_Final( (unsigned char*) crypt_key[index], &ctx);

		memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
		SHA512_Update( &ctx, crypt_key[index], BINARY_SIZE);
		SHA512_Final( (unsigned char*) crypt_key[index], &ctx);
#endif
	}
	new_keys = 0;
	return count;
}

static void *get_binary(char *ciphertext)
{
	JTR_ALIGN(BINARY_ALIGN) static unsigned char realcipher[BINARY_SIZE];
	int i,pos;

	for(i=strlen(ciphertext);ciphertext[i]!='#';i--); // allow # in salt
	pos=i+1;
	for(i=0;i<BINARY_SIZE;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];

#ifdef SIMD_COEF_64
	alter_endianity_w64(realcipher, BINARY_SIZE/8);
#endif
	return (void*)realcipher;
}

static void *get_salt(char *ciphertext)
{
	static unsigned char salt[SALT_LENGTH+1];
#ifdef SIMD_COEF_64
	int i = 0;
	unsigned total_len = 0;
#endif
	// allow # in salt
	int len = strrchr(ciphertext, '#') - ciphertext;
	memset(salt, 0, SALT_LENGTH+1);
	memcpy(salt, ciphertext, len);
	salt[len] = 0;
#ifdef SIMD_COEF_64
	memset(cur_salt, 0, sizeof(cur_salt));
	while(((unsigned char*)salt)[total_len])
	{
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
			cur_salt[GETPOS(total_len, i)] = ((unsigned char*)salt)[total_len];
		++total_len;
	}
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
		cur_salt[GETPOS(total_len, i)] = 0x80;
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
		((ARCH_WORD_64*)cur_salt)[15 * SIMD_COEF_64 + (i & (SIMD_COEF_64-1)) + (i/SIMD_COEF_64) * SHA_BUF_SIZ * SIMD_COEF_64] = (total_len + 128) << 3;
	return cur_salt;
#else
	return salt;
#endif
}

#ifdef SIMD_COEF_64
// NOTE crypt_key is in input format (4 * SHA_BUF_SIZ * SIMD_COEF_64)
#define HASH_OFFSET (index & (SIMD_COEF_64 - 1)) + ((unsigned int)index / SIMD_COEF_64) * SIMD_COEF_64 * SHA_BUF_SIZ
static int get_hash_0(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_64*)crypt_key)[HASH_OFFSET] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return crypt_key[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_key[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_key[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[index][0] & 0x7ffffff; }
#endif

struct fmt_main fmt_hmacSHA512 = {
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
#ifdef SIMD_COEF_64
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

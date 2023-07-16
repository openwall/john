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
extern struct fmt_main fmt__hmacSHA512;
extern struct fmt_main fmt__hmacSHA384;
#elif FMT_REGISTERS_H
john_register_one(&fmt__hmacSHA512);
john_register_one(&fmt__hmacSHA384);
#else

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "base64_convert.h"
#include "formats.h"
#include "aligned.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL			"HMAC-SHA512"
#define FORMAT_LABEL_384		"HMAC-SHA384"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"password is key, SHA512 " SHA512_ALGORITHM_NAME
#define ALGORITHM_NAME_384		"password is key, SHA384 " SHA512_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		125

#define PAD_SIZE			128
#define PAD_SIZE_W			(PAD_SIZE/8)
#define BINARY_SIZE			(512/8)
#define BINARY_SIZE_384			(384/8)
#define BINARY_ALIGN			8

#ifndef SIMD_COEF_64
#define SALT_LENGTH			1023
#define SALT_ALIGN			1
#else
#define SALT_LIMBS			2  /* 2 limbs, 239 bytes */
#define SALT_LENGTH			(SALT_LIMBS * PAD_SIZE - 17)
#define SALT_ALIGN			MEM_ALIGN_SIMD
#endif
#define CIPHERTEXT_LENGTH		(SALT_LENGTH + 1 + BINARY_SIZE * 2)
#define CIPHERTEXT_LENGTH_384		(SALT_LENGTH + 1 + BINARY_SIZE_384 * 2)

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512 * 8)
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i&127)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i&127)&7)) + index/SIMD_COEF_64 * PAD_SIZE * SIMD_COEF_64 )
#else
#define GETPOS(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i&127)&(0xffffffff-7))*SIMD_COEF_64 + ((i&127)&7) + index/SIMD_COEF_64 * PAD_SIZE * SIMD_COEF_64 )
#endif
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
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
	/* mockup JWT hash */
	{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.r7FDU-ahrbW0Wtsekh5UNqV2iyXGrQQaRZjdc8i733QIoTSIQM__FSGjP151C2ijvNUVo5syWOW-RpZc7khU1g", "magnum"},
	{NULL}
};
static struct fmt_tests tests_384[] = {
	{"what do ya want for nothing?#af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649", "Jefe"},
	{"Beppe#Grillo#8361922C63506E53714F8A8491C6621A76CF0FD6DFEAD91BF59B420A23DFF2745C0A0D5E142D4F937E714EA8C228835B", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
	/* mockup JWT hash */
	{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.WNzjJCdDCTV3hLfsRy__hny9VzlaZXHFvoKSJXB5_rbKkXwE1Jve_DUirW7r5ztm", "magnum"},
	{NULL}
};

#ifdef SIMD_COEF_64
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
static unsigned char (*opad)[PAD_SIZE];
static unsigned char (*ipad)[PAD_SIZE];
static unsigned char cur_salt[SALT_LENGTH+1];
static SHA512_CTX *ipad_ctx;
static SHA512_CTX *opad_ctx;
#define SALT_SIZE               sizeof(cur_salt)
#endif

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int new_keys;

#ifdef SIMD_COEF_64
static void clear_keys(void)
{
	memset(ipad, 0x36, bufsize);
	memset(opad, 0x5C, bufsize);
}
#endif

static void init(struct fmt_main *self, const int B_LEN)
{
#ifdef SIMD_COEF_64
	int i;
#endif

	omp_autotune(self, OMP_SCALE);

#ifdef SIMD_COEF_64
	bufsize = sizeof(*opad) * self->params.max_keys_per_crypt * PAD_SIZE;
	crypt_key = mem_calloc_align(1, bufsize, MEM_ALIGN_SIMD);
	ipad = mem_calloc_align(1, bufsize, MEM_ALIGN_SIMD);
	opad = mem_calloc_align(1, bufsize, MEM_ALIGN_SIMD);
	prep_ipad = mem_calloc_align(self->params.max_keys_per_crypt,
	                             BINARY_SIZE, MEM_ALIGN_SIMD);
	prep_opad = mem_calloc_align(self->params.max_keys_per_crypt,
	                             BINARY_SIZE, MEM_ALIGN_SIMD);
	for (i = 0; i < self->params.max_keys_per_crypt; ++i) {
		crypt_key[GETPOS(B_LEN, i)] = 0x80;
		((uint64_t*)crypt_key)[15 * SIMD_COEF_64 + (i&(SIMD_COEF_64-1)) + (i/SIMD_COEF_64) * PAD_SIZE_W * SIMD_COEF_64] = (B_LEN + PAD_SIZE) << 3;
	}
	clear_keys();
#else
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
	ipad = mem_calloc(sizeof(*ipad), self->params.max_keys_per_crypt);
	opad = mem_calloc(sizeof(*opad), self->params.max_keys_per_crypt);
	ipad_ctx = mem_calloc_align(self->params.max_keys_per_crypt,
	                      sizeof(*opad_ctx), 8);
	opad_ctx = mem_calloc_align(self->params.max_keys_per_crypt,
	                      sizeof(*opad_ctx), 8);
#endif
	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
}
static void init_512(struct fmt_main *self) {
	init(self, BINARY_SIZE);
}
static void init_384(struct fmt_main *self) {
	init(self, BINARY_SIZE_384);
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

static char *split(char *ciphertext, int index, struct fmt_main *self, const int B_LEN, const int CT_LEN)
{
	static char out[(BINARY_SIZE * 2 + 1) + (CIPHERTEXT_LENGTH + 1) + 2];

	if (strnlen(ciphertext, LINE_BUFFER_SIZE) < LINE_BUFFER_SIZE &&
	    strstr(ciphertext, "$SOURCE_HASH$"))
		return ciphertext;

	if (!strchr(ciphertext, '#')) {
		// Treat this like a JWT hash. Convert into 'normal' hmac-sha512 format.
		char buf[BINARY_SIZE * 2 + 1], tmp[CIPHERTEXT_LENGTH + 1], *cpi;

		strnzcpy(tmp, ciphertext, sizeof(tmp));
		cpi = strchr(tmp, '.');
		cpi = strchr(&cpi[1], '.');
		if (cpi - tmp + B_LEN * 2 + 1  > CT_LEN)
			return ciphertext;
		*cpi++ = 0;
		memset(buf, 0, sizeof(buf));
		base64_convert(cpi, e_b64_mime, strlen(cpi), buf, e_b64_hex,
		               sizeof(buf), flg_Base64_NO_FLAGS, 0);
		if (strlen(buf) != B_LEN * 2)
			return ciphertext;
		sprintf(out, "%s#%s", tmp, buf);
	} else
		strnzcpy(out, ciphertext, sizeof(out));
	strlwr(strrchr(out, '#'));

	return out;
}
static char *split_512(char *ciphertext, int index, struct fmt_main *self) {
	return split(ciphertext, index, self, BINARY_SIZE, CIPHERTEXT_LENGTH);
}
static char *split_384(char *ciphertext, int index, struct fmt_main *self) {
	return split(ciphertext, index, self, BINARY_SIZE_384, CIPHERTEXT_LENGTH_384);
}

static int valid_jwt(const char *ciphertext, const int B_LEN)
{
	static const char * const base64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const char *p = ciphertext;
	if (*p++ != 'e') /* Assume no whitespace before JSON's "{" */
		return 0;
	p += strspn(p, base64url);
	if (*p++ != '.')
		return 0;
	p += strspn(p, base64url);
	if (*p++ != '.')
		return 0;
	const int E_LEN = (B_LEN * 8 + 5) / 6;
	if (strspn(p, base64url) != E_LEN)
		return 0;
	return !p[E_LEN];
}

static int valid(char *ciphertext, struct fmt_main *self, const int B_LEN, const int CT_LEN)
{
	char *p;
	int extra;

	p = strrchr(ciphertext, '#'); /* search backwards to allow '#' in salt */
	if (!p && valid_jwt(ciphertext, B_LEN)) {
		if (strlen(ciphertext) > CT_LEN)
			return 0;
		ciphertext = split(ciphertext, 0, self, B_LEN, CT_LEN);
		p = strrchr(ciphertext, '#');
	}
	if (!p)
		return 0;
	if (p - ciphertext > SALT_LENGTH)
		return 0;
	if (hexlen(++p, &extra) != B_LEN * 2 || extra)
		return 0;
	return 1;
}
static int valid_512(char *ciphertext, struct fmt_main *self) {
	return valid(ciphertext, self,  BINARY_SIZE, CIPHERTEXT_LENGTH);
}
static int valid_384(char *ciphertext, struct fmt_main *self) {
	return valid(ciphertext, self,  BINARY_SIZE_384, CIPHERTEXT_LENGTH_384);
}

static void set_salt(void *salt)
{
#ifdef SIMD_COEF_64
	cur_salt = salt;
#else
	strcpy((char*)cur_salt, (char*)salt);
#endif
}

static MAYBE_INLINE void set_key(char *key, int index, const int B_LEN)
{
	int len;

#ifdef SIMD_COEF_64
#if ARCH_LITTLE_ENDIAN==1
	uint64_t *ipadp = (uint64_t*)&ipad[GETPOS(7, index)];
	uint64_t *opadp = (uint64_t*)&opad[GETPOS(7, index)];
#else
	uint64_t *ipadp = (uint64_t*)&ipad[GETPOS(0, index)];
	uint64_t *opadp = (uint64_t*)&opad[GETPOS(0, index)];
#endif
	const uint64_t *keyp = (uint64_t*)key;
	uint64_t temp;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	if (len > PAD_SIZE) {
		unsigned char k0[BINARY_SIZE];
		SHA512_CTX ctx;
		int i;

		if (B_LEN == BINARY_SIZE) {
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, key, len);
			SHA512_Final(k0, &ctx);
		} else {
			SHA384_Init(&ctx);
			SHA384_Update(&ctx, key, len);
			SHA384_Final(k0, &ctx);
		}

		keyp = (uint64_t*)k0;
		for (i = 0; i < B_LEN / 8; i++, ipadp += SIMD_COEF_64, opadp += SIMD_COEF_64)
		{
#if ARCH_LITTLE_ENDIAN==1
			temp = JOHNSWAP64(*keyp++);
#else
			temp = *keyp++;
#endif
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	}
	else
#if ARCH_LITTLE_ENDIAN==1
	while(((temp = JOHNSWAP64(*keyp++)) & 0xff00000000000000ULL)) {
		if (!(temp & 0x00ff000000000000ULL) || !(temp & 0x0000ff0000000000ULL))
		{
			((unsigned short*)ipadp)[3] ^=
				(unsigned short)(temp >> 48);
			((unsigned short*)opadp)[3] ^=
				(unsigned short)(temp >> 48);
			break;
		}
		if (!(temp & 0x00ff00000000ULL) || !(temp & 0x0000ff000000ULL))
		{
			((uint32_t*)ipadp)[1] ^=
				(uint32_t)(temp >> 32);
			((uint32_t*)opadp)[1] ^=
				(uint32_t)(temp >> 32);
			break;
		}
		if (!(temp & 0x00ff0000) || !(temp & 0x0000ff00))
		{
			((uint32_t*)ipadp)[1] ^=
				(uint32_t)(temp >> 32);
			((uint32_t*)opadp)[1] ^=
				(uint32_t)(temp >> 32);
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
	while(((temp = *keyp++) & 0xff00000000000000ULL)) {
		if (!(temp & 0x00ff000000000000ULL) || !(temp & 0x0000ff0000000000ULL))
		{
			((unsigned short*)ipadp)[0] ^=
				(unsigned short)(temp >> 48);
			((unsigned short*)opadp)[0] ^=
				(unsigned short)(temp >> 48);
			break;
		}
		if (!(temp & 0x00ff00000000ULL) || !(temp & 0x0000ff000000ULL))
		{
			((uint32_t*)ipadp)[0] ^=
				(uint32_t)(temp >> 32);
			((uint32_t*)opadp)[0] ^=
				(uint32_t)(temp >> 32);
			break;
		}
		if (!(temp & 0x00ff0000) || !(temp & 0x0000ff00))
		{
			((uint32_t*)ipadp)[0] ^=
				(uint32_t)(temp >> 32);
			((uint32_t*)opadp)[0] ^=
				(uint32_t)(temp >> 32);
			((unsigned short*)ipadp)[2] ^=
				(unsigned short)(temp >> 16);
			((unsigned short*)opadp)[2] ^=
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
#endif

#else
	int i;

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	memset(ipad[index], 0x36, PAD_SIZE);
	memset(opad[index], 0x5C, PAD_SIZE);

	if (len > PAD_SIZE) {
		SHA512_CTX ctx;
		unsigned char k0[BINARY_SIZE];

		if (B_LEN == BINARY_SIZE) {
			SHA512_Init( &ctx );
			SHA512_Update( &ctx, key, len);
			SHA512_Final( k0, &ctx);
		} else {
			SHA384_Init( &ctx );
			SHA384_Update( &ctx, key, len);
			SHA384_Final( k0, &ctx);
		}

		len = B_LEN;

		for (i=0;i<len;i++)
		{
			ipad[index][i] ^= k0[i];
			opad[index][i] ^= k0[i];
		}
	}
	else
	for (i=0;i<len;i++)
	{
		ipad[index][i] ^= key[i];
		opad[index][i] ^= key[i];
	}
#endif
	new_keys = 1;
}
static void set_key_512(char *key, int index) {
	set_key(key, index, BINARY_SIZE);
}
static void set_key_384(char *key, int index) {
	set_key(key, index, BINARY_SIZE_384);
}

static char *get_key(int index)
{
	return saved_plain[index];
}

static int cmp_all(void *binary, int count)
{
#ifdef SIMD_COEF_64
	unsigned int index;

	for (index = 0; index < count; index++) {
		// NOTE crypt_key is in input format (PAD_SIZE * SIMD_COEF_64)
		if (((uint64_t*)binary)[0] == ((uint64_t*)crypt_key)[(index&(SIMD_COEF_64-1))+index/SIMD_COEF_64*PAD_SIZE_W*SIMD_COEF_64])
			return 1;
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

static int cmp_one(void *binary, int index, int B_LEN)
{
#ifdef SIMD_COEF_64
	int i;
	for (i = 0; i < (B_LEN/8); i++)
		// NOTE crypt_key is in input format (PAD_SIZE * SIMD_COEF_64)
		if (((uint64_t*)binary)[i] != ((uint64_t*)crypt_key)[i * SIMD_COEF_64 + (index & (SIMD_COEF_64-1)) + (index/SIMD_COEF_64) * PAD_SIZE_W * SIMD_COEF_64])
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], B_LEN);
#endif
}
static int cmp_one_512(void *binary, int index) {
	return cmp_one(binary, index, BINARY_SIZE);
}
static int cmp_one_384(void *binary, int index) {
	return cmp_one(binary, index, BINARY_SIZE_384);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt,
#ifdef SIMD_COEF_64
	const unsigned EX_FLAGS
#else
	const int B_LEN
#endif
	)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_64
		unsigned int i;

		if (new_keys) {
			SIMDSHA512body(&ipad[index * PAD_SIZE],
			            (uint64_t*)&prep_ipad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN|EX_FLAGS);
			SIMDSHA512body(&opad[index * PAD_SIZE],
			            (uint64_t*)&prep_opad[index * BINARY_SIZE],
			            NULL, SSEi_MIXED_IN|EX_FLAGS);
		}

		SIMDSHA512body(cur_salt->salt[0],
			        (uint64_t*)&crypt_key[index * PAD_SIZE],
			        (uint64_t*)&prep_ipad[index * BINARY_SIZE],
			        SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT|EX_FLAGS);
		for (i = 1; i <= (cur_salt->salt_len + 16) / PAD_SIZE; i++)
			SIMDSHA512body(cur_salt->salt[i],
			        (uint64_t*)&crypt_key[index * PAD_SIZE],
			        (uint64_t*)&crypt_key[index * PAD_SIZE],
			         SSEi_MIXED_IN|SSEi_RELOAD_INP_FMT|SSEi_OUTPUT_AS_INP_FMT|EX_FLAGS);

		if (EX_FLAGS) {
			// NOTE, SSESHA384 will output 64 bytes. We need the first 48 (plus the 0x80 padding).
			// so we are forced to 'clean' this crap up, before using the crypt as the input.
			uint64_t *pclear = (uint64_t*)&crypt_key[index/SIMD_COEF_64*PAD_SIZE_W*SIMD_COEF_64*8];
			for (i = 0; i < MIN_KEYS_PER_CRYPT; i++) {
				pclear[48/8*SIMD_COEF_64+(i&(SIMD_COEF_64-1))+i/SIMD_COEF_64*PAD_SIZE_W*SIMD_COEF_64] = 0x8000000000000000ULL;
				pclear[48/8*SIMD_COEF_64+(i&(SIMD_COEF_64-1))+i/SIMD_COEF_64*PAD_SIZE_W*SIMD_COEF_64+SIMD_COEF_64] = 0;
			}
		}

		SIMDSHA512body(&crypt_key[index * PAD_SIZE],
		            (uint64_t*)&crypt_key[index * PAD_SIZE],
		            (uint64_t*)&prep_opad[index * BINARY_SIZE],
		            SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT|EX_FLAGS);
#else
		SHA512_CTX ctx;

		// Note, for oSSL, we really only need SHA512_Init and SHA384_Init.  From that point
		// on, SHA512_Update/SHA512_Final can be used.  Also, jtr internal sha2.c file works
		// like that. BUT I am not sure every hash engine works that way, so we are keeping
		// the 'full' block.
		if (B_LEN == BINARY_SIZE) {
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
			SHA512_Update( &ctx, crypt_key[index], B_LEN);
			SHA512_Final( (unsigned char*) crypt_key[index], &ctx);
		} else {
			if (new_keys) {
				SHA384_Init(&ipad_ctx[index]);
				SHA384_Update(&ipad_ctx[index], ipad[index], PAD_SIZE);
				SHA384_Init(&opad_ctx[index]);
				SHA384_Update(&opad_ctx[index], opad[index], PAD_SIZE);
			}

			memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
			SHA384_Update( &ctx, cur_salt, strlen( (char*) cur_salt) );
			SHA384_Final( (unsigned char*) crypt_key[index], &ctx);

			memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
			SHA384_Update( &ctx, crypt_key[index], B_LEN);
			SHA384_Final( (unsigned char*) crypt_key[index], &ctx);
		}
#endif
	}
	new_keys = 0;
	return count;
}
static int crypt_all_512(int *pcount, struct db_salt *salt) {
#ifdef SIMD_COEF_64
	return crypt_all(pcount, salt, 0);
#else
	return crypt_all(pcount, salt, BINARY_SIZE);
#endif
}
static int crypt_all_384(int *pcount, struct db_salt *salt) {
#ifdef SIMD_COEF_64
	return crypt_all(pcount, salt, SSEi_CRYPT_SHA384);
#else
	return crypt_all(pcount, salt, BINARY_SIZE_384);
#endif
}

static void *get_binary(char *ciphertext, const int B_LEN)
{
	JTR_ALIGN(BINARY_ALIGN) static unsigned char realcipher[BINARY_SIZE];
	int i,pos;

	for (i=strlen(ciphertext);ciphertext[i]!='#';i--); // allow # in salt
	pos=i+1;
	for (i=0;i<B_LEN;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];

#if defined(SIMD_COEF_64) && ARCH_LITTLE_ENDIAN==1
	alter_endianity_w64(realcipher, B_LEN/8);
#endif
	return (void*)realcipher;
}
static void *get_binary_512(char *ciphertext) {
	return get_binary(ciphertext, BINARY_SIZE);
}
static void *get_binary_384(char *ciphertext) {
	return get_binary(ciphertext, BINARY_SIZE_384);
}

static void *get_salt(char *ciphertext)
{
	static unsigned char salt[SALT_LENGTH+1];
	int len;
#ifdef SIMD_COEF_64
	unsigned int i = 0;
	static JTR_ALIGN(MEM_ALIGN_SIMD) cur_salt_t cur_salt;
	int salt_len = 0;
#endif

	// allow # in salt
	len = strrchr(ciphertext, '#') - ciphertext;
	memset(salt, 0, sizeof(salt));
	memcpy(salt, ciphertext, len);
#ifdef SIMD_COEF_64
	memset(&cur_salt, 0, sizeof(cur_salt));
	while(((unsigned char*)salt)[salt_len])
	{
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			cur_salt.salt[salt_len / PAD_SIZE][GETPOS(salt_len, i)] =
				((unsigned char*)salt)[salt_len];
		++salt_len;
	}
	cur_salt.salt_len = salt_len;
	for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
		cur_salt.salt[salt_len / PAD_SIZE][GETPOS(salt_len, i)] = 0x80;
		((uint64_t*)cur_salt.salt[(salt_len+16) / PAD_SIZE])[15 * SIMD_COEF_64 + (i & (SIMD_COEF_64-1)) + (i/SIMD_COEF_64) * PAD_SIZE_W * SIMD_COEF_64] = (salt_len + PAD_SIZE) << 3;
	}
	return &cur_salt;
#else
	return salt;
#endif
}

struct fmt_main fmt__hmacSHA512 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ NULL },
		tests
	}, {
		init_512,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_512,
		split_512,
		get_binary_512,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key_512,
		get_key,
#ifdef SIMD_COEF_64
		clear_keys,
#else
		fmt_default_clear_keys,
#endif
		crypt_all_512,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one_512,
		cmp_exact
	}
};

struct fmt_main fmt__hmacSHA384 = {
	{
		FORMAT_LABEL_384,
		FORMAT_NAME,
		ALGORITHM_NAME_384,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE_384,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ NULL },
		tests_384
	}, {
		init_384,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid_384,
		split_384,
		get_binary_384,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key_384,
		get_key,
#ifdef SIMD_COEF_64
		clear_keys,
#else
		fmt_default_clear_keys,
#endif
		crypt_all_384,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one_384,
		cmp_exact
	}
};

#endif /* plugin stanza */

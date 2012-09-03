/* *New* EPiServer cracker patch for JtR. Hacked together during Summer of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC. Based on sample
 * code by hashcat's atom.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Obtaining hashes from EPiServer 6.x:
 *
 * sqlcmd -L
 * sqlcmd -S <server> -U sa -P <password> *
 * 1> SELECT name from sys.databases
 * 2> go
 * 1> use <database name>
 * 2> select Email, PasswordFormat, PasswordSalt, Password from aspnet_Membership
 * 3> go
 *
 * JtR Input Format:
 *
 * user:$episerver$*version*base64(salt)*base64(hash)
 *
 * Where,
 *
 * version == 0, for EPiServer 6.x standard config / .NET <= 3.5 SHA1 hash/salt format.
 * 		 hash =  sha1(salt | utf16bytes(password)), PasswordFormat == 1 *
 *
 * version == 1, EPiServer 6.x + .NET >= 4.x SHA256 hash/salt format,
 * 		 PasswordFormat == ?
 *
 * Improved performance, JimF, July 2012.
 * Full Unicode support, magnum, August 2012.
 */

#include "sha.h"
#include "sha2.h"
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#include "unicode.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               4
#endif

#define FORMAT_LABEL		"episerver"
#define FORMAT_NAME		"EPiServer salted SHA-1/SHA-256"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR " " SHA2_LIB
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		32 /* larger of the two */
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	16

static struct fmt_tests episerver_tests[] = {
	{"$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*UQgnz/vPWap9UeD8Dhaw3h/fgFA=", "testPassword"},
	{"$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*uiP1YrZlVcHESbfsRt/wljwNeYU=", "sss"},
	{"$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*dxTlKqnxaVHs0210VcX+48QDonA=", "notused"},

	// hashes from pass_gen.pl, including some V1 data
	{"$episerver$*0*OHdOb002Z1J6ZFhlRHRzbw==*74l+VCC9xkGP27sNLPLZLRI/O5A", "test1"},
	{"$episerver$*0*THk5ZHhYNFdQUDV1Y0hScg==*ik+FVrPkEs6LfJU88xl5oBRoZjY", ""},
	{"$episerver$*1*aHIza2pUY0ZkR2dqQnJrNQ==*1KPAZriqakiNvE6ML6xkUzS11QPREziCvYkJc4UtjWs","test1"},
	{"$episerver$*1*RUZzRmNja0c5NkN0aDlMVw==*nh46rc4vkFIL0qGUrKTPuPWO6wqoESSeAxUNccEOe28","thatsworking"},
	{"$episerver$*1*cW9DdnVVUnFwM2FobFc4dg==*Zr/nekpDxU5gjt+fzTSqm0j/twZySBBW44Csoai2Fug","test3"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int version;
	unsigned char esalt[18]; /* base64 decoding, 24 / 4 * 3 = 18 */
} *cur_salt;

static void init(struct fmt_main *self)
{

#if defined (_OPENMP)
	static int omp_t = 1;
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	if (options.utf8)
		self->params.plaintext_length = PLAINTEXT_LENGTH * 3;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$episerver$", 11);
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char _ctcopy[256], *ctcopy=_ctcopy;
	char *p;
	strncpy(ctcopy, ciphertext, 255);
	ctcopy[255] = 0;
	ctcopy += 12;	/* skip over "$episerver$*" */
	p = strtok(ctcopy, "*");
	cs.version = atoi(p);
	p = strtok(NULL, "*");
	base64_decode(p, strlen(p), (char*)cs.esalt);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	p = strrchr(ciphertext, '*') + 1;
	base64_decode(p, strlen(p), (char*)out);
	return out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		unsigned char passwordBuf[PLAINTEXT_LENGTH*2+2];
		int len;
		len = enc_to_utf16((UTF16*)passwordBuf, PLAINTEXT_LENGTH,
		                   (UTF8*)saved_key[index], strlen(saved_key[index]));
		if (len < 0)
			len = strlen16((UTF16*)saved_key[index]);
		len <<= 1;
		if(cur_salt->version == 0) {
			SHA_CTX ctx;
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, cur_salt->esalt, 16);
			SHA1_Update(&ctx, passwordBuf, len);
			SHA1_Final((unsigned char*)crypt_out[index], &ctx);
		}
		else if(cur_salt->version == 1) {
			SHA256_CTX ctx;
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, cur_salt->esalt, 16);
			SHA256_Update(&ctx, passwordBuf, len);
			SHA256_Final((unsigned char*)crypt_out[index], &ctx);
		}
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++) {
		if (*((ARCH_WORD_32*)binary) == crypt_out[index][0])
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (*((ARCH_WORD_32*)binary) == crypt_out[index][0]);
}

static int cmp_exact(char *source, int index)
{
	void *binary = get_binary(source);
	if(cur_salt->version == 0)
		return !memcmp(binary, crypt_out[index], 20);
	else
		return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static void episerver_set_key(char *key, int index)
{
	strcpy(saved_key[index], key);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main episerver_fmt = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8,
		episerver_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		set_salt,
		episerver_set_key,
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

/*
 * this is a SAP-H plugin for john the ripper.
 * Copyright (c) 2014 JimF, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sapH;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sapH);
#else

#include <string.h>
#include <ctype.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "base64_convert.h"
#include "sha.h"
#include "sha2.h"

/* for now, undef this until I get OMP working, then start on SIMD */
#undef MMX_COEF
#undef SHA1_SSE_PARA


#if defined(_OPENMP)
#include <omp.h>
#ifdef MMX_COEF
#define OMP_SCALE			16
#else
#define OMP_SCALE			64
#endif
#endif

/*
 * Assumption is made that MMX_COEF*SHA1_SSE_PARA is >= than
 * SHA256_COEF*PARA and SHA512_COEF*PARA, and that these other 2
 * will evenly divide the MMX_COEF*SHA1_SSRE_PARA value.
 * Works with current code. BUT if SHA1_SSE_PARA was 3 and
 * SHA256_SSE_PARA was 2, then we would have problems.
 */
#ifdef MMX_COEF
#define NBKEYS	(MMX_COEF * SHA1_SSE_PARA)
#endif
#include "sse-intrinsics.h"

#define FORMAT_LABEL            "saph"
#define FORMAT_NAME             "SAP CODVN H (HCODE)"

#define ALGORITHM_NAME          "SHA1/SHA256/SHA384/SHA512"

#include "memdbg.h"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define SALT_LENGTH             16  /* the max used sized salt */
#define PLAINTEXT_LENGTH        125
#define CIPHERTEXT_LENGTH       132 /* max salt+sha512 + 2^32 iterations */

#define BINARY_SIZE             16 /* we cut off all hashes down to 16 bytes */
#define MAX_BINARY_SIZE         64 /* sha512 is 64 byte */
#define SHA1_BINARY_SIZE        20
#define SHA256_BINARY_SIZE      32
#define SHA384_BINARY_SIZE      48
#define SHA512_BINARY_SIZE      64
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct saltstruct)
#define SALT_ALIGN              4

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
/* NOTE, format is slow enough that endianity conversion is pointless. Just use flat buffers. */
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static struct fmt_tests tests[] = {
	{"{x-issha, 1024}L1PHSP1vOwdYh0ASjswI69fQQQhzQXFlWmxnaFA5","booboo"},
	{"{x-issha, 1024}dCjaHQ47/WeSwsoSYDR/8puLby5T","booboo"},	/* 1 byte salt */
	{"{x-issha, 1024}+q+WSxWXJt7SjV5VJEymEKPUbn1FQWM=","HYulafeE!3"},

	{"{x-isSHA256, 3000}UqMnsr5BYN+uornWC7yhGa/Wj0u5tshX19mDUQSlgih6OTFoZjRpMQ==","booboo"},
	{"{x-isSHA256, 3000}ydi0JlyU6lX5305Qk/Q3uLBbIFjWuTyGo3tPBZDcGFd6NkFvV1gza3RkNg==","GottaGoWhereNeeded"},
	
	{"{x-isSHA384, 5000}3O/F4YGKNmIYHDu7ZQ7Q+ioCOQi4HRY4yrggKptAU9DtmHigCuGqBiAPVbKbEAfGTzh4YlZLWUM=","booboo"},
	{"{x-isSHA384, 5000}XSLo2AKIvACwqW/X416UeVbHOXmio4u27Z7cgXS2rxND+zTpN+x3JNfQcEQX2PT0Z3FPdEY2dHM=","yiPP3rs"},
	
	{"{x-isSHA512, 7500}ctlX6qYsWspafEzwoej6nFp7zRQQjr8y22vE+xeveIX2gUndAw9N2Gep5azNUwuxOe2o7tusF800OfB9tg4taWI4Tg==","booboo"},
	{"{x-isSHA512, 7500}Qyrh2JXgGkvIfKYOJRdWFut5/pVnXI/vZvqJ7N+Tz9M1zUTXGWCZSom4az4AhqOuAahBwuhcKqMq/pYPW4h3cThvT2JaWVBw","hapy1CCe!"},
	{"{x-isSHA512, 18009}C2+Sij3JyXPPDuQgsF6Zot7XnjRFX86X67tWJpUzXNnFw2dKcGPH6HDEzVJ8HN8+cJe4vZaOYTlmdz09gI7YEwECAwQFBgcICQoLDA0ODwA=","maxlen"},

	{NULL}
};

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE/sizeof(ARCH_WORD_32)];

static struct saltstruct {
	int slen;	/* actual length of salt ( 1 to 16 bytes) */
	int type;	/* 1, 256, 384 or 512 for sha1, sha256, sha384 or sha512 */
	unsigned iter;   /* from 1 to 2^32 rounds */
	unsigned char s[SALT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt = omp_t * MIN_KEYS_PER_CRYPT;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt = omp_t * MAX_KEYS_PER_CRYPT;
#endif
	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) * self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int isdecu(char *q)
{
	char buf[24];
	unsigned int x;
	sscanf(q, "%u", &x);
	sprintf(buf, "%u", x);
	return x && !strcmp(q,buf);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *cp = ciphertext;
	char *keeptr;
	int len, hash_len=0;
	char tmp[MAX_BINARY_SIZE+SALT_LENGTH+4];
	/* first check for 'simple' signatures before allocation other stuff. */
	if (strncmp(cp, "{x-is", 5) || !strchr(cp, '}'))
		return 0;
	if (!strncmp(&cp[5], "sha, ", 5))
		hash_len = SHA1_BINARY_SIZE;
	if (!hash_len && !strncmp(&cp[5], "SHA256, ", 8))
		hash_len = SHA256_BINARY_SIZE;
	if (!hash_len && !strncmp(&cp[5], "SHA384, ", 8))
		hash_len = SHA384_BINARY_SIZE;
	if (!hash_len && !strncmp(&cp[5], "SHA512, ", 8))
		hash_len = SHA512_BINARY_SIZE;
	if (!hash_len)
		return 0;
	keeptr = strdup(cp);
	cp = keeptr;
	while (*cp++ != ' ') ;  /* skip the "{x-issha?, " */

	if ((cp = strtok(cp, "}")) == NULL)
		goto err;
	if (!isdecu(cp))
		goto err;

	if ((cp = strtok(NULL, " ")) == NULL)
		goto err;
	if (strlen(cp) != base64_valid_length(cp, e_b64_mime, flg_Base64_MIME_TRAIL_EQ|flg_Base64_MIME_TRAIL_EQ_CNT))
		return 0;
	len = base64_convert(cp, e_b64_mime, strlen(cp), tmp, e_b64_raw,
	                     MAX_BINARY_SIZE+SALT_LENGTH, flg_Base64_MIME_TRAIL_EQ);
	len -= hash_len;
	if (len < 1 || len > SALT_LENGTH)
		return 0;

	MEM_FREE(keeptr);
	return 1;
err:
	MEM_FREE(keeptr);
	return 0;
}

static void set_salt(void *salt)
{
	cur_salt = (struct saltstruct*)salt;
}

static void set_key(char *key, int index)
{
	strcpy((char*)saved_plain[index], key);
}

static char *get_key(int index)
{
	return (char*)saved_plain[index];
}

static int cmp_all(void *binary, int count) {
	int index;
	for (index = 0; index < count; index++)
		if (*(ARCH_WORD_32*)binary == *(ARCH_WORD_32*)crypt_key[index])
			return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int cmp_one(void * binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static void crypt_all_1(int count) {
	int idx;
#if defined(_OPENMP)
#pragma omp parallel for
#endif
	for (idx = 0; idx < count; ++idx) {
		int i, len = strlen(saved_plain[idx]);
		unsigned char tmp[SHA1_BINARY_SIZE];
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_plain[idx], len);
		SHA1_Update(&ctx, cur_salt->s, cur_salt->slen);
		SHA1_Final(tmp, &ctx);
		for (i = 1; i < cur_salt->iter; ++i) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, saved_plain[idx], len);
			SHA1_Update(&ctx, tmp, SHA1_BINARY_SIZE);
			SHA1_Final(tmp, &ctx);
		}
		memcpy(crypt_key[idx], tmp, BINARY_SIZE);
	}
}
static void crypt_all_256(int count) {
	int idx;
#if defined(_OPENMP)
#pragma omp parallel for
#endif
	for (idx = 0; idx < count; ++idx) {
		int i, len = strlen(saved_plain[idx]);
		unsigned char tmp[SHA256_BINARY_SIZE];
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_plain[idx], len);
		SHA256_Update(&ctx, cur_salt->s, cur_salt->slen);
		SHA256_Final(tmp, &ctx);
		for (i = 1; i < cur_salt->iter; ++i) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, saved_plain[idx], len);
			SHA256_Update(&ctx, tmp, SHA256_BINARY_SIZE);
			SHA256_Final(tmp, &ctx);
		}
		memcpy(crypt_key[idx], tmp, BINARY_SIZE);
	}
}
static void crypt_all_384(int count) {
	int idx;
#if defined(_OPENMP)
#pragma omp parallel for
#endif
	for (idx = 0; idx < count; ++idx) {
		int i, len = strlen(saved_plain[idx]);
		unsigned char tmp[SHA384_BINARY_SIZE];
		SHA512_CTX ctx;
		SHA384_Init(&ctx);
		SHA384_Update(&ctx, saved_plain[idx], len);
		SHA384_Update(&ctx, cur_salt->s, cur_salt->slen);
		SHA384_Final(tmp, &ctx);
		for (i = 1; i < cur_salt->iter; ++i) {
			SHA384_Init(&ctx);
			SHA384_Update(&ctx, saved_plain[idx], len);
			SHA384_Update(&ctx, tmp, SHA384_BINARY_SIZE);
			SHA384_Final(tmp, &ctx);
		}
		memcpy(crypt_key[idx], tmp, BINARY_SIZE);
	}
}
static void crypt_all_512(int count) {
	int idx;
#if defined(_OPENMP)
#pragma omp parallel for
#endif
	for (idx = 0; idx < count; ++idx) {
		int i, len = strlen(saved_plain[idx]);
		unsigned char tmp[SHA512_BINARY_SIZE];
		SHA512_CTX ctx;
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, saved_plain[idx], len);
		SHA512_Update(&ctx, cur_salt->s, cur_salt->slen);
		SHA512_Final(tmp, &ctx);
		for (i = 1; i < cur_salt->iter; ++i) {
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, saved_plain[idx], len);
			SHA512_Update(&ctx, tmp, SHA512_BINARY_SIZE);
			SHA512_Final(tmp, &ctx);
		}
		memcpy(crypt_key[idx], tmp, BINARY_SIZE);
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	/*
	 * split logic into 4 separate functions, to make the logic more
	 * simplistic, when we start adding OMP + SIMD code
	 */
	switch(cur_salt->type) {
		case 1: crypt_all_1(*pcount); break;
		case 256: crypt_all_256(*pcount); break;
		case 384: crypt_all_384(*pcount); break;
		case 512: crypt_all_512(*pcount); break;
	}
	return *pcount;
}

static void *binary(char *ciphertext)
{
	static union {
		unsigned char cp[BINARY_SIZE]; /* only stores part the size of each hash */
		ARCH_WORD_32 jnk[BINARY_SIZE/4];
	} b;
	char *cp = ciphertext;
	unsigned char tmp[MAX_BINARY_SIZE+SALT_LENGTH+4];

	cp += 5; /* skip the {x-is */
	if (!strncasecmp(cp, "sha, ", 5)) { cp += 5; }
	else if (!strncasecmp(cp, "sha256, ", 8)) { cp += 8; }
	else if (!strncasecmp(cp, "sha384, ", 8)) { cp += 8; }
	else if (!strncasecmp(cp, "sha512, ", 8)) { cp += 8; }
	else { fprintf(stderr, "error, bad signature in sap-H format!\n"); exit(-1); }
	while (*cp != '}') ++cp;
	++cp;
	base64_convert(cp, e_b64_mime, strlen(cp), tmp, e_b64_raw,
	               MAX_BINARY_SIZE+SALT_LENGTH, flg_Base64_MIME_TRAIL_EQ);
	memcpy(b.cp, tmp, BINARY_SIZE);
	return b.cp;

}

static void *get_salt(char *ciphertext)
{
	static struct saltstruct s;
	char *cp = ciphertext;
	unsigned char tmp[MAX_BINARY_SIZE+SALT_LENGTH+4];
	int total_len, hash_len;

	memset(&s, 0, sizeof(s));
	cp += 5; /* skip the {x-is */
	if (!strncasecmp(cp, "sha, ", 5)) { s.type = 1; cp += 5; hash_len = SHA1_BINARY_SIZE; }
	else if (!strncasecmp(cp, "sha256, ", 8)) { s.type = 256; cp += 8; hash_len = SHA256_BINARY_SIZE; }
	else if (!strncasecmp(cp, "sha384, ", 8)) { s.type = 384; cp += 8; hash_len = SHA384_BINARY_SIZE; }
	else if (!strncasecmp(cp, "sha512, ", 8)) { s.type = 512; cp += 8; hash_len = SHA512_BINARY_SIZE; }
	else { fprintf(stderr, "error, bad signature in sap-H format!\n"); exit(-1); }
	sscanf (cp, "%u", &s.iter);
	while (*cp != '}') ++cp;
	++cp;
	total_len = base64_convert(cp, e_b64_mime, strlen(cp), tmp, e_b64_raw,
	                           MAX_BINARY_SIZE+SALT_LENGTH, flg_Base64_MIME_TRAIL_EQ);
	s.slen = total_len-hash_len;
	memcpy(s.s, &tmp[hash_len], s.slen);
	return &s;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	/* we 'could' cash switch the SHA/sha and unify case. If they an vary, we will have to. */
	return ciphertext;
}

static int get_hash_0(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xF; }
static int get_hash_1(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFF; }
static int get_hash_2(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFFF; }
static int get_hash_3(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFFFF; }
static int get_hash_4(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFFFFF; }
static int get_hash_5(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0x7FFFFFF; }

static int salt_hash(void *salt)
{
	unsigned char *cp = (unsigned char*)salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < sizeof(struct saltstruct); i++)
		hash = ((hash << 5) + hash) ^ cp[i];

	return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_sapH = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_OMP | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		binary,
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
		salt_hash,
		set_salt,
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

/* EFS cracker. Hacked together during 2013 monsoons by Dhiru Kholia
 * <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * All credits for the algorithm go to "dpapick" project,
 * https://bitbucket.org/jmichel/dpapick
 *
 * Hash Format ==> $efs$version$SID$iv$iterations$ciphertext
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_efs;
#elif FMT_REGISTERS_H
john_register_one(&fmt_efs);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "memory.h"
#include "johnswap.h"
#include "options.h"
#include "unicode.h"
#include "sha.h"
#include "gladman_hmac.h"
#include "sse-intrinsics.h"
#define EFS_CRAP_LOGIC
#include "pbkdf2_hmac_sha1.h"
#include <openssl/des.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               64
#endif
#endif
#include "memdbg.h"

#ifdef SIMD_COEF_32
#define SHA1_BLK                (SIMD_PARA_SHA1 * SIMD_COEF_32)
#endif

#define FORMAT_LABEL            "EFS"
#define FORMAT_TAG              "$efs$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define FORMAT_NAME             ""
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "PBKDF2-SHA1-efs-variant 3DES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1-efs-variant 3DES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define MAX_CT_LEN              4096
#define MAX_IV_LEN              16
#define MAX_SID_LEN             1024
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SHA1_BLK
#define MAX_KEYS_PER_CRYPT      SHA1_BLK
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static struct fmt_tests efs_tests[] = {
	/* Windows XP, openwall.efs */
	{"$efs$0$S-1-5-21-1482476501-1659004503-725345543-1003$b3d62a0b06cecc236fe3200460426a13$4000$d3841257348221cd92caf4427a59d785ed1474cab3d0101fc8d37137dbb598ff1fd2455826128b2594b846934c073528f8648d750d3c8e6621e6f706d79b18c22f172c0930d9a934de73ea2eb63b7b44810d332f7d03f14d1c153de16070a5cab9324da87405c1c0", "openwall"},
	/* Windows XP, openwall.efs.2 */
	{"$efs$0$S-1-5-21-1482476501-1659004503-725345543-1005$c9cbd491f78ea6d512276b33f025bce8$4000$091a13443cfc2ddb16dcf256ab2a6707a27aa22b49a9a9011ebf3bb778d0088c2896de31de67241d91df75306e56f835337c89cfb2f9afa940b4e7e019ead2737145032fac0bb34587a707d42da7e00b72601a730f5c848094d54c47c622e2f8c8d204c80ad061be", "JtRisthebest"},
	{NULL}
};

#ifndef min
#define min( a, b ) ( ((a) < (b)) ? (a) : (b) )
#endif


#if defined (_OPENMP)
static int omp_t = 1;
#endif
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned char iv[MAX_IV_LEN];
	int ivlen;
	int iterations;
	int ctlen;
	int version;  // for future expansion
	unsigned char ct[MAX_CT_LEN];
	UTF16 SID[MAX_SID_LEN+1];
} *cur_salt;

static void init(struct fmt_main *self)
{

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	cracked   = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)  /* version number */
		goto err;
	if(!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* SID */
		goto err;
	if (strlen(p) > MAX_SID_LEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iv */
		goto err;
	if (strlen(p) > MAX_IV_LEN * 2 || (strlen(p)&1)) /* iv length */
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iterations */
		goto err;
	if(!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* data */
		goto err;
	if (strlen(p) > MAX_CT_LEN * 2 || (strlen(p)&1))
		goto err;
	if (!ishex(p))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	int length;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += TAG_LENGTH;  // skip over "$efs$"
	p = strtokm(ctcopy, "$");
	cs.version = atoi(p);
	p = strtokm(NULL, "$");

	// Convert SID to Unicode
	enc_to_utf16(cs.SID, MAX_SID_LEN, (UTF8*)p, strlen(p));

	p = strtokm(NULL, "$");
	length = strlen(p) / 2;
	cs.ivlen = length;

	for (i = 0; i < cs.ivlen; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);

	p = strtokm(NULL, "$");
	length = strlen(p) / 2;
	cs.ctlen = length;

	for (i = 0; i < cs.ctlen; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int kcdecrypt(unsigned char *key, unsigned char *iv, unsigned char *pwdhash, unsigned char *data)
{
	unsigned char out[MAX_CT_LEN+16];
	unsigned char *hmacSalt;
	unsigned char *ourKey;
	unsigned char *hmac;
	unsigned char hmacComputed[20];
	unsigned char encKey[20];
	DES_cblock key1, key2, key3;
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;

	memset(out, 0, sizeof(out));
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);
	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);
	memcpy(ivec, iv, 8);
	DES_ede3_cbc_encrypt(data, out, cur_salt->ctlen, &ks1, &ks2, &ks3, &ivec,  DES_DECRYPT);

	// self.key = cleartxt[-64:]
	// self.hmacSalt = cleartxt[:16]
	// self.hmac = cleartxt[16:16+self.hashAlgo.digestLength]
	// self.hmacComputed = crypto.DPAPIHmac(self.hashAlgo, pwdhash,
	//      self.hmacSalt, self.key)
	// self.decrypted = self.hmac == self.hmacComputed

	ourKey = out + cur_salt->ctlen - 64;
	hmacSalt = out; // 16 bytes
	hmac = out + 16;

	// encKey = hmac.new(pwdhash, hmacSalt, dg).digest()
	hmac_sha1(pwdhash, 32, hmacSalt, 16, encKey, 20);

	// return hmac.new(encKey, value, dg).digest()
	// dump_stuff(key, 64);
	hmac_sha1(encKey, 20, ourKey, 64, hmacComputed, 20);

	// dump_stuff(hmac, 20);
	return memcmp(hmac, hmacComputed, 20);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
	{
#ifdef SIMD_COEF_32
		int lens[MAX_KEYS_PER_CRYPT];
		unsigned char *pin[MAX_KEYS_PER_CRYPT];
		union {
			ARCH_WORD_32 *pout[MAX_KEYS_PER_CRYPT];
			unsigned char *poutc;
		} x;
#endif

		// def derivePassword(userPwd, userSID, hashAlgo)
		// Computes the encryption key from a user's password
		// return derivePwdHash(hashlib.sha1(userPwd.encode("UTF-16LE")).digest()
		unsigned char *passwordBuf;
		int passwordBufSize;
		unsigned char out[MAX_KEYS_PER_CRYPT][32];
		unsigned char out2[MAX_KEYS_PER_CRYPT][32];
		SHA_CTX ctx;
		int i;

		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			passwordBuf = (unsigned char*)saved_key[index+i];
			passwordBufSize = strlen16((UTF16*)passwordBuf) * 2;
			/* hash the UTF-16LE encoded key */
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, passwordBuf, passwordBufSize);
			SHA1_Final(out[i], &ctx);
			// 2. use UTF-16LE encoded SID in HMAC
			passwordBuf = (unsigned char*)cur_salt->SID;
			passwordBufSize = (strlen16(cur_salt->SID) + 1) * 2;
			hmac_sha1(out[i], 20, passwordBuf, passwordBufSize, out2[i], 20);
#ifdef SIMD_COEF_32
			lens[i] = 20;
			pin[i] = (unsigned char*)out2[i];
			x.pout[i] = (ARCH_WORD_32*)(out[i]);
#endif
		}
#ifdef SIMD_COEF_32
		pbkdf2_sha1_sse((const unsigned char **)pin, lens, cur_salt->iv, 16, cur_salt->iterations, &(x.poutc), 32, 0);
#else
		pbkdf2_sha1(out2[0], 20, cur_salt->iv, 16, cur_salt->iterations, out[0], 32, 0);
#endif

#if ARCH_LITTLE_ENDIAN==0
		{
			uint32_t *p32 = (uint32_t *)out;
			for (i = 0; i < 8; ++i) {
				*p32 = JOHNSWAP(*p32);
				++p32;
			}
		}
#endif

		// kcdecrypt will use 32 bytes, we only initialized 20 so far
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			unsigned char iv[8];
			memset(out2[i] + 20, 0, 32 - 20);

			// split derived key into "key" and IV
			memcpy(iv, out[i] + 24, 8);

			if (kcdecrypt(out[i], iv, out2[i], cur_salt->ct) == 0)
				cracked[index+i] = 1;
			else
				cracked[index+i] = 0;
		}
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
    return 1;
}

static void efs_set_key(char *key, int index)
{
	/* Convert key to UTF-16LE (--encoding aware) */
	enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->iterations;
}
#endif

struct fmt_main fmt_efs = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		efs_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		efs_set_key,
		get_key,
		fmt_default_clear_keys,
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

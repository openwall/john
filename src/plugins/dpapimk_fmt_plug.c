/* DPAPI masterkey file version 1 and 2 cracker by
 * Fist0urs <jean-christophe.delaunay at synacktiv.com>
 *
 * This software is Copyright (c) 2017
 * Fist0urs <jean-christophe.delaunay at synacktiv.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * All credits for the algorithm go to "dpapick" project,
 * https://bitbucket.org/jmichel/dpapick
 * and Dhiru Kholia <dhiru.kholia at gmail.com> for his
 * work on the DPAPI masterkey file version 1 implementation.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_DPAPImk;
#elif FMT_REGISTERS_H
john_register_one(&fmt_DPAPImk);
#else

#include <string.h>
#include <openssl/des.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include <assert.h>

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "aes.h"
#include "sha.h"
#include "md4.h"
#include "hmac_sha.h"

#define DPAPI_CRAP_LOGIC

#include "pbkdf2_hmac_sha512.h"
#include "pbkdf2_hmac_sha1.h"
#include "pbkdf2_hmac_sha256.h"

#define FORMAT_LABEL            "DPAPImk"
#define FORMAT_TAG              "$DPAPImk$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG) - 1)
#define FORMAT_NAME             "DPAPI masterkey file v1 and v2"

#if defined(SIMD_COEF_64) && defined(SIMD_COEF_32)
#define ALGORITHM_NAME          "SHA1/MD4 PBKDF2-(SHA1/SHA512)-DPAPI-variant 3DES/AES256 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "SHA1/MD4 PBKDF2-(SHA1/SHA512)-DPAPI-variant 3DES/AES256 32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define MAX_CT_LEN              4096
#define MAX_SID_LEN             1024
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)

#define MAX_IV_LEN              16

#define KEY_LEN2                32
#define IV_LEN2                 16
#define DIGEST_LEN2             64

#define KEY_LEN1                24
#define IV_LEN1                 8
#define DIGEST_LEN1             20

#if defined(SIMD_COEF_64) && defined(SIMD_COEF_32)
#define MIN_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA1 * SSE_GROUP_SZ_SHA512)
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA1 * SSE_GROUP_SZ_SHA512)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               1 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests dpapimk_tests[] = {
	/* new samples, including other Windows versions and both local and domain credentials */
	{"$DPAPImk$1*1*S-15-21-447321867-460417387-480872410-1240*des3*sha1*24000*9b49e2d3b25103d03e936fdf66b94d26*208*ec96025ed4b023ebfa52bdfd91dfeb64edf3f3970b347ee8bb8adfb2a686a0a34792d40074edd372f346da8fcd02cc5d4182c2fd09f4549ec106273926edd05c42e4b5fc8b8758a7c48f6ddae273f357bcb645c8ad16e3161e8a9dbb5002454f4db5ef0d5d7a93ac", "bouledepetanque"},
	{"$DPAPImk$1*2*S-15-21-458698633-447735394-485599537-1788*des3*sha1*24000*96b957d9bf0f8846399e70a84431b595*208*0ee9fa2baf2cf0efda81514376aef853c6c93a5776fa6af66a869f44c50ac80148b7488f52b4c52c305e89a497a583e17cca4a9bab580668a8a5ce2eee083382c98049e481e47629b5815fb16247e3bbfa62c454585aaaf51ef15555a355fcf925cff16c0bb006f8", "jordifirstcredit"},
	{"$DPAPImk$2*1*S-15-21-417226446-481759312-475941522-1494*aes256*sha512*8000*1e6b7a71a079bc12e71c75a6bcfd865c*288*5b5d651e538e5185f7d6939ba235ca2d8a2b9726a6e95b59844320ba1d1f22282527210bc784d22075e596d113927761a644ad4057cb4dbb497bd64ee6c630930a4ba388eadb59484ec2be7fb4cc79299a87f341d002d25b5b187c71fa19417ec9d1b65568a79c962cb3b5bcb1b8df5f968669af35eec5a24ed5dcee46deef42bfee5ad665dd4de56ccd9c6ba26b2acd", "PaulSmiteSuper160"},
	{"$DPAPImk$2*2*S-15-21-402916398-457068774-444912990-1699*aes256*sha512*17000*4c51109a901e4be7f1e208f82a56e690*288*bb80d538ac4185eb0382080fda0d405bb74da3a6b98e96f222292b819fa9168cf1571e9bc9c698ad10daf850ab34de1a1765cfd5c0fb8a63a413a767d241dfe6355804af259d24f6be7282daac0a9e02d7fbe20675afb3733141995990a6d11012edfb7e81b49c0e1132dbc4503dd2206489e4f512e4fe9d573566c9d8973188b8d1a87610b8bef09e971270a376a52b", "Juan-Carlos"},
	{"$DPAPImk$1*3*S-1-5-21-1857904334-2267218879-1458651445-1123*des3*sha1*18000*e4c529ba8975e4ed56f5fb8b1e85be43*208*af96b391f1d6e2d37a4de3b4c412ce78f032d446d77ea1fb6a0782f47c390c844349c2bcaeba9fd570b39def6f67a369aa2e266e8d017689d8a09667fdfb640feb3e19ca22067cc5704644c1dcc43d4cccac667391f4918d0de77f36569fd2e104ef0619a46edcfc", "LaKuckaracha42"},
	/* old samples, with less iterations, preserved for backward compatibiliy */
	{"$DPAPImk$1*1*S-1-5-21-1482476501-1659004503-725345543-1003*des3*sha1*4000*b3d62a0b06cecc236fe3200460426a13*208*d3841257348221cd92caf4427a59d785ed1474cab3d0101fc8d37137dbb598ff1fd2455826128b2594b846934c073528f8648d750d3c8e6621e6f706d79b18c22f172c0930d9a934de73ea2eb63b7b44810d332f7d03f14d1c153de16070a5cab9324da87405c1c0", "openwall"},
	{"$DPAPImk$1*1*S-1-5-21-1482476501-1659004503-725345543-1005*des3*sha1*4000*c9cbd491f78ea6d512276b33f025bce8*208*091a13443cfc2ddb16dcf256ab2a6707a27aa22b49a9a9011ebf3bb778d0088c2896de31de67241d91df75306e56f835337c89cfb2f9afa940b4e7e019ead2737145032fac0bb34587a707d42da7e00b72601a730f5c848094d54c47c622e2f8c8d204c80ad061be", "JtRisthebest"},
	{NULL}
};

static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	uint32_t version;
	uint32_t cred_type;
	UTF16 SID[MAX_SID_LEN + 1];
	//unsigned char cipher_algo[20]; /* here only for possible other algorithms */
	//unsigned char hash_algo[20];   /* same */
	uint32_t pbkdf2_iterations;
	unsigned char iv[16];
	uint32_t encrypted_len;
	unsigned char encrypted[512];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

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
	char *p;
	char *ctcopy;
	char *keeptr;
	int length1, length2, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;                /* skip over "$DPAPImk$" */
	if ((p = strtokm(ctcopy, "*")) == NULL)  /* version */
		goto err;
	if (!isdec(p))
		goto err;
	if (!atoi(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)    /* credential type */
		goto err;
	if (!isdec(p))
		goto err;
	if (!atoi(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)    /* SID */
		goto err;
	{
		UTF16 SID[MAX_SID_LEN + 1]; /* assumes MAX_SID_LEN is 2x+ larger than PLAINTEXT_LENGTH */
		if (enc_to_utf16(SID, PLAINTEXT_LENGTH, (UTF8 *) p, strlen(p)) < 0)
			goto err;
	}
	if ((p = strtokm(NULL, "*")) == NULL)    /* cipher algorithm */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)    /* hash algorithm */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)    /* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if (!atoi(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)    /* IV */
		goto err;
	if (strlen(p) != 32 || !ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)    /* encrypted length */
		goto err;
	if (!isdec(p))
		goto err;
	length1 = atoi(p);
	if ((p = strtokm(NULL, "*")) == NULL)    /* encrypted part */
		goto err;
	length2 = hexlenl(p, &extra);
	if (length2 < 64 * 2 || length2 > 512 * 2 || (length1 != length2) || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;
err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;     /* skip over "$DPAPImk$" */
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);         /* version */

	p = strtokm(NULL, "*");
	cs.cred_type = atoi(p);       /* credential type */

	p = strtokm(NULL, "*");       /* SID */
	assert(enc_to_utf16(cs.SID, PLAINTEXT_LENGTH, (UTF8 *) p, strlen(p)) >= 0); /* already checked in valid() */

	p = strtokm(NULL, "*"); /* cipher algorithm */

	p = strtokm(NULL, "*"); /* hash algorithm */

	p = strtokm(NULL, "*"); /* pbkdf2 iterations */
	cs.pbkdf2_iterations = (uint32_t) atoi(p);

	p = strtokm(NULL, "*"); /* iv */
	for (i = 0; i < 16; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "*"); /* encrypted length */
	cs.encrypted_len = (uint32_t) atoi(p) / 2;

	p = strtokm(NULL, "*"); /* encrypted stuff */
	for (i = 0; i < cs.encrypted_len; i++)
		cs.encrypted[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int decrypt_v1(unsigned char *key, unsigned char *iv, unsigned char *pwdhash, unsigned char *data)
{
	unsigned char out[MAX_CT_LEN+16];
	unsigned char *last_key;
	unsigned char *hmacSalt;
	unsigned char *expected_hmac;
	unsigned char computed_hmac[DIGEST_LEN1];
	unsigned char encKey[DIGEST_LEN1];
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;

	memset(out, 0, sizeof(out));
	DES_set_key_unchecked((DES_cblock *) key, &ks1);
	DES_set_key_unchecked((DES_cblock *) (key + 8), &ks2);
	DES_set_key_unchecked((DES_cblock *) (key + 16), &ks3);
	memcpy(ivec, iv, 8);
	DES_ede3_cbc_encrypt(data, out, cur_salt->encrypted_len, &ks1, &ks2, &ks3, &ivec,  DES_DECRYPT);

	hmacSalt = out;
	expected_hmac = out + 16;
	last_key = out + cur_salt->encrypted_len - 64;

	hmac_sha1(pwdhash, 32, hmacSalt, 16, encKey, DIGEST_LEN1);
	hmac_sha1(encKey, DIGEST_LEN1, last_key, 64, computed_hmac, DIGEST_LEN1);

	return memcmp(expected_hmac, computed_hmac, DIGEST_LEN1);
}

static int decrypt_v2(unsigned char *key, unsigned char *iv, unsigned char *pwdhash, unsigned char *data)
{
	unsigned char out[MAX_CT_LEN+16];
	unsigned char *last_key;
	unsigned char *hmacSalt;
	unsigned char *expected_hmac;
	unsigned char hmacComputed[DIGEST_LEN2];
	unsigned char encKey[DIGEST_LEN2];

	AES_KEY aeskey;

	AES_set_decrypt_key(key, KEY_LEN2 * 8, &aeskey);
	AES_cbc_encrypt(data, out, cur_salt->encrypted_len, &aeskey, iv, AES_DECRYPT);

	hmacSalt = out;
	expected_hmac = out + 16;
	last_key = out + cur_salt->encrypted_len - 64;

	hmac_sha512(pwdhash, 20, hmacSalt, IV_LEN2, encKey, DIGEST_LEN2);
	hmac_sha512(encKey, DIGEST_LEN2, last_key, 64, hmacComputed, DIGEST_LEN2);

	return memcmp(expected_hmac, hmacComputed, DIGEST_LEN2);
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char *passwordBuf;
		int passwordBufSize;
		unsigned char *sidBuf;
		int sidBufSize;
		unsigned char out[MIN_KEYS_PER_CRYPT][KEY_LEN2 + IV_LEN2];
		unsigned char out2[MIN_KEYS_PER_CRYPT][KEY_LEN2 + IV_LEN2];
		SHA_CTX ctx;
		MD4_CTX ctx2;
		int i;

		int digestlens[MIN_KEYS_PER_CRYPT];

#if defined(SIMD_COEF_64) && defined(SIMD_COEF_32)
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT];
		union {
			unsigned char *pout[MIN_KEYS_PER_CRYPT];
			unsigned char *poutc;
		} x;
		int sha256loops = MIN_KEYS_PER_CRYPT / SSE_GROUP_SZ_SHA256, loops = MIN_KEYS_PER_CRYPT;

		if (cur_salt->version == 1)
			loops = MIN_KEYS_PER_CRYPT / SSE_GROUP_SZ_SHA1;
		else if (cur_salt->version == 2)
			loops = MIN_KEYS_PER_CRYPT / SSE_GROUP_SZ_SHA512;
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			digestlens[i] = 16;
			passwordBuf = (unsigned char*)saved_key[index+i];
			passwordBufSize = strlen16((UTF16*)passwordBuf) * 2;

			/* local credentials */
			if (cur_salt->cred_type == 1) {
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, passwordBuf, passwordBufSize);
				SHA1_Final(out[i], &ctx);
				digestlens[i] = 20;
			}
			/* domain credentials */
			else if (cur_salt->cred_type == 2 || cur_salt->cred_type == 3) {
				MD4_Init(&ctx2);
				MD4_Update(&ctx2, passwordBuf, passwordBufSize);
				MD4_Final(out[i], &ctx2);
				digestlens[i] = 16;
			}
		}

		/* 1607+ domain credentials */
		/* The key derivation algorithm is hardcoded in NtlmShared.dll!MsvpDeriveSecureCredKey */
		if(cur_salt->cred_type == 3) {
			sidBuf = (unsigned char*)cur_salt->SID;
			sidBufSize = (strlen16(cur_salt->SID) * 2);
#if defined(SIMD_COEF_64) && defined(SIMD_COEF_32)
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				lens[i] = 16;
				pin[i] = (unsigned char*)out[i];
				x.pout[i] = out2[i];
			}

			for (i = 0; i < sha256loops; i++) {
				pbkdf2_sha256_sse((const unsigned char**)(pin + i * SSE_GROUP_SZ_SHA256), &lens[i * SSE_GROUP_SZ_SHA256], sidBuf, sidBufSize, 10000, x.pout + (i * SSE_GROUP_SZ_SHA256), 32, 0);
			}

			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				lens[i] = 32;
				pin[i] = (unsigned char*)out2[i];
				x.pout[i] = out[i];
			}

			for (i = 0; i < sha256loops; i++) {
				pbkdf2_sha256_sse((const unsigned char**)(pin + i * SSE_GROUP_SZ_SHA256), &lens[i * SSE_GROUP_SZ_SHA256], sidBuf, sidBufSize, 1, x.pout + (i * SSE_GROUP_SZ_SHA256), 16, 0);
			}
#else
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				pbkdf2_sha256(out[i], 16, sidBuf, sidBufSize, 10000, out2[i], 32, 0);
				pbkdf2_sha256(out2[i], 32, sidBuf, sidBufSize, 1, out[i], 16, 0);
			}
#endif
		}


		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			passwordBuf = (unsigned char*)cur_salt->SID;
			passwordBufSize = (strlen16(cur_salt->SID) + 1) * 2;
			hmac_sha1(out[i], digestlens[i], passwordBuf, passwordBufSize, out2[i], 20);
#if defined(SIMD_COEF_64) && defined(SIMD_COEF_32)
			lens[i] = 20;
			pin[i] = (unsigned char*)out2[i];
			x.pout[i] = out[i];
#endif
		}

#if defined(SIMD_COEF_64) && defined(SIMD_COEF_32)
		if (cur_salt->version == 1)
			for (i = 0; i < loops; i++)
				pbkdf2_sha1_sse((const unsigned char**)(pin + i * SSE_GROUP_SZ_SHA1), &lens[i * SSE_GROUP_SZ_SHA1], cur_salt->iv, MAX_IV_LEN, cur_salt->pbkdf2_iterations, x.pout + (i * SSE_GROUP_SZ_SHA1), KEY_LEN1 + IV_LEN1, 0);
		else if (cur_salt->version == 2)
			for (i = 0; i < loops; i++)
				pbkdf2_sha512_sse((const unsigned char**)(pin + i * SSE_GROUP_SZ_SHA512), &lens[i * SSE_GROUP_SZ_SHA512], cur_salt->iv, MAX_IV_LEN, cur_salt->pbkdf2_iterations, x.pout + (i * SSE_GROUP_SZ_SHA512), KEY_LEN2 + IV_LEN2, 0);
#else
		if (cur_salt->version == 1)
			pbkdf2_sha1(out2[0], 20, cur_salt->iv, MAX_IV_LEN, cur_salt->pbkdf2_iterations, out[0], KEY_LEN1 + IV_LEN1, 0);
		else if (cur_salt->version == 2)
			pbkdf2_sha512(out2[0], 20, cur_salt->iv, MAX_IV_LEN, cur_salt->pbkdf2_iterations, out[0], KEY_LEN2 + IV_LEN2, 0);
#endif
		if (cur_salt->version == 1) {
			/* decrypt will use 32 bytes, we only initialized 20 so far */
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				memset(out2[i] + 20, 0, 32 - 20);

				if (decrypt_v1(out[i], out[i] + KEY_LEN1, out2[i], cur_salt->encrypted) == 0)
					cracked[index+i] = 1;
				else
					cracked[index+i] = 0;
			}
		}
		else if (cur_salt->version == 2) {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				if (decrypt_v2(out[i], out[i] + KEY_LEN2, out2[i], cur_salt->encrypted) == 0)
					cracked[index+i] = 1;
				else
					cracked[index+i] = 0;
			}
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

static void dpapimk_set_key(char *key, int index)
{
	/* Convert key to UTF-16LE (--encoding aware) */
	enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->pbkdf2_iterations;
}

struct fmt_main fmt_DPAPImk = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_ENC | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		dpapimk_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		dpapimk_set_key,
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
#endif /* HAVE_LIBCRYPTO */

/* PEM (PKCS #8) cracker.
 *
 * This software is Copyright (c) 2015, Dhiru Kholia <kholia at kth.se>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * This code may be freely used and modified for any purpose.
 *
 * Big thanks to Martin Kleppmann, and Lapo Luchini for making this format
 * possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pem;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pem);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#include <openssl/des.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               64
#endif
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "pbkdf2_hmac_sha1.h"
#include "jumbo.h"
#include "memdbg.h"
#include "asn1.h"

#define FORMAT_LABEL            "PEM"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$PEM$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 3DES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 3DES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*fctx)
#define BINARY_ALIGN            1
#define SALT_ALIGN              1
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#define SALTLEN                 8     // XXX
#define IVLEN                   8     // XXX
#define CTLEN                   1024  // XXX

// $PEM$type$cipher$$salt$iterations$iv$blob_length$blob  // type, and cipher should be enough for all possible combinations
static struct fmt_tests PEM_tests[] = {
	/* https://github.com/bwall/pemcracker/blob/master/test.pem */
	{FORMAT_TAG "1$1$0c71e1c801194282$2048$87120f8c098437d0$640$c4bc6bc5447bed58e6f945cd1fde56d52aa794bd64b3c509fead910b1e7c1be9b6a89666c572c8ba5e469c5732ff105ecb97875efc2490ea9659082bdf0f3a2fd263ceb86bde4807bb85b01ca25efe25655fcdb9d54db94f7f48bb9b04af2bad5c2aaed87dc289da8b3fb891a9797f73adacb05b21717fe11d4ebdf8f1d39ecfcb8791447263572f487b087484c02e40a13a89c0613ebc4958a0853781eb1382c1f9ac1f1f97dd06e1a26d98088c5f262680a33dbf2e7742a436847cead5af15c538a5eb21b99e0c4ca30d08f5e805678bdbae6a3ee53623b7cebaeac6c7dd54834f6806112909d2d74da35ea907d35cfbd9cfcca4c302e9dc19b3017957747b4525e7832067d462f15451ca47be771add080da835dc177c26df3dd3fbf4b44d0ac7aea30a44469fe542abaf9bb2787b5694c7fdc1b9765167bf9ea5bf695e927bb98217491d7f1843a1e39e2a1a6a178b03e391031a80943f08b6dd7fa5104e38c4a4bad773775a71f5d076641a52a1100e701c14e5a15ac3dbaefad5f2ceb3ccded6689aef2bc9060c36599580f34324ecfa8cf2628da6475934bb53a8f7ef4a07fc1d0a4d41bfc9bac91859ce98f3f8876bbfba01bbe4491fa2d511b2f6eb5ae7ad4213a24c21fef676c8713de9c674d7a88d8844765732dbab43ee9faa5245ddb6fd6d66ab301b82dca829aeacaa5f178cd12aa0565c8a2d6c00b8c7f611ceedeee8ea68d99582fe9ba701c46d1ea78c88bb942ee3e30e83d9843cbda720bd2dcc07f2b4497e781cd54156e5e1022c4fb5827ab4e0469bb40500a6978eed0f27e0258e7304b0745e90eb36bb8d8e1c15c458313c547c3bfe54d75ac26405c40cfa0fecbf2a95e312870c08b13e6b36494c09c8a8ef12057e090a24e05fd3", "komodia"},
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;

static struct format_context {
	int salt_length;
	unsigned char salt[SALTLEN];
	int iv_length;
	unsigned char iv[IVLEN];
	int iterations;
	int ciphertext_length;
	unsigned char ciphertext[CTLEN];
} *fctx;

static void init(struct fmt_main *self)
{

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(sizeof(*saved_key),  self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}
static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, value;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // type
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // cipher
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if(hexlenl(p) != 16)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iterations
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iv
		goto err;
	if(hexlenl(p) != 16)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // ciphertext length
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
	if(hexlenl(p) != len)
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

	fctx = mem_alloc_tiny(sizeof(struct format_context), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // type
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");   // salt

	for (i = 0; i < SALTLEN; i++)
		fctx->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	fctx->iterations = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < IVLEN; i++)
		fctx->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	fctx->ciphertext_length = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < fctx->ciphertext_length; i++)
		fctx->ciphertext[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)fctx;
}


static void set_salt(void *salt)
{
	fctx = (struct format_context *)salt;
}

static void PEM_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

/* The decrypted data should have a structure which is similar to,
 *
 * SEQUENCE(3 elem)
 *    INTEGER0
 *    SEQUENCE(2 elem)
 *      OBJECT IDENTIFIER1.2.840.113549.1.1.1
 *      NULL
 *    OCTET STRING(1 elem)
 *      SEQUENCE(9 elem)
 *      INTEGER0
 *      INTEGER(1024 bit) 163583298361518096026606050608205849417059808304583036000248988384009…
 *      INTEGER65537
 *      INTEGER(1024 bit) 117735944587247616941254265546766890629007951201899342739151083099399…
 *      INTEGER(512 bit) 1326824977515584662273167545044211564211924552512566340747744113458170…
 *      INTEGER(512 bit) 1232892816562888937701591901363879998543675433056414341240275826895052…
 *      INTEGER(512 bit) 1232481257247299197174170630936058522583110776863565636597653514732029…
 *      INTEGER(511 bit) 6306589984658176106246573218383922527912198486012975018041565347945398…
 *      INTEGER(512 bit) 1228874097888952320
 */
static int pem_decrypt(unsigned char *key, unsigned char *iv, unsigned char *data)
{
	unsigned char out[CTLEN];
	DES_cblock key1, key2, key3;
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;
	int length = fctx->ciphertext_length;

	memset(out, 0, sizeof(out));
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);
	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);
	memcpy(ivec, iv, 8);
	DES_ede3_cbc_encrypt(data, out, fctx->ciphertext_length, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

	/* possible bug here, is this assumption (pad of 4) always valid? */
	if (out[fctx->ciphertext_length - 1] != 4 || check_pkcs_pad(out, fctx->ciphertext_length, 8) < 0)
		return -1;

	/* check message structure, http://lapo.it/asn1js/ is the best tool for learning this stuff */

	// SEQUENCE
	if (asn1_get_next(out, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_SEQUENCE) {
		goto bad;
	}
	pos = hdr.payload;
	end = pos + hdr.length;


	// version Version (Version ::= INTEGER)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		goto bad;
	}
	if (*(pos + 2) != 0) // *(pos + 1) == header length
		goto bad;
	if (hdr.length != 1)
		goto bad;
	pos = hdr.payload + hdr.length;

	// SEQUENCE
	if (asn1_get_next(out, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_SEQUENCE) {
		goto bad;
	}
	pos = hdr.payload + hdr.length;

	// OCTET STRING (jumped over OBJECT IDENTIFIER and NULL)
	if (asn1_get_next(pos, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_OCTETSTRING) {
		goto bad;
	}
	pos = hdr.payload + hdr.length;

	// XXX add more structure checks!

	return 0;
bad:
	return -1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		unsigned char master[MAX_KEYS_PER_CRYPT][32];
		int i;
#ifdef SIMD_COEF_32
		int lens[MAX_KEYS_PER_CRYPT];
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char**)pin, lens, fctx->salt, SALTLEN, fctx->iterations, pout, 24, 0);
#else
		pbkdf2_sha1((unsigned char *)saved_key[index],  strlen(saved_key[index]), fctx->salt, SALTLEN, fctx->iterations, master[0], 24, 0);
#if !ARCH_LITTLE_ENDIAN
		{
			int i;
			for (i = 0; i < 24/sizeof(ARCH_WORD_32); ++i) {
				((ARCH_WORD_32*)master[0])[i] = JOHNSWAP(((ARCH_WORD_32*)master[0])[i]);
			}
		}
#endif
#endif
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			if(pem_decrypt(master[i], fctx->iv, fctx->ciphertext) == 0)
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

static unsigned int iteration_count(void *salt)
{
	struct format_context *my_fctx;

	my_fctx = salt;
	return (unsigned int) my_fctx->iterations;
}

struct fmt_main fmt_pem = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{
			"iteration count",
		},
		PEM_tests
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
		PEM_set_key,
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

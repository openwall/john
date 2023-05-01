/*
 * Cracker for Mozilla's key3.db's master password.
 *
 * All the real logic here is borrowed from Milen Rangelov's Hashkill project
 * and from Deque's article.
 *
 * Thanks to Jim Fougeron for all the help!
 *
 * This software is Copyright (c) 2014, Sanju Kholia <sanju.kholia [at]
 * gmail.com> and Dhiru Kholia <dhiru [at] openwall.com>, and it is hereby
 * released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_mozilla;
#elif FMT_REGISTERS_H
john_register_one(&fmt_mozilla);
#else

#include <string.h>
#include <stdint.h>
#include <openssl/des.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"
#include "sha.h"

#define FORMAT_LABEL            "Mozilla"
#define FORMAT_NAME             "Mozilla key3.db"
#define FORMAT_TAG              "$mozilla$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "SHA1 3DES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      128

#ifndef OMP_SCALE
#define OMP_SCALE 2 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	{"$mozilla$*3*20*1*5199adfab24e85e3f308bacf692115f23dcd4f8f*11*2a864886f70d010c050103*16*9debdebd4596b278de029b2b2285ce2e*20*2c4d938ccb3f7f1551262185ccee947deae3b8ae", "12345678"},
	{"$mozilla$*3*20*1*4f184f0d3c91cf52ee9190e65389b4d4c8fc66f2*11*2a864886f70d010c050103*16*590d1771368107d6be64844780707787*20*b8458c712ffcc2ff938409804cf3805e4bb7d722", "openwall"},
	{"$mozilla$*3*20*1*897f35ff10348f0d3a7739dbf0abddc62e2e64c3*11*2a864886f70d010c050103*16*1851b917997b3119f82b8841a764db62*20*197958dd5e114281f59f9026ad8b7cfe3de7196a", "password"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static  struct custom_salt {
	SHA_CTX pctx;
	int global_salt_length;
	unsigned char global_salt[20];
	int local_salt_length;  // entry-salt (ES)
	unsigned char local_salt[20];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *keepptr;
	int res;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;
	keepptr=xstrdup(ciphertext);
	p = &keepptr[TAG_LENGTH];
	if (*p != '*')
		goto err;
	++p;
	if ((p = strtokm(p, "*")) == NULL) /* version */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res != 3)  /* we only know about this particular version */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) /* local_salt_length */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 20)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) /* nnLen (we ignore nnlen) */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) /* local_salt */
		goto err;
	if (strlen(p) /2 != res)
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) /* oidDatalen */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 20)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) /* oidData */
		goto err;
	if (strlen(p) / 2 != res)
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) /* password_check_length */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 20)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) /* password_check */
		goto err;
	if (strlen(p) / 2 != res)
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) /* global_salt_length */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 20)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) /* global_salt */
		goto err;
	if (strlen(p) / 2 != res)
		goto err;
	if (!ishexlc(p))
		goto err;

	MEM_FREE(keepptr);
	return 1;

err:
	MEM_FREE(keepptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	int i;
	static struct custom_salt cs;
	char *p, *q;

	memset(&cs, 0, SALT_SIZE);  // cs.local_salt needs to be zero padded to length 20
	p = ciphertext + TAG_LENGTH;

	q = strchr(p, '*'); // version
	p = q + 1;

	q = strchr(p, '*'); // local_salt_length
	p = q + 1;
	cs.local_salt_length = atoi(p);

	q = strchr(p, '*'); // nnLen
	p = q + 1;

	q = strchr(p, '*'); // local_salt
	p = q + 1;
	for (i = 0; i < cs.local_salt_length; i++)
		cs.local_salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) |
			atoi16[ARCH_INDEX(p[2 * i + 1])];

	q = strchr(p, '*'); // oidLen (unused)
	p = q + 1;
	q = strchr(p, '*'); // oidData (unused)
	p = q + 1;

	q = strchr(p, '*'); // password_check_length
	p = q + 1;
	// Not stored in salt. This is the binary length

	q = strchr(p, '*'); // password_check
	p = q + 1;
	// Not stored in salt, this is the binary.

	q = strchr(p, '*'); // global_salt_length
	p = q + 1;
	cs.global_salt_length = atoi(p);

	q = strchr(p, '*'); // global_salt
	p = q + 1;
	for (i = 0; i < cs.global_salt_length; i++)
		cs.global_salt[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	// Calculate partial sha1 data for password hashing
	SHA1_Init(&cs.pctx);
	SHA1_Update(&cs.pctx, cs.global_salt, cs.global_salt_length);

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p, *q;
	int i;
	p = ciphertext + TAG_LENGTH;

	q = strchr(p, '*'); // version
	p = q + 1;
	q = strchr(p, '*'); // local_salt_length
	p = q + 1;
	q = strchr(p, '*'); // nnLen
	p = q + 1;
	q = strchr(p, '*'); // local_salt
	p = q + 1;
	q = strchr(p, '*'); // oidLen (unused)
	p = q + 1;
	q = strchr(p, '*'); // oidData (unused)
	p = q + 1;
	q = strchr(p, '*'); // password_check_length
	p = q + 1;
	q = strchr(p, '*'); // password_check
	p = q + 1;

	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

// http://www.drh-consultancy.demon.co.uk/key3.html
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		SHA_CTX ctx, ctxi, ctxo;
		int i;
		union {
			unsigned char uc[64];
			uint32_t ui[64/4];
		} pad;
		unsigned char buffer[20];
		unsigned char tk[20];
		unsigned char key[40];
		DES_cblock ivec;
		DES_key_schedule ks1, ks2, ks3;

		// HP = SHA1(global-salt||password)
		// Copy already calculated partial hash data
		memcpy(&ctx, &cur_salt->pctx, sizeof(SHA_CTX));
		SHA1_Update(&ctx, saved_key[index], saved_len[index]);
		SHA1_Final(buffer, &ctx);

		// CHP = SHA1(HP||entry-salt) // entry-salt (ES) is local_salt
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, buffer, 20);
		SHA1_Update(&ctx, cur_salt->local_salt, cur_salt->local_salt_length);
		SHA1_Final(buffer, &ctx);

		// Step 0 for all hmac, store off the first half (the key is the same for all 3)
		// this will avoid having to setup the ipad/opad 2 times, and also avoids 4 SHA calls
		// reducing the hmac calls from 12 SHA limbs, down to 8 and ipad/opad loads from 3
		// down to 1.  It adds 4 CTX memcpy's, but that is a very fair trade off.
		SHA1_Init(&ctxi);
		SHA1_Init(&ctxo);
		memset(pad.uc, 0x36, 64);
		for (i = 0; i < 20; ++i)
			pad.uc[i] ^= buffer[i];
		SHA1_Update(&ctxi, pad.uc, 64);
		for (i = 0; i < 64/4; ++i)
			pad.ui[i] ^= 0x36363636^0x5c5c5c5c;
		SHA1_Update(&ctxo, pad.uc, 64);

		// k1 = HMAC(PES||ES) // use CHP as the key, PES is ES which is zero padded to length 20
		//  NOTE, memcpy ctxi/ctxo to harvest off the preloaded hmac key
		memcpy(&ctx, &ctxi, sizeof(ctx));
		SHA1_Update(&ctx, cur_salt->local_salt, 20);
		SHA1_Update(&ctx, cur_salt->local_salt, cur_salt->local_salt_length);
		SHA1_Final(buffer, &ctx);
		memcpy(&ctx, &ctxo, sizeof(ctx));
		SHA1_Update(&ctx, buffer, 20);
		SHA1_Final(key, &ctx);

		// tk = HMAC(PES) // use CHP as the key
		//  NOTE, memcpy ctxi/ctxo to harvest off the preloaded hmac key
		memcpy(&ctx, &ctxi, sizeof(ctx));
		SHA1_Update(&ctx, cur_salt->local_salt, 20);
		SHA1_Final(buffer, &ctx);
		memcpy(&ctx, &ctxo, sizeof(ctx));
		SHA1_Update(&ctx, buffer, 20);
		SHA1_Final(tk, &ctx);

		// k2 = HMAC(tk||ES) // use CHP as the key
		//  NOTE, ctxi and ctxo are no longer needed after this hmac, so we simply use them
		SHA1_Update(&ctxi, tk, 20);
		SHA1_Update(&ctxi, cur_salt->local_salt, cur_salt->local_salt_length);
		SHA1_Final(buffer, &ctxi);
		SHA1_Update(&ctxo, buffer, 20);
		SHA1_Final(key+20, &ctxo);

		// k = k1||k2 // encrypt "password-check" string using this key
		DES_set_key_unchecked((DES_cblock *) key, &ks1);
		DES_set_key_unchecked((DES_cblock *) (key+8), &ks2);
		DES_set_key_unchecked((DES_cblock *) (key+16), &ks3);
		memcpy(ivec, key + 32, 8);  // last 8 bytes!
		// PKCS#5 padding (standard block padding)
		DES_ede3_cbc_encrypt((unsigned char*)"password-check\x02\x02", (unsigned char*)crypt_out[index], 16, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void mozilla_set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_mozilla = {
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
		BINARY_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG },
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
		mozilla_set_key,
		get_key,
		fmt_default_clear_keys,
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

#endif
#endif /* HAVE_LIBCRYPTO */

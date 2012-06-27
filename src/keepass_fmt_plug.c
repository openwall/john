/* KeePass cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#if defined(__APPLE__) && defined(__MACH__) && \
	defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && \
	__MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif

#include <openssl/aes.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"keepass"
#define FORMAT_NAME		"KeePass SHA-256 AES"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests KeePass_tests[] = {
	{"$keepass$*1*50000*124*60eed105dac456cfc37d89d950ca846e*72ffef7c0bc3698b8eca65184774f6cd91a9356d338e5140e47e319a87f5e46a*8725bdfd3580cf054a1564dc724aaffe*8e58cc08af2462ddffe2ee39735ad14b15e8cb96dc05ef70d8e64d475eca7bf5*1*752*71d7e65fb3e20b288da8cd582b5c2bc3b63162eef6894e5e92eea73f711fe86e7a7285d5ac9d5ffd07798b83673b06f34180b7f5f3d05222ebf909c67e6580c646bcb64ad039fcdc6f33178fe475739a562dc78012f6be3104da9af69e0e12c2c9c5cd7134bb99d5278f2738a40155acbe941ff2f88db18daf772c7b5fc1855ff9e93ceb35a1db2c30cabe97a96c58b07c16912b2e095e530cc8c24041e7d4876b842f2e7c6df41d08da8c5c4f2402dd3241c3367b6e6e06cd0fa369934e78a6aab1479756a15264af09e3c8e1037f07a58f70f4bf634737ff58725414db10d7b2f61a7ed69878bc0de8bb99f3795bf9980d87992848cd9b9abe0fa6205a117ab1dd5165cf11ffa10b765e8723251ea0907bbc5f3eef8cf1f08bb89e193842b40c95922f38c44d0c3197033a5c7c926a33687aa71c482c48381baa4a34a46b8a4f78715f42eccbc8df80ee3b43335d92bdeb3bb0667cf6da83a018e4c0cd5803004bf6c300b9bee029246d16bd817ff235fcc22bb8c729929499afbf90bf787e98479db5ff571d3d727059d34c1f14454ff5f0a1d2d025437c2d8db4a7be7b901c067b929a0028fe8bb74fa96cb84831ccd89138329708d12c76bd4f5f371e43d0a2d234e5db2b3d6d5164e773594ab201dc9498078b48d4303dd8a89bf81c76d1424084ebf8d96107cb2623fb1cb67617257a5c7c6e56a8614271256b9dd80c76b6d668de4ebe17574ad617f5b1133f45a6d8621e127fcc99d8e788c535da9f557d91903b4e388108f02e9539a681d42e61f8e2f8b06654d4dec308690902a5c76f55b3d79b7c9a0ce994494bc60eff79ff41debc3f2684f40fc912f09035aae022148238ba6f5cfb92f54a5fb28cbb417ff01f39cc464e95929fba5e19be0251bef59879303063e6392c3a49032af3d03d5c9027868d5d6a187698dd75dfc295d2789a0e6cf391a380cc625b0a49f3084f45558ac273b0bbe62a8614db194983b2e207cef7deb1fa6a0bd39b0215d72bf646b599f187ee0009b7b458bb4930a1aea55222099446a0250a975447ff52", "openwall"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	int version;
	long long offset;
	int isinline;
	int contentsize;
	unsigned char contents[LINE_BUFFER_SIZE];
	unsigned char final_randomseed[16];
	unsigned char enc_iv[16];
	unsigned char contents_hash[32];
	unsigned char transf_randomseed[32];
	uint32_t key_transf_rounds;
} *cur_salt;

static void transform_key(char *masterkey, struct custom_salt *csp, unsigned char *final_key)
{
        // First, hash the masterkey
	SHA256_CTX ctx;
	unsigned char hash[32];
	int i;
	AES_KEY akey;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, masterkey, strlen(masterkey));
	SHA256_Final(hash, &ctx);
	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_encrypt_key(csp->transf_randomseed, 256, &akey) < 0) {
		fprintf(stderr, "AES_set_derypt_key failed!\n");
	}
        // Next, encrypt the created hash
	i = csp->key_transf_rounds >> 2;
	while (i--) {
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
	}
	i = csp->key_transf_rounds & 3;
	while (i--) {
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash+16, hash+16, &akey);
	}
        // Finally, hash it again...
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final(hash, &ctx);

        // ...and hash the result together with the randomseed
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, csp->final_randomseed, 16);
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final(final_key, &ctx);
}

static void init(struct fmt_main *pFmt)
{
#ifdef _OPENMP
	int omp_t = 1;
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * pFmt->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$keepass$", 9);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	ctcopy += 10;	/* skip over "$keepass$*" */
	p = strtok(ctcopy, "*");
	cs.version = atoi(p);
	if(cs.version == 1) {
		p = strtok(NULL, "*");
		cs.key_transf_rounds = atoi(p);
		p = strtok(NULL, "*");
		cs.offset = atoll(p);
		p = strtok(NULL, "*");
		for (i = 0; i < 16; i++)
			cs.final_randomseed[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.transf_randomseed[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		for (i = 0; i < 16; i++)
			cs.enc_iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.contents_hash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.isinline = atoi(p);
		if(cs.isinline == 1) {
			p = strtok(NULL, "*");
			cs.contentsize = atoi(p);
			p = strtok(NULL, "*");
			for (i = 0; i < cs.contentsize; i++)
				cs.contents[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
					+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
	}
	else {
		fprintf(stderr, "KeePass 2.x support is TODO!\n");
		exit(-1);
	}
	free(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char final_key[32];
		unsigned char decrypted_content[LINE_BUFFER_SIZE];
		SHA256_CTX ctx;
		unsigned char iv[16];
		unsigned char out[32];
		int pad_byte;
		int datasize;
		AES_KEY akey;
		transform_key(saved_key[index], cur_salt, final_key);
		/* AES decrypt cur_salt->contents with final_key */
		memcpy(iv, cur_salt->enc_iv, 16);
		memset(&akey, 0, sizeof(AES_KEY));
		if(AES_set_decrypt_key(final_key, 256, &akey) < 0) {
			fprintf(stderr, "AES_set_derypt_key failed in crypt!\n");
		}
		AES_cbc_encrypt(cur_salt->contents, decrypted_content, cur_salt->contentsize, &akey, iv, AES_DECRYPT);
		pad_byte = decrypted_content[cur_salt->contentsize-1];
		datasize = cur_salt->contentsize - pad_byte;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, decrypted_content, datasize);
		SHA256_Final(out, &ctx);
		if(!memcmp(out, cur_salt->contents_hash, 32))
			any_cracked = cracked[index] = 1;
	}
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

static void KeePass_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main KeePass_fmt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		KeePass_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		KeePass_set_key,
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

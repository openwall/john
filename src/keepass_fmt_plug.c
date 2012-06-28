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
#include "stdint.h"
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

#ifdef _MSC_VER
#define atoll (unsigned long long)_atoi64
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
	{"$keepass$*1*50000*124*f7465d646bab0a86197fcf2b778ea9c1*ec24a474b0745f9ff1de44ac3e0a274dda83375ecec45eb9ddc40b524fb51df2*f7f17dd2a15c4cf13fb4c8a504298fb3*e7765dba9ed64686a2c0b712de95bd0051a20b331ea0f77133e6afbb9faa1479*1*608*e5802225bf18755620355ad67efa87335532197ce45ee8374a5d23478557414b110426904671c49b266672c02e334c4261d52a9a0723d050329319f8d3b06a6d9507e5b30c78823beea101f52bde5ecdb6b6d0d2627fc254678416b39d2ba43ebce229c0b25f8c530975bc617be602d36e95a6e83c99c7264d5cc994af762460942830ac06b03d30c84c000d01061a938c274d78d383040c8cf5e69e7fbbaf6b46a7061399087f1db2747cd83afdb2b36e6077cecdc3b5c3b3f29f3a1ef537e8c798f8d614f9866a19a53b463aa81632e9aca43ebff9c787ca20a416a4051f16e4ececb84ea853fcc48a988e2d77cb385a2add3b858a18ee73783695a093628a0082d928ffeea39db585a478647e29395fdf2e3e8f54dc5b8277712d8cf5e8a266780944889fb46408b8afb614c3b8e7152b8cc865368d0ae000404234c11c8a77ebc521326683c00967a474cf82336afd1cb8f867db5f6cc7f5c9ae755c0fd0b4c9554ad26bef0b10f0c70978746090034e16922ee9cf38eb251515117cc62da3a62a6fd8a5dab0c10e857b2e2489d2521e1903d6b107c16fd1bf6565fc2953ea3206481ab6c466dba43777076c58ada7cb1883043f4747b2b80731476057598054ea9ec9de1645b4034f6569f579e70a021cc0a490dfa703def725846d0693d7cb02dea430905470db56663953b81b72f7543d6db7713afbcc91919b23cff80290a1053f34516c0b2c7a1f4bec1718994563ae188c2f65e20378537f88be2ebc6c47fbadabbd33414ffa30f115be0abdc89182e0a77d8d5c258d9ec5005415890218eb456fdcb79f1b15031289a0909fc6d8ae48ca6d2d699b6e0cd2e76462", "crackthis"},
	{"$keepass$*1*50000*124*e144905f9aa746e1b2c382c807125d02*dd08f46898a3e75c458a44f34ec5391d3f3eb62b24dbda3d5e486e36312168cc*376ae8d5e8430d0a18e7bb4a0baddf75*5fa8dfc2f440ad296f1562683d06bf2717ae7e8ed343a279f54292f9fc8229ab*1*608*3ce1e03a1452e44b609ebe7326db4ef133ca25c325cc7cc5795ef92358011e2d32a1cb7cadc6f412b1d0a09f67f1444dfec73ed770507683360962d26b0c2b0384bcf9aba2cf1b3e4b5d7083ceaf5f941a2b99ec68d574eb58fe79e94d90b81c8f1f0ccfd35b16d415e8e203c06138eb6a1144520ef98bcdb33d669d2ab4aef2ab739e6dbc3f2ea5c6eef8410ca1555262181d8379b516551eb9d6a23eeb515bd8ef12735a635b25743c1188642486dd1fa4544138a361bcfc108f689bfb90f81d9808adcbd509f057cdbfd1cd31ee8b542956292f9bcca21fabeacc9ba96b335223103a72f94d9b04bcba9d74fada62e0d5bf2da142e413a373ea3c97ff1d50109532f5d041c5f77bea28cdea00388ab9dd3afc72bc266ff44c34221d751738545056e83d7558cf02ffc6f5a57163526ffff9a7de1c6276d4815a812c165ef0293bb951bcbc2cf389d20e188a6c24d1bc5322ee0bc6972b765fb199b28d6e14c3b795bd5d7d4f0672352dfed4870cf59480bab0f39f2a20ac162e8365b6e3dcb4a7fec1baafcb8c806726a777c7a5832a0d1c12568c2d9cad8dc04b1ce3506dbc1bf9663d625cfccb2d3c1cb6b96eee0f34e019b0145e903feed4683abe2568f2c0007c02c57b43f4ee585f9760d5b04c8581e25421b6b5bb370a5b48965b64584b1ed444ea52101af2b818b71eb0f9ae7942117273a3aff127641e17779580b48168c5575a8d843a87dee1088e0fde62bb2100e5b2e178daa463aeaeb1d4ff0544445aab09a7bdc684bd948f21112004dcc678e9c5f8cf8ba6113244b7c72d544f37cbc6baed6ddc76b9ccba6480abfb79a80dda4cdf7e218f396a749b4e5f", "password"},
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

/*
 * JtR format to crack password protected Electrum Wallets.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Special thanks goes to Christopher Gurnee for making this work possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_electrum;
#elif FMT_REGISTERS_H
john_register_one(&fmt_electrum);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               4
#endif
#endif
#include <openssl/bn.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "sha2.h"
#include "jumbo.h"
#include "secp256k1.h"
#define PBKDF2_HMAC_SHA512_ALSO_INCLUDE_CTX 1 // hack
#include "pbkdf2_hmac_sha512.h"
#include "hmac_sha.h"
#include "memdbg.h"

#define FORMAT_NAME             "Electrum Wallet"
#define FORMAT_LABEL            "electrum"
#define FORMAT_TAG              "$electrum$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "SHA256 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        125
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests electrum_tests[] = {
	// Wallets created by Electrum 1.9.8
	{"$electrum$1*d64ac297de09893a03bc540b346d5e97*0af493539c512e3ded466b4879b8a47b", "openwall123"},
	{"$electrum$1*bb7feb604201d0e74135337ca33249c4*090a4001b972c7483116471aa1598a84", "password@12345"}, // 1.x to 2.4.3 upgrade generates same hash
	// Wallet created by Electrum 2.4.3
	{"$electrum$2*ca2a36958ea86cafd91be8f4806f073a*259129742f91f72e14d048fa0a1a0acf", "openwall"},
	// Wallet created by Electrum 2.6.3
	{"$electrum$2*3e37a6b705ea4e61884433c735edd0ff*dbfeaef2ea18df11016be57ed2a66b9d", "openwall"},
	// Electrum 2.8.3 2FA wallet
	{"$electrum$2*af6348b949824312bad6fd6c16363c1c*a645e1f547174ce950884936777b3842", "openwall"},
	// Electrum 1.x wallet upgraded to 2.8.3
	{"$electrum$1*8f664b711d89cba39e1af76928832776*6c563922cf8630d46daeb10f90442499", "openwall123"},
	// Electrum 2.6.4 wallet created by selecting "import keys" option during initialization, wallet_type == "imported"
	{"$electrum$3*390c9a6dea1160f17c263cabaf8e1d74*7edc571ab41253406c9ad18fc925a4ee", "openwall"},
	// Similar wallet as above
	{"$electrum$3*e4a1a7f27bb2df7d0bbf91d769adb29b*9340ec01561bf8bc6240627bee4f84a5", "password@123456789"},
	// Electrum 2.8.0+ encrypted wallet
	{"$electrum$4*03c2a94eb01e9453c24c9bf49102356788673cc26fbe27b9bf54b0f150758c7864*4249453103c2a94eb01e9453c24c9bf49102356788673cc26fbe27b9bf54b0f150758c7864355ed45b963901b56cd6c483468247c7c8c76ba11c9cb94633575838cffb8f0cebfc9af91ba402c06cca5c08238c643a0291e66e1a849eb66a9eda17e1496d09f46bfe6f63bfdcd591c260f31b92bd5958ce85c7719983a7395c88570946a59d5dcc2188680aba439cde0dbdfeaba985fe3d1a97d25b81573a92f72aea8c60fa3a4228acb789d7f307f6a19d1025fa6ac81d91d45ef07c0b26d9f85fc6ba07246b8b19d641929aac16ff1c942a3d69b824e3e39a122402aed63d3d12ca299416500459e7353bd56db92102c93f045ccc719cee90d2f891ff6b128886ec90768364bcc89c3393f21a5b57915f4eaf4e3b9c7a3958124b43956a47572ae38df2a11b84f6dc25ddc3d3b1968e3adadc756507118301e8cc490d249dc603f4f46c3bf0b214fd3bfb8dab6f048ba7d60dbee031d386a5aeec6664d2891abbeb0201b437d6e37c140be3e6210078e76afafbd78a8acaf45f21cf83c69218f9bfd3abb0211d57ab1874e9d645171cdaad4887a9fea86003b9948d22d9e7bfaec4c4bd0786cd4d191c82c61e83c61bae06a7c9936af46f8fa121ab696aba24ad8fd8f69537aa713bf271e4be567e7e3ccd141511c96ce634175f845ff680f71bbd595ef5d45d9cfd9a7e099fbab7964add7a76c4820b20952121e5621cb53c9476dc23860a5bc4ba3ecf636dc224503202dc11bf3bc88c70dcc2005684f7d3ebe6a7ea1487423a5145442f8f3d806d5d219560b4bce272ef9d6e32849b692cd91d4c60462b0f813603a52dc84b959051e787d890661e9f439a11fa8819c4fb947ff8dd0a5b7e5e63605f4e9f6eac6f8b2bfd7a9098dd2201c2f4cdaa2d7d0691ccf42b2761a8bb2a08c755077a753a41bcf305c83da8cd9ebaeee0360afb4be00827e167b2c1a3d5975d3a4a1e3b3b56794a155253437710ee3c0d0a2de0c4d631b48808fa946146f09e8ea9888d6c6bad104ebed814e79bdc26be38e8580d8fff6324405c128627079d1e3bafc2479274a3bc4f8196e923c835204e91ce8a9cb235c5349056415ad58a83b41254eda57839cd2e0bb66f125e32c76671f6447b2b0321d021c60706ff6f103ce483986fe0f1cc62307f6a1e89c4b2f334fc6f1f2597f5d68b3948c7655025a04ea858bc33eb341de09bdb4862701abcbc4c907270856de6072ee8d0c9e46e19c50eac454d4ca5fcd1a35f5d239aadc82543deafcd17f0eae2145561b8834dd80d337c574d3e931365db294d66aa4b47669f92784325b85abae49a8447a2afeb4cac460cba2a9d7b298bd3f69ac31862b92a970ed8d3241227858b0c40b2f6793cdd733020987beb7e6f01826fa2dae2b345f4e8e96da885a00901b20308f37c8613cf28ef997a6f25c741af917a547b38cff7577d2cac2654d5cdac2d0f1135ac6db3d70174b03c4149d134325f1b805ef11cd62531c13436ad1c7cb73f488dc411d349be34523d477953e8b47848e31ec85230a99ecd88c9cbc5d33de132aacd04877123cff599bea3b2e7b931347673cca605b3bc129496d5e80b06ae0eb3fce5c24ea0f8d2ecd4cfb9ed5034b26ed18b564731c78f5344ec863bd78797ad7de722c7a88e047af0364f69a303dc5f716ebda1de9ca21cb49e4091cb975c17f098932e884f36bded1fab34814931b0aeb72b1bc90747f7f5ebe73c547681f7a8d6d74e7acde2ba6e5e998bd6b035ade5fa64171dde4a82ed5ed7f273220d47bbd5a1c2ed4359d02392b746ba653d1c30f63bce161d0555ebc4775262036be51d4a50113bbac6823fd6a0d387a32673dc454c4d9d018cc25885a0d15d3f7488bbe18398d758cbbf1a24eaf71bd1560ff216e342e09efdbfae2872cfdf59ed802420ba8522edfd74f6d728ffa1683e586b53cbec80f00be6478a44d8df1c69a5cdbb50aa75da2f2dd0a679b037b4173f20b9514064d15ff50f1e9beb0112a41cdc0ecf7fb3028fe6f4c7339bb79d50cb7d43cabd8ae198741677d41e411c811c6267e9b4e41d944b035e47406d5120f1ee192db810cf6774*40c7a179573d57c54d0da0a1c4d71e306e1eea823f637f29c3e43b9792469d15", "openwall123"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;

static struct custom_salt {
	uint32_t type;
	unsigned char iv[16];
	unsigned char seed[64];
	unsigned char ephemeral_pubkey[128];
	unsigned char data[16384]; // is 16 KiB enough?
	uint32_t datalen;
	unsigned char mac[32];
	secp256k1_pubkey pubkey;
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_num_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
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
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1 && value != 2 && value != 3 && value != 4)
		goto err;

	if (value == 1 || value == 2 || value == 3) {
		if ((p = strtokm(NULL, "*")) == NULL) // iv
			goto err;
		if (hexlenl(p, &extra) != 16 * 2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // encrypted data (seed part)
			goto err;
		if (hexlenl(p, &extra) != 16 * 2 || extra)
			goto err;
	} else {
		if ((p = strtokm(NULL, "*")) == NULL) // ephemeral_pubkey
			goto err;
		if (hexlenl(p, &extra) > 128 * 2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // data
			goto err;
		if (hexlenl(p, &extra) > 16384 * 2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL) // data
			goto err;
		if (hexlenl(p, &extra) > 32 * 2 || extra)
			goto err;
	}

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");

	if (cs.type == 1 || cs.type == 2 || cs.type == 3) {
		for (i = 0; i < 16; i++)
			cs.iv[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 16; i++)
			cs.seed[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	} else {
		secp256k1_context *ctx;
		int length = strlen(p) / 2;

		for (i = 0; i < length; i++)
			cs.ephemeral_pubkey[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

		p = strtokm(NULL, "*");
		cs.datalen = strlen(p) / 2;
		for (i = 0; i < cs.datalen; i++)
			cs.data[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.mac[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
		ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
		secp256k1_ec_pubkey_parse(ctx, &cs.pubkey, cs.ephemeral_pubkey, length);
		secp256k1_context_destroy(ctx);
	}

	MEM_FREE(keeptr);
	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void electrum_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static const char *group_order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char iv[16];
		unsigned char key[32];
		unsigned char outbuf[48];
		SHA256_CTX ctx;
		AES_KEY aes_decrypt_key;
		int extra;
		int i;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA256_Final(key, &ctx);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, 32);
		SHA256_Final(key, &ctx);
		memcpy(iv, cur_salt->iv, 16);
		AES_set_decrypt_key(key, 128 * 2, &aes_decrypt_key);
		AES_cbc_encrypt(cur_salt->seed, outbuf, 16, &aes_decrypt_key, iv, AES_DECRYPT);

		if (cur_salt->type == 1) {
			// check if 16 bytes of the encrypted seed are all lower-case hex (btcrecover)
			outbuf[16] = 0;
			if (hexlenl((const char*)outbuf, &extra) != 8 * 2 || extra)
				cracked[index] = 0;
			else
				cracked[index] = 1;
		} else if (cur_salt->type == 2) {
			// check if starting 4 bytes are "xprv"
			if (strncmp((const char*)outbuf, "xprv", 4))
				cracked[index] = 0;
			else {
				// check if remaining 12 bytes are in base58 set [1-9A-HJ-NP-Za-km-z]
				for (i = 0; i < 12; i++) {
					unsigned char c = outbuf[4 + i];
					if ((c > 'z') || (c < '1') || ((c > '9') && (c < 'A')) || ((c > 'Z') && (c < 'a'))) {
						cracked[index] = 0;
						break;
					}
				}
				if (i == 12)
					cracked[index] = 1;
			}
		} else if (cur_salt->type == 3) {
			unsigned char padbyte = outbuf[15];
			// check for valid PKCS7 padding for a 52 or 51 byte "WIF" private key, 64 is the original data size
			if (padbyte == 12 || padbyte == 13) {
				if (check_pkcs_pad(outbuf, 16, 16) < 0)
					cracked[index] = 0;
				else
					cracked[index] = 1;
			}
			else {
				cracked[index] = 0;
			}
		} else if (cur_salt->type == 4) {
			BIGNUM *p, *q, *r;
			BN_CTX *ctx;
			unsigned char static_privkey[128];
			unsigned char shared_pubkey[33];
			unsigned char keys[128];
			unsigned char cmac[32];
			secp256k1_context *sctx;
			SHA512_CTX md_ctx;
			int shared_pubkeylen= 33;

			pbkdf2_sha512((unsigned char *)saved_key[index],
					strlen(saved_key[index]),
					(unsigned char*)"", 0, 1024,
					static_privkey, 64, 0);
			// do static_privkey % GROUP_ORDER
			p = BN_bin2bn(static_privkey, 64, NULL);
			q = BN_new();
			r = BN_new();
			BN_hex2bn(&q, group_order);
			ctx = BN_CTX_new();
			BN_mod(r, p, q, ctx);
			BN_CTX_free(ctx);
			BN_free(p);
			BN_free(q);
			BN_bn2bin(r, static_privkey);
			BN_free(r);
			sctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
			// multiply point with a scaler, shared_pubkey is compressed representation
			secp256k1_mul(sctx, shared_pubkey, &cur_salt->pubkey, static_privkey);
			secp256k1_context_destroy(sctx);
			SHA512_Init(&md_ctx);
			SHA512_Update(&md_ctx, shared_pubkey, shared_pubkeylen);
			SHA512_Final(keys, &md_ctx);
			// calculate mac of data
			hmac_sha256(keys + 32, 32, cur_salt->data, cur_salt->datalen, cmac, 32);
			if (memcmp(&cur_salt->mac, cmac, 16) == 0)
				cracked[index] = 1;
			else
				cracked[index] = 0;
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

struct fmt_main fmt_electrum = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		electrum_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		electrum_set_key,
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

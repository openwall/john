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

#include "arch.h"
#if !AC_BUILT
#define HAVE_LIBZ 1
#endif
#if HAVE_LIBZ

#if FMT_EXTERNS_H
extern struct fmt_main fmt_electrum;
#elif FMT_REGISTERS_H
john_register_one(&fmt_electrum);
#else

#include <string.h>
#include <zlib.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               4
#endif
#endif
#include <openssl/bn.h>

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "sha2.h"
#include "jumbo.h"
#include "secp256k1.h"
#include "pbkdf2_hmac_sha512.h"
#include "hmac_sha.h"
#include "memdbg.h"

#define FORMAT_NAME             "Electrum Wallet"
#define FORMAT_LABEL            "electrum"
#define FORMAT_TAG              "$electrum$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "SHA256 AES / PBKDF2-SHA512 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "SHA256 AES / PBKDF2-SHA512 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        125
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static struct fmt_tests electrum_tests[] = {
	// Wallet created by Electrum 1.9.8
	{"$electrum$1*d64ac297de09893a03bc540b346d5e97*0af493539c512e3ded466b4879b8a47b", "openwall123"},
	// Electrum 2.8.0+ encrypted wallet
	{"$electrum$4*03c2a94eb01e9453c24c9bf49102356788673cc26fbe27b9bf54b0f150758c7864*4249453103c2a94eb01e9453c24c9bf49102356788673cc26fbe27b9bf54b0f150758c7864355ed45b963901b56cd6c483468247c7c8c76ba11c9cb94633575838cffb8f0cebfc9af91ba402c06cca5c08238c643a0291e66e1a849eb66a9eda17e1496d09f46bfe6f63bfdcd591c260f31b92bd5958ce85c7719983a7395c88570946a59d5dcc2188680aba439cde0dbdfeaba985fe3d1a97d25b81573a92f72aea8c60fa3a4228acb789d7f307f6a19d1025fa6ac81d91d45ef07c0b26d9f85fc6ba07246b8b19d641929aac16ff1c942a3d69b824e3e39a122402aed63d3d12ca299416500459e7353bd56db92102c93f045ccc719cee90d2f891ff6b128886ec90768364bcc89c3393f21a5b57915f4eaf4e3b9c7a3958124b43956a47572ae38df2a11b84f6dc25ddc3d3b1968e3adadc756507118301e8cc490d249dc603f4f46c3bf0b214fd3bfb8dab6f048ba7d60dbee031d386a5aeec6664d2891abbeb0201b437d6e37c140be3e6210078e76afafbd78a8acaf45f21cf83c69218f9bfd3abb0211d57ab1874e9d645171cdaad4887a9fea86003b9948d22d9e7bfaec4c4bd0786cd4d191c82c61e83c61bae06a7c9936af46f8fa121ab696aba24ad8fd8f69537aa713bf271e4be567e7e3ccd141511c96ce634175f845ff680f71bbd595ef5d45d9cfd9a7e099fbab7964add7a76c4820b20952121e5621cb53c9476dc23860a5bc4ba3ecf636dc224503202dc11bf3bc88c70dcc2005684f7d3ebe6a7ea1487423a5145442f8f3d806d5d219560b4bce272ef9d6e32849b692cd91d4c60462b0f813603a52dc84b959051e787d890661e9f439a11fa8819c4fb947ff8dd0a5b7e5e63605f4e9f6eac6f8b2bfd7a9098dd2201c2f4cdaa2d7d0691ccf42b2761a8bb2a08c755077a753a41bcf305c83da8cd9ebaeee0360afb4be00827e167b2c1a3d5975d3a4a1e3b3b56794a155253437710ee3c0d0a2de0c4d631b48808fa946146f09e8ea9888d6c6bad104ebed814e79bdc26be38e8580d8fff6324405c128627079d1e3bafc2479274a3bc4f8196e923c835204e91ce8a9cb235c5349056415ad58a83b41254eda57839cd2e0bb66f125e32c76671f6447b2b0321d021c60706ff6f103ce483986fe0f1cc62307f6a1e89c4b2f334fc6f1f2597f5d68b3948c7655025a04ea858bc33eb341de09bdb4862701abcbc4c907270856de6072ee8d0c9e46e19c50eac454d4ca5fcd1a35f5d239aadc82543deafcd17f0eae2145561b8834dd80d337c574d3e931365db294d66aa4b47669f92784325b85abae49a8447a2afeb4cac460cba2a9d7b298bd3f69ac31862b92a970ed8d3241227858b0c40b2f6793cdd733020987beb7e6f01826fa2dae2b345f4e8e96da885a00901b20308f37c8613cf28ef997a6f25c741af917a547b38cff7577d2cac2654d5cdac2d0f1135ac6db3d70174b03c4149d134325f1b805ef11cd62531c13436ad1c7cb73f488dc411d349be34523d477953e8b47848e31ec85230a99ecd88c9cbc5d33de132aacd04877123cff599bea3b2e7b931347673cca605b3bc129496d5e80b06ae0eb3fce5c24ea0f8d2ecd4cfb9ed5034b26ed18b564731c78f5344ec863bd78797ad7de722c7a88e047af0364f69a303dc5f716ebda1de9ca21cb49e4091cb975c17f098932e884f36bded1fab34814931b0aeb72b1bc90747f7f5ebe73c547681f7a8d6d74e7acde2ba6e5e998bd6b035ade5fa64171dde4a82ed5ed7f273220d47bbd5a1c2ed4359d02392b746ba653d1c30f63bce161d0555ebc4775262036be51d4a50113bbac6823fd6a0d387a32673dc454c4d9d018cc25885a0d15d3f7488bbe18398d758cbbf1a24eaf71bd1560ff216e342e09efdbfae2872cfdf59ed802420ba8522edfd74f6d728ffa1683e586b53cbec80f00be6478a44d8df1c69a5cdbb50aa75da2f2dd0a679b037b4173f20b9514064d15ff50f1e9beb0112a41cdc0ecf7fb3028fe6f4c7339bb79d50cb7d43cabd8ae198741677d41e411c811c6267e9b4e41d944b035e47406d5120f1ee192db810cf6774*40c7a179573d57c54d0da0a1c4d71e306e1eea823f637f29c3e43b9792469d15", "openwall123"},
	// Wallet created by Electrum 1.9.8
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
	// Electrum 2.8.0+ encrypted wallet with truncated hash, "electrum28-wallet" from btcrecover project
	{"$electrum$5*0328e536dd1fbbb85d78de1a8c21215d4646cd87d6b6545afcfb203e5bb32e0de4*61b1e287a5acff4b40e4abd73ff62dc233c1c7a6a54b3270949281b9d44bc6e746743733360500718826e50bb28ea99a6378dc0b0c578e9d0bf09c667671c82a1bd71c8121edbb4c9cbca93ab0e17e218558ead81755e62b0d4ad547aa1b3beb0b9ee43b11270261c9b38502f00e7f6f096811b7fdae6f3dce85c278d3751fec044027054218ccf20d404bab24380b303f094704e626348a218f44ab88ce2ac5fa7d450069fca3bb53f9359dbbaad0ea1b3859129b19c93ed7888130f8a534f84a629c67edc150a1c5882a83cb0add4615bb569e8dc471de4d38fc8b1e0b9b28040b5ea86093fcdeceaedb6b8f073f6f0ee5541f473a4b1c2bfae4fc91e4bbb40fa2185ecfa4c72010bcf8df05b1a7db45f64307dbc439f8389f0e368e38960b6d61ac88c07ce95a4b03d6d8b13f4c7dc7d7c447097865235ab621aeef38dc4172bf2dc52e701132480127be375fe98834f16d9895dce7f6cdfe900a2ce57eaa6c3036c1b9a661c3c9adbf84f4adfe6d4d9fa9f829f2957cfb353917dc77fd8dd4872b7d90cb71b7d3a29c9bfe3440e02449220acba410fa0af030f51aa2438f7478dbb277d62613112e4eebc66d5d7bdba793fb2073d449954f563284819189ffb5dbcdeb6c95c64bc24e0ef986bce07bafe96ab449ae2b6edaf4f98ffbd392a57bd93c2359444ec4046ae65b440adb96b6e4eef9d06bb04d2f3fa2e4175165bcadbf7e13cc3b6e65e67df901f96a2f154bc763b56b3736a335e1d1bc16e99736f757a4ae56c099645c917360b1ecf8dcefc7281541c6ff65d87cadab4a48f1f6b7b73a3e5a67e2e032abb56b499e73a9f3b69ce065e43b0174639785ae30635d105ebcc827dcf9b19bdd1a92879a5d4bc4e12b5630c188b1b96e3c586e19901b8f96084bcd59b2f4b201a3a8b6e633a5c194901d4609add9671b0bcc12b2b94ae873d201258b36315484e4b9c5f5d6289656baa93eec9e92aec88e2d73d86b9e3d1f24294e3d8ebe9a9f2f6edfbf28f530670c5b086fc4f74df89b4e4cbe06ee7e45cbd238b599d19c2d5da5523b12b1e7050ea0a9b47a5d22c6c3fc476f814f9705dc7ed3aeb1b44fc6b4d69f02a74963dce5057c3c049f92e595a4da5035cffc303a4cb162803aa3f816527a7e466b8424789a0d77e26819615662420c370457e29fcc1938fd754f3acfd21416ce3ab27e9febbc0e24fc7055eddc31e48faa014f9f3695c2e956f0e6c94c507a8d2f8c3aeb4b98b69b6340b6a3acb1acdde9581279f78ee10687616360c018e9f67d6c8bb5950e8fdabd3d0d5808824975aa4a50f88581472212f24ad58a700fe4787642b973924575fe71d1ecd7b2b6acd363f48c40bdd55f35f60a06dee544c266e608fd5a6d263f745e8b11d1160638eb301adfd1a88eddf6d0ccb9e1021e0bde9cf5163583a202b3dc95c255c8cc24*ec90c1ff54632e7c8cfb812eeb14d7ec49ddaf576dca10bfb16f965e6106ce48", "btcr-test-password"},
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
	omp_autotune(self, OMP_SCALE);
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
	if (value != 1 && value != 2 && value != 3 && value != 4 && value != 5)
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

// The decypted and decompressed wallet should start with one of these two, // Christopher Gurnee
#define EXPECTED_BYTES_1 "{\n    \""
#define EXPECTED_BYTES_2 "{\r\n    \""

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
		unsigned char iv[16];
		unsigned char key[32];
		SHA256_CTX ctx;
		AES_KEY aes_decrypt_key;
		int extra;
		unsigned char static_privkey[MAX_KEYS_PER_CRYPT][64];
		int i, j;

		if (cur_salt->type == 1 || cur_salt->type == 2 || cur_salt->type == 3) {
			for (i = 0; i < MAX_KEYS_PER_CRYPT; i++) {
				unsigned char outbuf[48] = { 0 };

				SHA256_Init(&ctx);
				SHA256_Update(&ctx, saved_key[index+i], strlen(saved_key[index+i]));
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
						cracked[index+i] = 0;
					else
						cracked[index+i] = 1;
				} else if (cur_salt->type == 2) {
					// check if starting 4 bytes are "xprv"
					if (strncmp((const char*)outbuf, "xprv", 4))
						cracked[index+i] = 0;
					else {
						// check if remaining 12 bytes are in base58 set [1-9A-HJ-NP-Za-km-z]
						for (j = 0; j < 12; j++) {
							unsigned char c = outbuf[4 + j];
							if ((c > 'z') || (c < '1') || ((c > '9') && (c < 'A')) || ((c > 'Z') && (c < 'a'))) {
								cracked[index+i] = 0;
								break;
							}
						}
						if (j == 12)
							cracked[index+i] = 1;
					}
				} else if (cur_salt->type == 3) {
					unsigned char padbyte = outbuf[15];
					// check for valid PKCS7 padding for a 52 or 51 byte "WIF" private key, 64 is the original data size
					if (padbyte == 12 || padbyte == 13) {
						if (check_pkcs_pad(outbuf, 16, 16) < 0)
							cracked[index+i] = 0;
						else
							cracked[index+i] = 1;
					}
					else {
						cracked[index+i] = 0;
					}
				}
			}
		} else if (cur_salt->type == 4 || cur_salt->type == 5) {
			BIGNUM *p, *q, *r;
			BN_CTX *ctx;
			unsigned char shared_pubkey[33];
			unsigned char keys[128];
			unsigned char cmac[32];
			secp256k1_context *sctx;
			SHA512_CTX md_ctx;
			int shared_pubkeylen= 33;
#ifdef SIMD_COEF_64
			int len[MAX_KEYS_PER_CRYPT];
			unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
			for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
				len[i] = strlen(saved_key[i+index]);
				pin[i] = (unsigned char*)saved_key[i+index];
				pout[i] = static_privkey[i];
			}
			pbkdf2_sha512_sse((const unsigned char **)pin, len, (unsigned char*)"", 0, 1024, pout, 64, 0);
#else

			for (i = 0; i < MAX_KEYS_PER_CRYPT; i++) {
				pbkdf2_sha512((unsigned char *)saved_key[index+i],
						strlen(saved_key[index+i]),
						(unsigned char*)"", 0, 1024,
						static_privkey[i], 64, 0);
			}
#endif
			for (i = 0; i < MAX_KEYS_PER_CRYPT; i++) {
				// do static_privkey % GROUP_ORDER
				p = BN_bin2bn(static_privkey[i], 64, NULL);
				q = BN_new();
				r = BN_new();
				BN_hex2bn(&q, group_order);
				ctx = BN_CTX_new();
				BN_mod(r, p, q, ctx);
				BN_CTX_free(ctx);
				BN_free(p);
				BN_free(q);
				BN_bn2bin(r, static_privkey[i]);
				BN_free(r);
				sctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
				// multiply point with a scaler, shared_pubkey is compressed representation
				secp256k1_mul(sctx, shared_pubkey, &cur_salt->pubkey, static_privkey[i]);
				secp256k1_context_destroy(sctx);
				SHA512_Init(&md_ctx);
				SHA512_Update(&md_ctx, shared_pubkey, shared_pubkeylen);
				SHA512_Final(keys, &md_ctx);
				if (cur_salt->type == 4) {
					// calculate mac of data
					hmac_sha256(keys + 32, 32, cur_salt->data, cur_salt->datalen, cmac, 32);
					if (memcmp(&cur_salt->mac, cmac, 16) == 0)
						cracked[index+i] = 1;
					else
						cracked[index+i] = 0;
				} else if (cur_salt->type == 5) {
					        z_stream z;
						unsigned char iv[16];
						unsigned char out[512] = { 0 };
						unsigned char fout[512] = { 0 };
						AES_KEY aes_decrypt_key;

						// common zlib settings
						z.zalloc = Z_NULL;
						z.zfree = Z_NULL;
						z.opaque = Z_NULL;
						z.avail_in = 512;
						z.avail_out = 512;
						z.next_out = fout;

						memcpy(iv, keys, 16);
						// fast zlib based rejection test, is this totally safe?
						AES_set_decrypt_key(keys + 16, 128, &aes_decrypt_key);
						AES_cbc_encrypt(cur_salt->data, out, 16, &aes_decrypt_key, iv, AES_DECRYPT);
						if ((memcmp(out, "\x78\x9c", 2) != 0) || (out[2] & 0x7) != 0x5) {
							cracked[index+i] = 0;
						} else {
							AES_set_decrypt_key(keys + 16, 128, &aes_decrypt_key);
							AES_cbc_encrypt(cur_salt->data + 16, out + 16, 512 - 16, &aes_decrypt_key, iv, AES_DECRYPT);
							z.next_in = out;
							inflateInit2(&z, 15);
							inflate(&z, Z_NO_FLUSH);
							inflateEnd(&z);
							if ((memcmp(fout, EXPECTED_BYTES_1, 7) == 0) || (memcmp(fout, EXPECTED_BYTES_2, 8) == 0))
								cracked[index+i] = 1;
							else
								cracked[index+i] = 0;
						}
				}
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

/* report kdf type as tunable cost */
static unsigned int get_kdf_type(void *salt)
{
	struct custom_salt *cs = salt;

	if (cs->type == 1 || cs->type == 2 || cs->type == 3)
		return 1; // SHA256 based KDF
	else
		return 2; // PBKDF2-SHA512
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
		{
			"kdf [1:SHA256 2:PBKDF2-SHA512]",
		},
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
		{
			get_kdf_type,
		},
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

#endif /* HAVE_LIBZ */

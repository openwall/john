/*
 * Format for cracking BitShares wallet hashes.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_bitshares;
#elif FMT_REGISTERS_H
john_register_one(&fmt_bitshares);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               32  // MKPC and OMP_SCALE tuned on i5-6500 CPU

#include "formats.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "aes.h"
#include "secp256k1.h"

#define FORMAT_LABEL            "bitshares"
#define FORMAT_NAME             "BitShares Wallet"
#define FORMAT_TAG              "$BitShares$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "SHA-512 64/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      16

#define MAX_CIPHERTEXT_LENGTH   1024

static struct fmt_tests tests[] = {
	// BitShares.Setup.2.0.180115.exe
	{"$BitShares$0*ec415018f26e7182a273655aef7cec47966306c48956604462f5b9e1613b3b70ebaaed4d7600b24a424ddb7d4cd56e55", "openwall"},
	{"$BitShares$0*3bebbec17f0643ee9d3d5e48f04451bf7e38765f3bf2fa6ea12f680d60da121bb04ced9f76681744f3730322082c7ec7", "äbc12345"},
	// Google Chrome -> https://wallet.bitshares.org in January, 2018
	{"$BitShares$0*97452e44d43818099fbd2cc7539588c2c2dbc4e06e1b18831ded86b7e68e51d2da2c2b81054863032248a9da93ea1943", "openwall123"},
	// Backup (.bin) files from February, 2018
	{"$BitShares$1*0384138ccd1cc1afdd275a797eb7dad81aed490fb543d3bb01ec3daff87c862f59abd4aa930724a4b3de5a8c1b208a770457a501ec733e8f4544c2c0f6cef4eff145eed547e535806deeea138ec9aa12101721da78e3e91fe71f8c989d2a684a274b150d95cce7f76ba8503565739f0d8f0b602fa3cce519dbef4f40f2d34dfc4a6d1f5707aba3962c7b6eb0b46ac9e8503645da3df0a3375f953597ce246321bf95d2cd400532a45f23c2630f2b27c3a1a03946ed1852c8c2a9fbf4871941f716f47f0307649229770ae08c6843b537516303ad3462cd5406e9442b1124e8e4582db4db31ca0e0802e10fb5357098049f7935d300d3b8f0e36ba6d759d64b0936c2af037ac561fb9d52fa55204186258f9505ac82dc6c87df81f73c23edcd65724e858e47823feac4fdbc9bc49b689ad3113523e2d379d360daf9e97d7721bcf5f443451235415e436f4d3abf7a5c40cfbead4d6bf5ce6c4af6986429a957bf505e88f3531657165877966b2feb9650120d408a00cc9da8c2ed7215ea492c89459f2d8f047a35b55902f1762b3d1c8623db778b77d07f254185861c7a29437e0d48a88f011e93cfa9b1791a0487bd4c59a4515daeadd3c54e5213b652cd3ea3338b6999cbe08a2ea78e932b65d6b536a26d5999b5ea28ad4703c3349b9d824af02cf8eccb498f8bcc327ce86e493cf4147fd4cb9a3ec3cc67f3cfb047c47078007db9d1bc85b02d9672d52027b98665df1741c1e6b2a5771db9c4caa5a3b24492401d6148c5ed22beebb0d11017185cd00a2ef604ac35f5067842caf37fa93d35f20d999a79c7f2330efd85fcc8c6c626c08ed09b93f18f8af15f8187a6a6ed18fb25e4b1cd3270c4f10f8896f0011e6c5cfbe28a1c6ab3f7096713bcb603d39cda7a4fe6082dae7b05e4dcbd54890846", "openwall"},
	{"$BitShares$1*032dcf20c5d2d4ae30755a6c7a6fcdf385e4b1f3aa0bd768a35f6bc0bf9a6a052cfc714252a05d749f5539f28f50d00ea14c4623ad7080bd9ce37f083c610f92203a39c98ab1e6e2de8978d993acc52117eb1ad7fc3723fe001345b33b3e2c061bc1a82707c8fbbc531f3dbdb6173dc277358b0b5e5f0d431619c5bacf6cd01e7e48cfea8ceb1f8a3b6efcd3b3de9966d6c8ec9a2216d9e130f7f2315c62dfab2903212ca85a2a5f8b0a470378043771f89ba3bf7b06a9a7acc93c30832ad75375cf0574d681e01dfc9667bb3b30c0fb513ea78a3d9c963193093aab719546ddfaf44814e10fb5a90d3966203c95c57bc8b2e6463a9c16ff15e26646750c3a1ab0a65d53272d9707463f4583b9ef9d03f34ff963c5d32f4025474c8405f59307b9e61fc2c59290a79fc8580f8a881cfb0c454dbb94b5a78a82f87f4d1a79bc73bd91fc136de0dcb12c08dc04516eff7898a0e95d82fcd22328d16c6ab8a4c9a40f9ee2de1dca41928bf4ab0e109afa99098a7c5d22828ed4baa80a8658b5a457a63940642c6dd4c0707f65dedc01eeb414307ad7c5533a53d85378fd185d235f5d3edb84a48ac2c7e2b56f71c617cbc43dcc1ddea2ed39d04fabb98256ac573cf5887b608e11eef54e3762386f683d42d5e5bed5a15d7d4feec48dc3db1aff2f0277e7562b6f6a745c4ff6a8ead4b4f0ceac110659433a72c2300ac6c39ba80123a3ba2869b05f277acffc4d82a54d2b2b029f193ad772ecadb629f1c2b7c618ab5958d6982edc07d3b6865a4d722429d7851642438e2d54dee1428d2de36f128a0df5935495f4ed3258820c1dd0f8d473be6085a304172ad5d56b2209dcfe8643237623f51d4399596e70049fe0b5c207c37070b9f4900fbd72245578717f200bbd9f275aeba668477889fa23ad3032aa", "äbc12345"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	uint32_t ctlen;
	int type;
	unsigned char ct[MAX_CIPHERTEXT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(cracked);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;
	int type;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version / type
		goto err;
	if (!isdec(p))
		goto err;
	type = atoi(p);
	if (type != 0 && type != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
		goto err;
	value = hexlenl(p, &extra);
	if (type == 0) {
		if (value > MAX_CIPHERTEXT_LENGTH * 2 || value < 32 * 2 || extra)
			goto err;
	} else {
		if (value > MAX_CIPHERTEXT_LENGTH * 2 || value < 256 * 2 || extra)  // rough check!
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
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	cs.ctlen = strlen(p) / 2;
	for (i = 0; i < cs.ctlen; i++)
		cs.ct[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);

	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

// From JimF with love ;)
inline static void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;

	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		SHA512_CTX ctx;
		unsigned char km[64];
		AES_KEY aes_decrypt_key;
		unsigned char out[MAX_CIPHERTEXT_LENGTH];
		unsigned char iv[16] = { 0 }; // does not matter

		if (cur_salt->type == 0) {
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, saved_key[index], saved_len[index]);
			SHA512_Final(km, &ctx);

			AES_set_decrypt_key(km, 256, &aes_decrypt_key);
			AES_cbc_encrypt(cur_salt->ct + cur_salt->ctlen - 32, out, 32, &aes_decrypt_key, iv, AES_DECRYPT);

			if (memcmp(out + 16, "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", 16) == 0) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		} else {
			secp256k1_context *ctxs;
			secp256k1_pubkey pubkey;
			SHA256_CTX sctx;
			unsigned char output[128];
			size_t outlen = 33;
			int padbyte;
			int dlen = cur_salt->ctlen - outlen;

			SHA256_Init(&sctx);
			SHA256_Update(&sctx, saved_key[index], saved_len[index]);
			SHA256_Final(km, &sctx);

			ctxs = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
			secp256k1_ec_pubkey_parse(ctxs, &pubkey, cur_salt->ct, 33);
			secp256k1_ec_pubkey_tweak_mul(ctxs, &pubkey, km);
			secp256k1_ec_pubkey_serialize(ctxs, output, &outlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
			secp256k1_context_destroy(ctxs);
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, output + 1, 32);
			SHA512_Final(km, &ctx);
			hex_encode(km, 64, output);

			SHA512_Init(&ctx);
			SHA512_Update(&ctx, output, 128);
			SHA512_Final(km, &ctx);
			AES_set_decrypt_key(km, 256, &aes_decrypt_key);
			AES_cbc_encrypt(cur_salt->ct + 33, out, dlen, &aes_decrypt_key, km + 32, AES_DECRYPT);

			padbyte = out[dlen - 1];
			if (padbyte <= 16) {
				// check padding!
				if (check_pkcs_pad(out, dlen, 16) >= 0) {
					// check checksum
					SHA256_Init(&sctx);
					SHA256_Update(&sctx, out + 4, dlen - 4 - padbyte);
					SHA256_Final(km, &sctx);
					if (memcmp(km, out, 4) == 0) {
						cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
						any_cracked |= 1;

					}
				}
			}
		}
	}

	return count;
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
	return 1;
}

struct fmt_main fmt_bitshares = {
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
		tests
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
		set_key,
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

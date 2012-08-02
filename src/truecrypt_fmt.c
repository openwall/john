/* TrueCrypt volume support to John The Ripper
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2012.  No copyright
 * is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2012 Alain Espinosa and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x10001000

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "crc32.h"

#define PLAINTEXT_LENGTH					31
#define MAX_CIPHERTEXT_LENGTH		(512*2+32)
#define SALT_SIZE								64
#define BINARY_SIZE							(512-SALT_SIZE)
#define MIN_KEYS_PER_CRYPT			16
#define MAX_KEYS_PER_CRYPT			16

static char key_buffer[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH];
static unsigned char* salt_buffer;
static const EVP_MD* md = NULL;
static int num_iterations;

static void init(struct fmt_main *self)
{
	/* OpenSSL init, cleanup part is left to OS */
	//SSL_load_error_strings();
	//SSL_library_init();
	OpenSSL_add_all_algorithms();
}
static void init_ripemd160(struct fmt_main *self)
{
	init(self);

	md = EVP_get_digestbyname("RIPEMD160");
	num_iterations = 2000;
}
static void init_sha512(struct fmt_main *self)
{
	init(self);

	md = EVP_get_digestbyname("SHA512");
	num_iterations = 1000;
}
static void init_whirlpool(struct fmt_main *self)
{
	init(self);

	md = EVP_get_digestbyname("whirlpool");
	num_iterations = 1000;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	return split_fields[1];
}

static char* ms_split(char *ciphertext, int index)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];
	int i;

	for(i = 0; ciphertext[i] && i < MAX_CIPHERTEXT_LENGTH; i++)
		out[i] = ciphertext[i];

	out[i] = 0;

	return out;
}

static int valid(char* ciphertext, int pos)
{
	unsigned int i;
	// Very small
	if(pos + 512*2 != strlen(ciphertext))
		return 0;

	// Not hexadecimal characters
	for (i = 0; i < 512*2; i++)
		if (atoi16[ARCH_INDEX((ciphertext+pos)[i])] == 0x7F)
			return 0;

	return 1;
}
static int valid_ripemd160(char* ciphertext, struct fmt_main *self)
{
	// Not a supported hashing
	if (strncmp(ciphertext, "truecrypt_RIPEMD_160$", 21))
		return 0;

	return valid(ciphertext, 21);
}
static int valid_sha512(char* ciphertext, struct fmt_main *self)
{
	// Not a supported hashing
	if (strncmp(ciphertext, "truecrypt_SHA_512$", 18))
		return 0;

	return valid(ciphertext, 18);
}
static int valid_whirlpool(char* ciphertext, struct fmt_main *self)
{
	// Not a supported hashing
	if (strncmp(ciphertext, "truecrypt_WHIRLPOOL$", 20))
		return 0;

	return valid(ciphertext, 20);
}

static void set_salt(void *salt)
{
	salt_buffer = salt;
}

static void* get_salt(char *ciphertext)
{
	static unsigned char out[SALT_SIZE];
	unsigned int i;

	while(*ciphertext != '$') ciphertext++;
	ciphertext++;

	// Convert the hexadecimal salt in binary
	for(i = 0; i < SALT_SIZE; i++)
		out[i] = (atoi16[ARCH_INDEX(ciphertext[2*i])] << 4) | atoi16[ARCH_INDEX(ciphertext[2*i+1])];

	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[BINARY_SIZE];
	unsigned int i;

	while(*ciphertext != '$') ciphertext++;
	ciphertext += 1+64*2;

	for(i = 0; i < BINARY_SIZE; i++)
		out[i]  = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) | atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	return out;
}

static int binary_hash(void *binary)
{
	return 1;
}

static int get_hash(int index)
{
	return 1;
}

static void crypt_all(int count)
{}

static int cmp_all(void* binary, int count)
{
	unsigned int i;
	unsigned char key[192];
	unsigned char tweak[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int outlen;
	unsigned char first_block_dec[16];

	for(i = 0; i < count; i++)
	{
		EVP_CIPHER_CTX cipher_context;
		// Key Strengthening
		PKCS5_PBKDF2_HMAC(key_buffer[i], strlen(key_buffer[i]), salt_buffer, 64, num_iterations, md, sizeof(key), key);

		// Try to decrypt using AES
		EVP_CIPHER_CTX_init(&cipher_context);
		EVP_DecryptInit_ex(&cipher_context, EVP_aes_256_xts(), NULL, key, tweak);
		EVP_DecryptUpdate(&cipher_context, first_block_dec, &outlen, binary, 16);
		// If first 4 bytes is 'TRUE' sucefull decryption
		if(first_block_dec[0] == 84 && first_block_dec[1] == 82 && first_block_dec[2] == 85 && first_block_dec[3] == 69)
			return 1;
	}

	return 0;
}

static int cmp_one(void* binary, int index)
{
	unsigned char key[192];
	unsigned char tweak[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int outlen;
	unsigned char first_block_dec[16];

	EVP_CIPHER_CTX cipher_context;
	// Key Strengthening
	PKCS5_PBKDF2_HMAC(key_buffer[index], strlen(key_buffer[index]), salt_buffer, 64, num_iterations, md, sizeof(key), key);

	// Try to decrypt using AES
	EVP_CIPHER_CTX_init(&cipher_context);
	EVP_DecryptInit_ex(&cipher_context, EVP_aes_256_xts(), NULL, key, tweak);
	EVP_DecryptUpdate(&cipher_context, first_block_dec, &outlen, binary, 16);
	// If first 4 bytes is 'TRUE' sucefull decryption
	if(first_block_dec[0] == 84 && first_block_dec[1] == 82 && first_block_dec[2] == 85 && first_block_dec[3] == 69)
	{
		// int i;
		// unsigned char crc32[4];
		// unsigned char know_crc32[4];
		// unsigned char* bin_ptr = ((unsigned char*)binary)+256;
		// CRC32_t check_sum;
		// CRC32_Init(&check_sum);

		// know_crc32[0] = first_block_dec[8];
		// know_crc32[1] = first_block_dec[9];
		// know_crc32[2] = first_block_dec[10];
		// know_crc32[3] = first_block_dec[11];

		////Check that crc32 checksum are valid
		// for(i = 0; i < 16; i++, bin_ptr+=16)
		// {
			//// We need to "tweak" the tweak array: Its complex(i dont know the format) to convert i,n XTS params to an array
			// EVP_DecryptUpdate(&cipher_context, first_block_dec, &outlen, bin_ptr, 16);
			// CRC32_Update(&check_sum, first_block_dec, 16);
		// }

		// CRC32_Final(crc32, check_sum);
		// printf("Real: %i %i %i %i Decrypt: %i %i %i %i\n", (int)know_crc32[0], (int)know_crc32[1], (int)know_crc32[2], (int)know_crc32[3],
		// (int)crc32[0], (int)crc32[1], (int)crc32[2], (int)crc32[3]);

		// TODO: Not use this code, use the commented up
		if(!first_block_dec[12] && !first_block_dec[13] && !first_block_dec[14] && !first_block_dec[15])
			return 1;
	}

	return 0;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char* key, int index)
{
	strcpy(key_buffer[index], key);
}

static char *get_key(int index)
{
	return key_buffer[index];
}

static int salt_hash(void *salt)
{
	return ((int*)salt)[0] & (SALT_HASH_SIZE - 1);
}


static struct fmt_tests tests_ripemd160[] = {
{"truecrypt_RIPEMD_160$b9f118f89d2699cbe42cad7bc2c61b0822b3d6e57e8d43e79f55666aa30572676c3aced5f0900af223e9fcdf43ac39637640977f546eb714475f8e2dbf5368bfb80a671d7796d4a88c36594acd07081b7ef0fbead3d3a0ff2b295e9488a5a2747ed97905436c28c636f408b36b0898aad3c4e9566182bd55f80e97a55ad9cf20899599fb775f314067c9f7e6153b9544bfbcffb53eef5a34b515e38f186a2ddcc7cd3aed635a1fb4aab98b82d57341ec6ae52ad72e43f41aa251717082d0858bf2ccc69a7ca00daceb5b325841d70bb2216e1f0d4dc936b9f50ebf92dbe2abec9bc3babea7a4357fa74a7b2bcce542044552bbc0135ae35568526e9bd2afde0fa4969d6dc680cf96f7d82ec0a75b6170c94e3f2b6fd98f2e6f01db08ce63f1b6bcf5ea380ed6f927a5a8ced7995d83ea8e9c49238e8523d63d6b669ae0d165b94f1e19b49922b4748798129eed9aa2dae0d2798adabf35dc4cc30b25851a3469a9ee0877775abca26374a4176f8d237f8191fcc870f413ffdbfa73ee22790a548025c4fcafd40f631508f1f6c8d4c847e409c839d21ff146f469feff87198bc184db4b5c5a77f3402f491538503f68e0116dac76344b762627ad678de76cb768779f8f1c35338dd9f72dcc1ac337319b0e21551b9feb85f8cac67a2f35f305a39037bf96cd61869bf1761abcce644598dad254990d17f0faa4965926acb75abf", "password" },
{"truecrypt_RIPEMD_160$6ab053e5ebee8c56bce5705fb1e03bf8cf99e2930232e525befe1e45063aa2e30981585020a967a1c45520543847cdb281557e16c81cea9d329b666e232eeb008dbe3e1f1a181f69f073f0f314bc17e255d42aaa1dbab92231a4fb62d100f6930bae4ccf6726680554dea3e2419fb67230c186f6af2c8b4525eb8ebb73d957b01b8a124b736e45f94160266bcfaeda16b351ec750d980250ebb76672578e9e3a104dde89611bce6ee32179f35073be9f1dee8da002559c6fab292ff3af657cf5a0d864a7844235aeac441afe55f69e51c7a7c06f7330a1c8babae2e6476e3a1d6fb3d4eb63694218e53e0483659aad21f20a70817b86ce56c2b27bae3017727ff26866a00e75f37e6c8091a28582bd202f30a5790f5a90792de010aebc0ed81e9743d00518419f32ce73a8d3f07e55830845fe21c64a8a748cbdca0c3bf512a4938e68a311004538619b65873880f13b2a9486f1292d5c77116509a64eb0a1bba7307f97d42e7cfa36d2b58b71393e04e7e3e328a7728197b8bcdef14cf3f7708cd233c58031c695da5f6b671cc5066323cc86bb3c6311535ad223a44abd4eec9077d70ab0f257de5706a3ff5c15e3bc2bde6496a8414bc6a5ed84fe9462b65efa866312e0699e47338e879ae512a66f3f36fc086d2595bbcff2e744dd1ec283ba8e91299e62e4b2392608dd950ede0c1f3d5b317b2870ead59efe096c054ea1", "123" },
	{NULL}
};
static struct fmt_tests tests_sha512[] = {
{"truecrypt_SHA_512$73f6b08614dc4ffbd77d27a0815b0700d6b612f573ccd6c8937e8d154321e3c1c1c67dd348d4d3bc8304e94a3a6ec0c672de8396a9a6b26b12393195b7daa4225a9d3a134229be011f8179791bb00c31b5c132c8dbad5a6f8738487477c409b3c32d90b07be8d7a3a9faa95d37ab6faccc459d47f029e25adcea48cee83eaa35b7acc3f849717000421d92ac46e6f16ec3dccacd3ffae76a48280977d2a6727027d9d6ff9c4c98405359ee382f6dd1eca0d7007cbe804b81485c1085e74b58d3eb1e3c7ebdc1e1ab1384e4440ab6ca7beed7e0ef7d1e0da5ffc3cd89f7b6ac8a9257ee369d397ac1e112f75382ddbe6f7317ec20c46cb7b2111d0d91570e90b4c01a0b8205fcdf4d0cadcf4a067b8f285a541f1d649894fb3ade29a2ee0575524455d489c299dde215bea3254f7d43aa4e4011a39bdb6e7473bc29f588e659fdbf065cc4a336ba42f2b6c07479cf3e544978150fb013da7db22afcb4f8384e39e2edfa30a4cbe5e84a07c54ba66663bb9284836cc5a8ba7489d3f7f92aec6d9f4e264c90c2af6181082bd273197bc42c325cb1de31006dd55425e3f210d2ddd7973978eec865d3226bb1e30a9897146d90d79a73070e87f0182981ea85f15f948ae1958af7704fabecd6f07e20be70be9f9c38a5c5e5c8b17be648f011b2c40f62d6ac51de932add5bdb47bb428fd510b004a7aa79321b03ed7aa202be439fbf", "password" },
{"truecrypt_SHA_512$cfd9e5757da139b32d117cd60f86f649400615dc218981106dfadd44598599a7ec0ace42de61506fe8d81b5c885861cdb26e0c38cb9adfcff27ba88872220ccd0914d4fa44bab5a708fe6864e0f665ac71d87e7e97b3724d610cf1f6ec09fa99da40126f63868654fed3381eaa8176f689e8e292c3cb68e43601d5804bc2e19d86722c21d42204e158b26b720e7b8f7580edce15469195dd7ed711b0fcb6c8abc253d0fd93cc784d5279de527fbdcfb357780635a5c363b773b55957d7efb472f6e6012489a9f0d225573446e5251cfb277a1365eed787e0da52f02d835667d74cc41fa4002cc35ad1ce276fbf9d73d6553ac0f8ab6961901d292a66df814a2cbda1b41f29aeec88ed15e7d37fe84ac5306b5a1b8d2e1f2c132e5c7d40ca7bb76d4ff87980ca4d75eaac5066b3ed50b53259554b9f922f7cee8e91847359d06e448da02cbeeecc78ca9bee2899a33dfa04a478ca131d33c64d6de5f81b219f11bed6ff3c0d56f26b3a27c79e7c55b6f76567a612166ce71028e3d3ae7e5abd25faec5e2e9dc30719baa2c138e26d6f8e3799a72b5e7b1c2a07c12cea452073b72f6e429bb17dd23fe3934c9e406bb4060083f92aa100c2e82ca40664f65c02cbc800c5696659f8df84db17edb92de5d4f1ca9e5fe71844e1e8c4f8b19ce7362fb3ca5467bf65122067c53f011648a6663894b315e6c5c635bec5bd39da028041", "123" },
	{NULL}
};
static struct fmt_tests tests_whirlpool[] = {
{"truecrypt_WHIRLPOOL$5724ba89229d705010ec56af416b16155682a0cab9cf48ac5a5fdd2086c9a251ae4bbea6cfb8464321a789852f7812095b0e0c4c4f9c6d14ba7beedaf3484b375ac7bc97b43c3e74bf1a0c259b7ac8725d990d2ff31935ca3443f2ce8df59de86515da3e0f53f728882b71c5cc704df0c87c282a7413db446e9a2e516a144311dd25092eb0a2c5df0240d899708289fc7141abd8538fa5791d9f96c39129cce9fe8a6e58e84364e2f4acc32274147431cb2d2480b1b54bffee485acee0925852b8a6ee71d275f028b92e540be595448e5f1d78560a3b8ad209962dd5981d7ca98db9a678a588a9296157d44502cd78f9e32f022dddc9bc8111b5704ee39a9b56d30b89898ae340e90f2e6c73be6ac64de97e32fc2eed0b66dcd5c1553eeab3950cf851624a5a4439435a6fd5717fda6d5f939f4a902321341964c16bda8975752ba150fb9d858d8eaff2a2086cb50d30abff741ee20223b4223b1783f0ed537a609a081afed952395ef0b5de6883db66cbb5a8bac70f2f757c7b6e6bb5d863672820f0d3d61b262b2b6c2ca0dc8e7137851aa450da1c1d915e005bff0e849a89bf67693ef97f5c17bf8d07a18c562dc783274f9ec580f9519a6dd1429b66160ddb04549506ad616dd0695da144fa2ad270eac7163983e9036f1bde3c7634b8a246b8dcd518ce3e12b881c838fbce59a0cfdffa3b21447e3f28124f63549c3962", "password" },
{"truecrypt_WHIRLPOOL$0650595770851981d70b088ff6ef4bf90573e08d03c8cac8b2dfded22e1653f5c45103758c68be344fdccae42b4683087da083a3841b92fb79856798eaee793c04cd95ae556d9616684da17e47bd2f775d8128f94b80b781e4cab4921b12c620721cf719ca72d3997cea829fd29b429282b597d5719c13423cdf7bd717fa12a56b8eddcf7b1ad2796c4ad078ab3a9bd944a694aa4b0078ed160440dd3db13dd1d04a7aaaa4dc016a95bd1cfafcd833ae933c627bf5512ae55c76069af7190823dba0133d6fe02e4421d3684ff2a2493da990a3cc5eed40a9e8c48c7a89a2f47030d45c324a3d78b941e772e24b285af6739ae1f5953ff838edaa69e79939f55d0fe00cd0e3a20a46db3a232009eabc800711342f7e580ba909f16c2039d4900fd4025845a385641a6037ceb6420fe7d37868e8c06e6146eddec9e6cb97e71048da5fa5898dac08152516ea1c6729e85d31596cd226aa218ce693989efb9fa8b05404bcc2debbc75c429a03fe31bfc49f10d595b898436ff6b02fc01d745b91280f26ae94a4969ce7f86c12e6b562c7b5377e3fb3247a8cda11a930c2a9e80f24966925de01afad5987ebee9c3de1d41667c6dc35cebbbc963f263c700d06a647ab7020385e3a7e30406f3e7a9b3142d39e0439c98948134d11166b621dfd3ea9d3a84d985b2aa7732b7ad9beba44334dd86292b0c94befb2cb8aa72a823129cb", "123" },
	{NULL}
};

struct fmt_main fmt_truecrypt = {
	{
		"tc_ripemd160",						// FORMAT_LABEL
		"TrueCrypt",							// FORMAT_NAME
		"RIPEMD160 AES256_XTS",	// ALGORITHM_NAME,
		"",										// BENCHMARK_COMMENT
		0,											// BENCHMARK_LENGTH
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UTF8,
		tests_ripemd160
	}, {
		init_ripemd160,
		prepare,
		valid_ripemd160,
		ms_split,
		get_binary,
		get_salt,
		{
			binary_hash,
			binary_hash,
			binary_hash,
			binary_hash,
			binary_hash
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash,
			get_hash,
			get_hash,
			get_hash,
			get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_truecrypt_sha512 = {
	{
		"tc_sha512",							// FORMAT_LABEL
		"TrueCrypt",							// FORMAT_NAME
		"SHA512 AES256_XTS",		// ALGORITHM_NAME,
		"",										// BENCHMARK_COMMENT
		0,											// BENCHMARK_LENGTH
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UTF8,
		tests_sha512
	}, {
		init_sha512,
		prepare,
		valid_sha512,
		ms_split,
		get_binary,
		get_salt,
		{
			binary_hash,
			binary_hash,
			binary_hash,
			binary_hash,
			binary_hash
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash,
			get_hash,
			get_hash,
			get_hash,
			get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_truecrypt_whirlpool = {
	{
		"tc_whirlpool",							// FORMAT_LABEL
		"TrueCrypt",								// FORMAT_NAME
		"WHIRLPOOL AES256_XTS",	// ALGORITHM_NAME,
		"",											// BENCHMARK_COMMENT
		0,												// BENCHMARK_LENGTH
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UTF8,
		tests_whirlpool
	}, {
		init_whirlpool,
		prepare,
		valid_whirlpool,
		ms_split,
		get_binary,
		get_salt,
		{
			binary_hash,
			binary_hash,
			binary_hash,
			binary_hash,
			binary_hash
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash,
			get_hash,
			get_hash,
			get_hash,
			get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif

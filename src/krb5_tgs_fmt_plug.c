/*
 * Based on the work by Tim Medin
 * Port from his Pythonscript to John by Michael Kramer (SySS GmbH)
 *
 * This software is
 * Copyright (c) 2015 Michael Kramer <michael.kramer@uni-konstanz.de>,
 * Copyright (c) 2015 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_krb5tgs;
#elif FMT_REGISTERS_H
john_register_one(&fmt_krb5tgs);
#else

#include <stdio.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "formats.h"
#include "common.h"
#include "rc4.h"
#include "md4.h"
#include "hmacmd5.h"
#include "unicode.h"
#include "memdbg.h"

#ifndef OMP_SCALE
#define OMP_SCALE                       256
#endif

#define FORMAT_LABEL                    "krb5tgs"
#define FORMAT_NAME                     "Kerberos 5 TGS"
#define ALGORITHM_NAME                  "MD4 HMAC-MD5 RC4"
#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH                0
#define MIN_PLAINTEXT_LENGTH            0
#define PLAINTEXT_LENGTH                125
#define BINARY_SIZE                     0
#define BINARY_ALIGN                    1
#define SALT_SIZE                       sizeof(struct custom_salt)
#define SALT_ALIGN                      4
#define MIN_KEYS_PER_CRYPT              1
#define MAX_KEYS_PER_CRYPT              1

#define MAX_EDATA_SIZE                  2048

static struct fmt_tests tests[] = {
	{"74809c4c83c3c8279c6058d2f206ec2f$78b4bbd4d229487d5afc9a6050d4144ce10e9245cdfc0df542879814ce740cebb970ee820677041596d7e55836a18cc95c04169e7c74a4a22ae94e66f3d37150e26cc9cb99e189ef54feb7a40a8db2cb2c41db80d8927c74da7b33b52c58742d2109036b8ab27184609e7adff27b8f17b2f2a7b7d85e4ad532d8a70d48685a4390a9fc7a0ab47fd17334534d795abf83462f0db3de931c6a2d5988ab5bf3253facfff1381afb192ce385511c9052f2915ffdb7ea28a1bbad0573d9071e79dc15068527d50100de8813793a15c292f145fa3797ba86f373a4f0a05e5f2ec7dbfd8c8b5139cc7fbb098ea1dd91a7440134ffe2aff7174d0df13dcad82c81c680a70127a3ec8792bdecd74a878f97ff2b21277dc8c9a2f7bbcd9f72560dd933d85585259067d45a46a6f505d03f188b62c37edf03f117503a26743ebd674d5b07324c15fc8418881613b365402e0176da97d43cf85e8239b69aee07791233a959bcaf83a7f492fa718dd0a1747eaf5ce626eb11bda89e8235a056e2721f45c3b61442d893ef32a8c192ea0dadb853f3c6f3c75e92f23c744605c6f55578f696b0f33a9586b8aae3e12e38a097692cd9a31d780d973eaaf62ef23b2fc9ae59a38bfd8ea14d3289b46910f61a90aa733e66382bc27f40ba634e55ef1bec0ca7f71546b79566d85664b92f9fae495fcef5cde4c4399a6798569a7e81b9cc4bdde7104f3fe181401f82bba944e3b0a406c7093c00ff9d5984a82517b1a64a8aa561bc1f0cbafbdbbc5654d375c91d4e485e17bb06838109fbc1504147481c91652f545086a84daa423a6286ea6bb13460c5ff3d865a7b37b9ce4e7b07fbe2f6897c12c1e4df2e875c1ec9cfbf84097a7f48b270baf3481263b21849ab93c231490d06a23461a5e00c23df76bca8e5a19256d859304e1f5752bf055ac7f4843e1ad174f1cbbf5c142958f9310025ce439d5979982fb0b8c2ea95e1a22ee8dc63423d9d364cb0b95bcdf89ec4ed485b9005326d728757d77aa3e020a4a61d7deb782bc5264dca350173609772cd6d003ee8104dd24d310c9a18a44f78e27d65095f5bb54f6118c8f0d79ad5a850cec8d40a19bd0134144e904c9eb7fdcff3293696071fc1118f6b2f934281a25bcd5ca7d567714b1e43bd6d09bfcc8744c0ca273a75938394ac2fb31957287093346078577c94a71dfa6ad4a63211f54f00ef7a9064d070aaff84116ee891728915c938a8a32e87aaa00ec18e2b4e9ae88f7e53f08d855052a995f92351be32d8df934eab487103b0f089828e5fb5f73af3a8a05b9fffd25c43a392994743de3de1a2a9b8bba27e02ae2341f09d63aafab291759c41b9635521ca02f08e21e7e5c3ce75c8c3515eaa99aeb9bf8e204663e8b6b8507ecf87230a131687b4770e250ba0ef29fa3ca3b47b34971e17c6a3ef785acdd7c90da9d2", "test123"},
	{"ee09e292a05e3af870417758b1cdfd04$a1a480b8505d2f2f0ff06ddce40c2f6e76bd06fa64dcd5b0646a68effcd686b2e41562ebda90da7e7b36d95cd16ca8a33b8d99184d6b7fa7a2efec3a05dcb63b3e815ffd38849dc69174d1efb3a871544b73a6da55d2331bd4b60743d1654873e3c1748ce155c35a1711695296ab944d158e374b67f43dd07eab2bcacec1be480e5c1338e3834f7133909f5c7970ece39e73bd96d40f696cb5a8575e5e1feab937b616d6180cc3258e22b9fc495017593e15fc10e674af8184c282a0d80902ea9dabda5fb0a56d7980bfd4b62b330155cd8e318dc5be55500cb8ddd691b629af371463c411f1c11d21811e1546477b85f0a85e296f5df737930aff5015111d2f01a236ab7c77e9dab001f52400cccbcdb31bb180db027bd0fa2f6000dce7c1e072c0effbdee23a401720b1fe54a09a75430497f42f6e047d62d1123866d6ed37e58f8e2c1e462acb1a97a44a5ccef49897af190a46b3ab057d18c1e47d717c7a63658357d58d9cd5b7672f0a946f95f6e2ec3aee549e20e3b11237ea59f87723f24e03a6fac9e51086bc84142631ed36ee6855920f3d3d1e85d0faaa0a8b04a2b050b17f94d44af7f48302fa70dcf43279415983924e5d874c59722b6fb87ad1006fcb51e4341bb2cc4caf8c4b7993269af219cf4efa12b1009961c22f123c35f982e4ca75a97cd37f7f16be111ad301637ffb1664ccb021d3cf6bf771e07dc42202dac079c6bd7559f8e7a939bc14e9ddb45fe1b88c5f83b1ff966342bb9211afd15772cf5f871d39d0b30776d51d84b046df30d250c1877d146047e784c4bc2e6745f357dd0b1c6aaa11e26a0e3c2772781695f6a3bc536ba19e2327ec8c0866bd78d3b5b067abcf6991eafc8b7a11ad4049711263f3c68b358f246da1308d5a0daac1d7efedbc237be3d6a4bafe5ce66e941f7227d2b869bda637dfd223a4546340c59e7d0e2b58f60a67590468a53a5d28cc35cec36a9c5610c70c0633767539640b42cff787f4782057ff70d0e64658413429347f5449c1360da4d0827c4197bbb0361c6d0e04bcaf6bba1233912f806772146c0e778ac06749bbd3d8819007d070ae912580ff11a41f71b0907b88fb585585ebe42b4cc4ecde8ff7b49a856dd70f316425e53feff3ee6ca1e44d9ba5e607a41cf26edf44bffe2796f94ea2d767fbf81f665a7fedf0291e76c6fa409dc99c56954f21edc77f6173c5a3a909c8756f3cc5cc6c2d2e405f333ee0b50284aacfb81f9dfc6058b78b282db4511580eb623dc393919befc250d224490936e5fb16c483f4bd00c8915288d0ddf3812eaa3d46ad5a24c56390076730d23b2de6558ddadddba725f9b4a73d13de3e1276fc285194e3a2f613d9b020d0485d7e26b36b7b917f4911024127320627066fabbd465b4cd5d5fdebae804d15db0f5b276659364bec32a13a8d9e11349f54bd", "bluvshop2"},
	{"423cb47a258e5859c13381ae64de7464$8dd47d94e288a1b32af726d2eac33710fb1610e4c6f674907d7a74d26515a314173b2b531baa790b70467ebe538fc9e941bf4d7f7218a4ec17c1dc963b717d5837fcd5ae678189101a1b4831a53a1322ca6e8f5d644e4aa72e99bedb4a0e967c3e05ccdcc96137265612969a1214a71038dea845250cac45551963fe85f193d88aa39ed57b95b934295e17de04ebf0ad275df67f65fb1fc2ee3095c6af02c4c1b8efa570e1c2ac562601c5ac89bd6f59ca8b957660aa00787d4a0f9d9f29b15eb3b85823f7c9814eab9106210c37d863cf8413391c5941a994fdd52a44e4f8e8e4c9b8b520e62015fb5ed40e91e7a453b3ddcefb888fd896c187993a899b6a30d27a5b2b7847a410c0cce8b0fcf90367bfd8e6dfa7eb37676ecdf500c9a51ffb59792c13e222371e024f857134b7039931daa66a6902da37e71c41adf83846a9df1e75575696d7a6f1744d48e8215849773903c9475c29a1ec0fcc11257f9479467c2b65679a3da298e6806d619794dfc06b10b5e0a46e395c3ade3d750292f244cabb7172d83dbd42c6e3bd5a93a8c2d5fe84b23a3c60508733f5a087763f2fa514d18f891461b8ea22f7eaa847906182bd0415c28d197c06df8449cc2c6c2016c38672a67613a14ccac9025c4da85fc0825dcd9a1269e6064f80c0de445fbdd237d35ab0eb6ae468413c5b17c9955a8c8c34952c8a188bad7e5b18651a75b1c46cf116422378a94a19c31dfa634c8ab15f4f13e7e427741ab9e8f247b4a8fe2562986ee21f602b4fad45bd535718020b764da6f346e3b028db8a1af88419f3ea9141fcf0c622ed40d894814e5d60a9dcdfc8344f802c7b2f0089131e57ac0cc071af13c3b2b7302e9df4665c48b91f4ef0bb2a60a272e5841e0ee8da01a91773d41f295514b65ccb2190195f720d9838b3e7c701b51e813ef0262fbdbbe06391ba3fe4232e74523dfa933e6d3df2494ddd9f254afdf97623ceb5d32483a870cf72a57617bdbf97f0420c041edb5a884ff401dc21da0472d7a75d89dc9937fd65c3a422063ea44e3954435d38b8f34cec2c0360c8bef392f77fbab76a7b801e05b467d4980d20f0a7dbc1c39f50ce4429df1ec167c6be67d2fbd507a3f7b5d98cf214ae0510fac51e1075a06250d65a3a1179486bda5d982b7904682835079e3042f39a582492cd14dbafb5826e242c81998752043e2dd91b648f115900595f5191a01f187c4b6dea4917e4773a5fb28cb1d20508142a3905068c931a8c9a8fa291b92f8ece9884affd8787a5aa11858274879160e930587f3c32e2cabbd124c708641df09f82d05ab4db157ad24931dc36c616dbb778762ead6a8491ce8a48037106d382283ac69422c04af3ae2cbe22eff6dff21bc34b154a5fab666870c59aba65bd4e0ea0be3f394bb4901fd64a0e19293b8026188615c84601b7fecdb62b", "jlcirr."},
	{NULL}
};

static unsigned char (*crypt_key)[16];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*saved_K1)[16];
static int new_keys;

static struct custom_salt {
	unsigned char edata1[16];
	unsigned char edata2[MAX_EDATA_SIZE];
	uint32_t edata2len;
} *cur_salt;

static int valid(char *ciphertext, struct fmt_main *self)
{
	int len;

	if (hexlenl(ciphertext) != -32)
		return 0;

	if (ciphertext[32] != '$')
		return 0;

	ciphertext += 33;
	len = hexlenl(ciphertext);
	if ((len & 1) || len < 32 || len > (MAX_EDATA_SIZE * 2))
		return 0;

	return 1;
}

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	crypt_key = mem_alloc_align(sizeof(*crypt_key) *
	                            self->params.max_keys_per_crypt,
	                            MEM_ALIGN_CACHE);
	saved_key = mem_alloc_align(sizeof(*saved_key) *
	                            self->params.max_keys_per_crypt,
	                            MEM_ALIGN_CACHE);
	saved_K1 = mem_alloc_align(sizeof(*saved_K1) *
	                             self->params.max_keys_per_crypt,
	                             MEM_ALIGN_CACHE);
}

static void done(void)
{
	MEM_FREE(saved_K1);
	MEM_FREE(saved_key);
	MEM_FREE(crypt_key);
}

static void *get_salt(char *ciphertext)
{
	int i, len;

	static struct custom_salt cs;

	len = (strlen(ciphertext) - 33) / 2;
	for (i = 0; i < 16; i++) {
		cs.edata1[i] =
			atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
	for (i = 0; i < len; i++) {
		cs.edata2[i] =
			atoi16[ARCH_INDEX(ciphertext[i * 2 + 33])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[i * 2 + 1 + 33])];
	}
	cs.edata2len = len;
	return (void*)&cs;
}

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32*)salt & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	const unsigned char data[4] = { 2, 0, 0, 0 };
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char K3[16];
		unsigned char checksum[16];
		unsigned char ddata[MAX_EDATA_SIZE];
		RC4_KEY rckey;

		if (new_keys) {
			MD4_CTX ctx;
			unsigned char key[16];
			UTF16 wkey[PLAINTEXT_LENGTH + 1];
			int len;

			len = enc_to_utf16(wkey, PLAINTEXT_LENGTH,
			                   (UTF8*)saved_key[index],
			                   strlen(saved_key[index]));
			if (len <= 0) {
				saved_key[index][-len] = 0;
				len = strlen16(wkey);
			}

			MD4_Init(&ctx);
			MD4_Update(&ctx, (char*)wkey, 2 * len);
			MD4_Final(key, &ctx);

			hmac_md5(key, data, 4, saved_K1[index]);
		}

		hmac_md5(saved_K1[index], cur_salt->edata1, 16, K3);

		RC4_set_key(&rckey, 16, K3);
		RC4(&rckey, cur_salt->edata2len, cur_salt->edata2, ddata);

		hmac_md5(saved_K1[index], ddata, cur_salt->edata2len, checksum);

		memcpy(crypt_key[index], checksum, 16);
	}
	new_keys = 0;

	return *pcount;
}

static int cmp_all(void *binary, int count)
{
	unsigned int index;

	for (index = 0; index < count; index++)
		if (!memcmp(crypt_key[index], cur_salt->edata1, 16))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(crypt_key[index], cur_salt->edata1, 16);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_krb5tgs = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		MIN_PLAINTEXT_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP,
		{NULL},
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
		{NULL},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		salt_hash,
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

#endif							/* plugin stanza */

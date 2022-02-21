/*
 * Common code for the FreeBSD GELI format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "geli_common.h"

struct fmt_tests geli_tests[] = {
	{"$geli$0$7$22$128$0$1$256$31700bceaad80bc02f27644572288e765bd9356528f2a0eeef8144d8c1381a0da7ab32ec2570b254e57218924defaa0e233a55de818d8e97ae8c28cb85bc2842$a55f6782b63a048a3c39fec977e98c6387d6c64cf5be427cd450ecd9f5294834754f058edf3b62f64f3ba7b07ac1d769df17dcd6464330970e55f5c580885cde2d7bd544cd7946e3f9a47f3643f03687504f38ed7745024fd5039043e41a9f57cd238787c8dea0c32be72e82e6a20d3094a7a524d2cf36cc47b71bc663782e7891db3fb5c68ec4c29ac7cb19b2f9b157f69faceec4ed858b46d916a370f2b2c7fd5fb15bb45c72bd6da02de37094c59758ab9e3980f6f82ce178c5e050fd1737bf8bf8c00116d055e273b3ea7fa93aa96baade62815ca1e99639909059b5f09c34ddd7052b6a1384fc5908265dbda25c63efa473146674e39b765e1dcb4f85f6dea081f84f95b97897e1634e44120967808b2377f417befded2d4366c7ba1de28f973fb01d5627817b53a43f214ae82b1db1c3a5424fb8ae43118eb8446bc16d1f8f829ecd6165a4ad87ff715033a0d16ea8898c11705c06564012fb1e0bf4599989e65d203158e519b17fbff2df2ccc3455bbf29bdce8cae5b9399822243416", "openwall12345"},
	{"$geli$0$7$22$128$0$1$512$e59f8b6db2de8cb2db44ffc96473a9296929d9d17817ac8456a26bcee7e99af1131a117f2c297e59cba29e00e22404ce2db9991fb12437ac54af7c0050194a72$e02367a7fed99c219d516a072a29db7c3712f3bef7d5c6b6308d76b837a041f99f7742fef97502b73e30ba78ea8eaf0c2b16dc506e96c1e5523209f4ca9184d2dae4a31934d43c4160004e9c1fffda5c829befcf1f359ed416237262894d3a7269a0a6d67ffaee96e784c644c66005415b74c7ecbb98df3ec3e0773b3f452b612f13ce94712ffe04c02980c2e9ec55731d818f9b89c4e0da85114be8a5ef6461b481d87d09048e2f7189ffb751c0b5144f6e876a462860de6142e1bd6e6c1dfdadafbed1301962bcbb62f486f7947b1dbf8d87ef1af80928da395ccb815bc2183414bcaa2528c0b2436e4317bdb377b3b84163c3584b0c51bbcd6909c9e46096bd7e387fd0174bae07459d096b9c20ebc0b304013b42e7f8953b625c815db62957cb01474da9a8d341e4b344cf08e3b757f416a50431ab45136044cf7afe855e9ac1a95e5223dc01f86cb51177cb713a971479a766de0b75e43ee3d5f43ca61c31b4cb8c2689858f70e7a20c2ace2069ba4e59313f974bffde54562610b1f0bd", "♠"},
	{"$geli$0$7$22$256$0$1$100$0692854a6e44682591486f6843c3c587734e7a753a8f945a6a252f981327dd7bd54e435d47f73deeeb037248d1ddca6ecbd7eb2d878e672a24e6467f94833398$3934fc99effb89e1f1d5458b40d3388b5aa68408222ed8266b3605b224f23fc0c47bc2d4adbb40df4ed621fcfe5fb6259e574bf5de938755d2503c77c95191737726f5e8df2063b54af36f80b532dcc99670aced998616fcf1d41b2cbca238eb044f82f568b9ff1244b9993b318aacbf7100f6ebc2f60a34bd899bc6458fa164c160815eca141731d8375a4aab327c135cba306f4f714550c591b0dfcdd588687277edd9b1d42deb90493d6c65223c82839319fb3482e763728d9ab4a48f6190fbe4e1d18bb99ee58d5f20590662ea4d8ea43ea9dfde22894722ba6f04ce41812d826d2d40a6b2c0f41ee44900b30e5e4e12bbe9dbe8987b0d3ff064af5a7722c21d4328114b250f22e278c2a402865a1fcb8ceead5fa0512dfc42ead1ce92029eafbce80926541ab605da644f25df19adf9907c95e32427ebd1d3746c6719cabbc994fa91ad8a7023630d2c2ec043dcfe3e209dbfddbdf4c55760ea01953677088e956182dc672ead45a9225ec27bbb8f189a2f900e7caa3a9cd5f805f262bd", "Trounce1"},
	// the following two test vectors are more realistic (they are disabled to reduce testing time)
	// {"$geli$0$7$22$128$0$1$1073769$5a12045bee0059aa057b2970ef03252d3731c824732f2fe9537852165cd290501000224e88c954923479061d80500c71a99c97703a29109955d60915ab911220$c8cb6fcdf910aa45dd0557edfdeb3d2fa74dce79bb12ab978c4165fab2884cb9c4db3be988aa5d4ca0023d8472b8a4d3b43c6f3f0bbf1512ceb12a2d54b8caf9eafb422bad919d17b911f35f8870e98c2b7427b85a201d913745fa617f06016b4699d18d10894b6fa2190f525b9adad6a9b3826e943d6eb92b24e7469f574aa9481d0b36003eb4ccfa9e10bea0361c0e1705dd62706da3fca42f0c050bdf871c5ed38173ca9a2cea5548e5f2c9a85777f5915ec77f8e442e3237c803aed469dd962a8945aa7500b53395a41b4cb3bfdf7f8bfdf57052064f0ed9e7fc277bb5bc66999dbf659f154d95464a4bf4c53f005d2032c2171682d5fa7d8b931dba6cbee7df6258412e44ce24cf81acaec5d51de3fbd787b515705cea7106ef94ccbe650bca6ed5599427b873e9dd194650d5eeccc9bbc8fe8e405e62057070419ae3f231ea69cac4485aa7bb7a364d1cb0e4087d3be9a3fec4916683f5e362d1223ba5425aface02eda864522f5f55fdf95a9736e138e2ac608e618aa1d4e22bb0d962", "openwall"},
	// {"$geli$0$7$22$128$0$1$1007284$a9940c43932b609eb8b254bed2aba3809fb177d141a09109880f62ec51ba4fdec873d340f6d83810230e33fd16c7d61b2d0877e3f9133056c61f332df0dd6f72$cb40750d686c11699fb667675f45ee138d3d01834ae46619e4c150467405fb542dae9e28e753045cc6cb258b734c828a7bf1ce654d62e35e435ddc942eaed5a1823500fef6b4c4f3af501aef771035fac7a15d89e09a90252365041ede11f9ad5b5fef0671da74bd442a6b4d96b6dcc4f50ef5c60c13fb30856c3d915adab6746b8de94013b4e38e7d2a1f18fca3807a1d02871438e3894243658a3ee7cf656bc39f7ce5df06d4a435ce8d93e6a956ebcfb9594262f99000f5b413071f6bdf59b14f885b2318565a654431d6a01789ef4b18873126bd140fc0f11b8020fdcd86cf9334ab992328334a2432f06be90ab1434bc72e2294db8add242e94bcfbc94b87305419bbb9b3ba44b6776c75194dcef1c8ba6e0c9433745f614e88eff253098c3115e01f48ab010e5f0f2d3c6e2af9b33f07b5712ff260aa7e3128e4443f4fce42c629ff3e2a7f19744d1dc80267bdf826e56614a18662e873b33efaa146428faec5b66c7aac0003a8a33fff6cdfe70e9998c559bb2cfc073999e224e6ec19", "openwall123"},
	{NULL}
};

int geli_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // internal (to JtR) format version
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // md_version
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value > 7)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // md_ealgo (encryption algorithm)
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 22 && value != 11)         // CRYPTO_AES_XTS, CRYPTO_AES_CBC
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // md_keylen
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 128 && value != 256)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // md_aalgo
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // md_keys
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // md_iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // md_salt
		goto err;
	if (hexlenl(p, &extra) != G_ELI_SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // md_mkeys
		goto err;
	if (hexlenl(p, &extra) != (G_ELI_MAXMKEYS * G_ELI_MKEYLEN) * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *geli_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static custom_salt *cur_salt;

	cur_salt = mem_calloc_tiny(sizeof(custom_salt), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	cur_salt->md_ealgo = atoi(p);
	p = strtokm(NULL, "$");
	cur_salt->md_keylen = atoi(p);
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	cur_salt->md_keys = atoi(p);
	p = strtokm(NULL, "$");
	cur_salt->md_iterations = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < G_ELI_SALTLEN; i++)
		cur_salt->md_salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	for (i = 0; i < (G_ELI_MAXMKEYS * G_ELI_MKEYLEN); i++)
		cur_salt->md_mkeys[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);

	return (void *)cur_salt;
}

unsigned int geli_common_iteration_count(void *salt)
{
	return (unsigned int) ((custom_salt*)salt)->md_iterations;
}

// Based on "g_eli_mkey_decrypt" and "g_eli_mkey_verify" functions from FreeBSD
int geli_decrypt_verify(custom_salt *cur_salt, unsigned char *key)
{
	AES_KEY aes_decrypt_key;
	unsigned char iv[16];
	unsigned char enckey[SHA512_MDLEN];
	const unsigned char *mmkey;
	unsigned char tmpmkey[G_ELI_MKEYLEN];
	int nkey, bit, ret;
	const unsigned char *odhmac; /* On-disk HMAC. */
	unsigned char chmac[SHA512_MDLEN]; /* Calculated HMAC. */
	unsigned char hmkey[SHA512_MDLEN]; /* Key for HMAC. */

	// The key for encryption is: enckey = HMAC_SHA512(Derived-Key, 1)
	JTR_hmac_sha512(key, G_ELI_USERKEYLEN, (const unsigned char*)"\x01", 1, enckey, SHA512_MDLEN);

	mmkey = cur_salt->md_mkeys;
	for (nkey = 0; nkey < G_ELI_MAXMKEYS; nkey++, mmkey += G_ELI_MKEYLEN) {
		bit = (1 << nkey);
		if (!(cur_salt->md_keys & bit))
			continue;
		memcpy(tmpmkey, mmkey, G_ELI_MKEYLEN);

		// decrypt tmpmkey in aes-cbc mode using enckey
		AES_set_decrypt_key(enckey, cur_salt->md_keylen, &aes_decrypt_key);
		memset(iv, 0, 16);
		AES_cbc_encrypt(tmpmkey, tmpmkey, G_ELI_MKEYLEN, &aes_decrypt_key, iv, AES_DECRYPT);

		// verify stuff, tmpmkey and key are involved
		JTR_hmac_sha512(key, G_ELI_USERKEYLEN, (const unsigned char*)"\x00", 1, hmkey, SHA512_MDLEN);
		odhmac = tmpmkey + G_ELI_DATAIVKEYLEN;
		// Calculate HMAC from Data-Key and IV-Key.
		JTR_hmac_sha512(hmkey, SHA512_MDLEN, tmpmkey, G_ELI_DATAIVKEYLEN, chmac, SHA512_MDLEN);

		ret = memcmp(odhmac, chmac, 16) == 0;
		if (ret)
			return ret;
	}

	return 0;
}

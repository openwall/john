/*
 * Common code for the Ethereum Wallet format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "ethereum_common.h"

struct fmt_tests ethereum_tests[] = {
	// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition, v3 wallets
	{"$ethereum$p*262144*ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd*5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46*517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2", "testpassword"},
	// scrypt test vectors are disabled to ease CI testing
	// {"$ethereum$s*262144*1*8*ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19*d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c*2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097", "testpassword"},
	// {"$ethereum$s*262144*8*1*8de58242f1ab3111ed0ac43c35c8f0f26df783d3188cba906fd3cd33f7ded6b6*542e5f4563a5bb934c8c7caa39005e2cd8f1df731292392e4b006b1660e329df*2d05b6d31adb87243e6cdd9459912d6ddbf25e4bad7160def3e9dd6b3aa5989d", "openwall123"},
	// {"$ethereum$s*262144*8*1*089f8affe040ed0edaa7a238d505e235cf062262c1a4b8ce1b4fe1c8eb3f3eb7*2dcb06464c6fe2ccfd8eaef921fedceef68fa72e92d786e6272a8f66ecf9476c*9225bc94b0ff28e364a6f607d9213cd573eed178df19a9a08706603e61d93487", "password"},
	// {"$ethereum$s*262144*8*1*9daee6a42109e1facefe1f4c3db5452aba6d82f46d2fc15bde4923870e0f83e1*5be4a57d3629c36973186c78e2935e02cf38907c6531ae98400469f0291056be*ca58b99dfdf696af880c242410f22a55de2047b97e56562cd90ec1c38f1749c2", "openwall"},
	// MyEtherWallet (https://www.myetherwallet.com/)
	{"$ethereum$s*1024*8*1*8420bc934c1d6e3c016db11a22e31146b557ce254622135d128f4ed3fd8d86c8*3292ccbb6e3dfe1c1db71c941ec3f91b23726e726fc17708442d491bc824ae38*01af14f1ec3c7f457669c05ec4f56c914f2af39f23c6ff2a8c25d3e0d02500f8", "password123"},
	// Mist 0.3.9
	// {"$ethereum$s*262144*8*1*cc48acb99a3c5e5494c46175dfdf13999a93b75285c04c289b1828e4a003c42c*193d41913eae708e545b2e9dbc40d345f3acf6e6ea8ffdfac63d606043c22267*da77eb1ebbb17e471cd397f5b6b31987800790b885d4c807336e6d8eff77b93b", "password123"},
	{NULL}
};

int ethereum_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
		goto err;
	if (*p != 'p' && *p != 's')
		goto err;
	if (*p == 'p') {
		if ((p = strtokm(NULL, "*")) == NULL)   // iterations
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // salt
			goto err;
		if (hexlenl(p, &extra) != 64 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
			goto err;
		if (hexlenl(p, &extra) != 64 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // mac
			goto err;
		if (hexlenl(p, &extra) != 64 || extra)
			goto err;
	} else if (*p == 's') {
		if ((p = strtokm(NULL, "*")) == NULL)   // N
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // r
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // p
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // salt
			goto err;
		if (hexlenl(p, &extra) != 64 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
			goto err;
		if (hexlenl(p, &extra) > 128 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // mac
			goto err;
		if (hexlenl(p, &extra) != 64 || extra)
			goto err;
	}

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *ethereum_common_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static custom_salt *cur_salt;

	cur_salt = mem_calloc_tiny(sizeof(custom_salt), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	if (*p == 'p')
		cur_salt->type = 0; // PBKDF2
	else if (*p == 's')
		cur_salt->type = 1; // scrypt
	p = strtokm(NULL, "*");
	if (cur_salt->type == 0) {
		cur_salt->iterations = atoi(p);
		p = strtokm(NULL, "*");
	} else if (cur_salt->type == 1) {
		cur_salt->N = atoi(p);
		p = strtokm(NULL, "*");
		cur_salt->r = atoi(p);
		p = strtokm(NULL, "*");
		cur_salt->p = atoi(p);
		p = strtokm(NULL, "*");
	}
	cur_salt->saltlen = strlen(p) / 2;
	for (i = 0; i < cur_salt->saltlen; i++)
		cur_salt->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cur_salt->ctlen = strlen(p) / 2;
	for (i = 0; i < cur_salt->ctlen; i++)
		cur_salt->ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];


	MEM_FREE(keeptr);

	return (void *)cur_salt;
}

unsigned int ethereum_common_iteration_count(void *salt)
{
	custom_salt *cs = salt;

	if (cs->type == 0)
		return (unsigned int)cs->iterations;
	else
		return (unsigned int)cs->N;
}

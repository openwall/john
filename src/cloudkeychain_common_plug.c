/*
 * Common code for the 1Password Cloud Keychain format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"
#include "common.h"
#include "arch.h"
#include "misc.h"
#include "cloudkeychain_common.h"

struct fmt_tests cloudkeychain_tests[] = {
	// https://hashcat.net/misc/example_hashes/hashcat.cloudkeychain, some values are dummy and unused
	{"$cloudkeychain$16$c1b981dd8e36340daf420badbfe38ca9$40000$1$00$256$16$237c26e13beb237a85b8eacc4bddd111$272$a7bb7bee7cf71f019df9268cb3751d563d1bebf0331e7def4c26eeb90e61d2c2339b3c2d23ce75e969f250a1be823732823687950be19722f2dc92f02e614352c082d04358c421c1ddc90d07d8c6c9fb46255846ef950f14547e5b72b32a0e64cf3d24646d41b7fdd57534a1dd808d15e8dfe4299ef7ee8a3e923dc28496504cacb0be647a4600797ade6cb41694c2eb4d41b674ce762d66e98895fde98dda862b84720874b09b080b50ef9514b4ea0e3a19f5d51ccb8850cd26623e56dadef2bcbc625194dd107f663a7548f991803075874ecc4fc98b785b4cd56c3ce9bcb23ccf70f1908fc85a5b9520cd20d9d26a3bfb29ac289c1262302c82f6b0877d566369b98fb551fb9d044434c4cb1c50dc$32$92407e964bb9a368e86bcd52273e3f6b86181ab1204a9ed709bbe97667e7f67c$304$991a0942a91889409a70b6622caf779a00ba472617477883394141bd6e23e38d8e2f5a69f5b30aa9dc28ebf6ecedcb679224e29af1123889a947576806536b831cc1d159a6d9135194671719adf86324ce6c6cbc64069c4210e748dde5400f7da738016a6b3c35c843f740008b0282581b52ea91d46a9600bfa8b79270d1ce8e4326f9fc9afa97082096eaf0ce1270eb030f53e98e3654d6fd38a313777b182051d95d582f67675628202dab60f120d4146250fa9ade4d0112aa873b5eb56425380e7b1220f6284ed1fa7d913a595aedfc0159ba2c95719d3c33646372098dc49037018885ed5d79e3479fee47fbe69076ea94852672f04f10e63fe3f53366fd61f7afd41831150cf24a49e837d72d656a1906943117252ab1f3889261ce09c3d832a4d583cfc82a049cee99cf62d4ec", "hashcat"},
	// https://cache.agilebits.com/security-kb/freddy-2013-12-04.tar.gz, This is a sample OPVault file. The Master Password for it is freddy.
	{"$cloudkeychain$16$3f4a4e30c37a3b0e7020a38e4ac69242$50000$336$6f706461746130310001000000000000237c26e13beb237a85b8eacc4bddd111a7bb7bee7cf71f019df9268cb3751d563d1bebf0331e7def4c26eeb90e61d2c2339b3c2d23ce75e969f250a1be823732823687950be19722f2dc92f02e614352c082d04358c421c1ddc90d07d8c6c9fb46255846ef950f14547e5b72b32a0e64cf3d24646d41b7fdd57534a1dd808d15e8dfe4299ef7ee8a3e923dc28496504cacb0be647a4600797ade6cb41694c2eb4d41b674ce762d66e98895fde98dda862b84720874b09b080b50ef9514b4ea0e3a19f5d51ccb8850cd26623e56dadef2bcbc625194dd107f663a7548f991803075874ecc4fc98b785b4cd56c3ce9bcb23ccf70f1908fc85a5b9520cd20d9d26a3bfb29ac289c1262302c82f6b0877d566369b98fb551fb9d044434c4cb1c50dcb5bb5a07ad0315fd9742d7d0edc9b9ed685bfa76978e228fdaa237dae4152731$256$16$237c26e13beb237a85b8eacc4bddd111$272$a7bb7bee7cf71f019df9268cb3751d563d1bebf0331e7def4c26eeb90e61d2c2339b3c2d23ce75e969f250a1be823732823687950be19722f2dc92f02e614352c082d04358c421c1ddc90d07d8c6c9fb46255846ef950f14547e5b72b32a0e64cf3d24646d41b7fdd57534a1dd808d15e8dfe4299ef7ee8a3e923dc28496504cacb0be647a4600797ade6cb41694c2eb4d41b674ce762d66e98895fde98dda862b84720874b09b080b50ef9514b4ea0e3a19f5d51ccb8850cd26623e56dadef2bcbc625194dd107f663a7548f991803075874ecc4fc98b785b4cd56c3ce9bcb23ccf70f1908fc85a5b9520cd20d9d26a3bfb29ac289c1262302c82f6b0877d566369b98fb551fb9d044434c4cb1c50dc$32$b5bb5a07ad0315fd9742d7d0edc9b9ed685bfa76978e228fdaa237dae4152731$304$6f706461746130310001000000000000237c26e13beb237a85b8eacc4bddd111a7bb7bee7cf71f019df9268cb3751d563d1bebf0331e7def4c26eeb90e61d2c2339b3c2d23ce75e969f250a1be823732823687950be19722f2dc92f02e614352c082d04358c421c1ddc90d07d8c6c9fb46255846ef950f14547e5b72b32a0e64cf3d24646d41b7fdd57534a1dd808d15e8dfe4299ef7ee8a3e923dc28496504cacb0be647a4600797ade6cb41694c2eb4d41b674ce762d66e98895fde98dda862b84720874b09b080b50ef9514b4ea0e3a19f5d51ccb8850cd26623e56dadef2bcbc625194dd107f663a7548f991803075874ecc4fc98b785b4cd56c3ce9bcb23ccf70f1908fc85a5b9520cd20d9d26a3bfb29ac289c1262302c82f6b0877d566369b98fb551fb9d044434c4cb1c50dc", "freddy"},
	// too slow for benchmarking
	// {"$cloudkeychain$16$2e57e8b57eda4d99df2fe02324960044$227272$336$6f706461746130310001000000000000881d65af6b863f6678d484ff551bc843a95faf289b914e570a1993353789b66a9c6bd40b42c588923e8869862339d06ef3d5c091c0ba997a704619b3ffc121b4b126071e9e0a0812f722f95a2d7b80c22bc91fc237cb3dfaba1bee1c9d3cb4c94332335ab203bb0f07ca774c19729ce8182f91cd228ae18fb82b17535ecae012f14904a6ace90d9bab1d934eb957ea98a68b4b2db3c8e02d27f7aff9203cdbd91c2b7c6aaa6f9c2ca3c1d5f976fc9ed86b80082ae3e39c2f30a35d26c2c14dbd64386be9b5ae40851824dc5963b54703ba17d20b424deaaa452793a1ef8418db2dda669b064075e450404a46433f6533dfe0a13b34fa1f55238ffea5062a4f22e821b9e99639c9d0ece27df65caf0aaaad7200b0187e7b3134107e38582ef73b6fde10044103924d8275bf9bfadc98540ae61c5e59be06c5bca981460345bd29$256$16$881d65af6b863f6678d484ff551bc843$272$a95faf289b914e570a1993353789b66a9c6bd40b42c588923e8869862339d06ef3d5c091c0ba997a704619b3ffc121b4b126071e9e0a0812f722f95a2d7b80c22bc91fc237cb3dfaba1bee1c9d3cb4c94332335ab203bb0f07ca774c19729ce8182f91cd228ae18fb82b17535ecae012f14904a6ace90d9bab1d934eb957ea98a68b4b2db3c8e02d27f7aff9203cdbd91c2b7c6aaa6f9c2ca3c1d5f976fc9ed86b80082ae3e39c2f30a35d26c2c14dbd64386be9b5ae40851824dc5963b54703ba17d20b424deaaa452793a1ef8418db2dda669b064075e450404a46433f6533dfe0a13b34fa1f55238ffea5062a4f22e821b9e99639c9d0ece27df65caf0aaaad7200b0187e7b3134107e38582ef73b$32$6fde10044103924d8275bf9bfadc98540ae61c5e59be06c5bca981460345bd29$304$6f706461746130310001000000000000881d65af6b863f6678d484ff551bc843a95faf289b914e570a1993353789b66a9c6bd40b42c588923e8869862339d06ef3d5c091c0ba997a704619b3ffc121b4b126071e9e0a0812f722f95a2d7b80c22bc91fc237cb3dfaba1bee1c9d3cb4c94332335ab203bb0f07ca774c19729ce8182f91cd228ae18fb82b17535ecae012f14904a6ace90d9bab1d934eb957ea98a68b4b2db3c8e02d27f7aff9203cdbd91c2b7c6aaa6f9c2ca3c1d5f976fc9ed86b80082ae3e39c2f30a35d26c2c14dbd64386be9b5ae40851824dc5963b54703ba17d20b424deaaa452793a1ef8418db2dda669b064075e450404a46433f6533dfe0a13b34fa1f55238ffea5062a4f22e821b9e99639c9d0ece27df65caf0aaaad7200b0187e7b3134107e38582ef73b", "fred"},
	{NULL}
};

int cloudkeychain_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, extra;

	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* salt length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > SALTLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iterations */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* masterkey length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > CTLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* masterkey */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* plaintext length */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iv length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > IVLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iv */
		goto err;
	if (hexlenl(p, &extra) / 2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* cryptext length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > CTLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* cryptext */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* expectedhmac length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > EHMLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* expectedhmac */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* hmacdata length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > CTLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* hmacdata */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

unsigned int cloudkeychain_iteration_count(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int)my_salt->iterations;
}

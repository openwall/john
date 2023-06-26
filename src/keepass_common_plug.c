/*
 * This software is
 * Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Copyright (c) 2014 m3g9tr0n (Spiros Fraganastasis),
 * Copyright (c) 2016 Fist0urs <eddy.maaalou at gmail.com>, and
 * Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE		1
#endif
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "keepass_common.h"
#include "sha2.h"
#include "aes.h"
#include "twofish.h"

struct fmt_tests keepass_tests[] = {
	{"$keepass$*1*50000*124*60eed105dac456cfc37d89d950ca846e*72ffef7c0bc3698b8eca65184774f6cd91a9356d338e5140e47e319a87f5e46a*8725bdfd3580cf054a1564dc724aaffe*8e58cc08af2462ddffe2ee39735ad14b15e8cb96dc05ef70d8e64d475eca7bf5*1*752*71d7e65fb3e20b288da8cd582b5c2bc3b63162eef6894e5e92eea73f711fe86e7a7285d5ac9d5ffd07798b83673b06f34180b7f5f3d05222ebf909c67e6580c646bcb64ad039fcdc6f33178fe475739a562dc78012f6be3104da9af69e0e12c2c9c5cd7134bb99d5278f2738a40155acbe941ff2f88db18daf772c7b5fc1855ff9e93ceb35a1db2c30cabe97a96c58b07c16912b2e095e530cc8c24041e7d4876b842f2e7c6df41d08da8c5c4f2402dd3241c3367b6e6e06cd0fa369934e78a6aab1479756a15264af09e3c8e1037f07a58f70f4bf634737ff58725414db10d7b2f61a7ed69878bc0de8bb99f3795bf9980d87992848cd9b9abe0fa6205a117ab1dd5165cf11ffa10b765e8723251ea0907bbc5f3eef8cf1f08bb89e193842b40c95922f38c44d0c3197033a5c7c926a33687aa71c482c48381baa4a34a46b8a4f78715f42eccbc8df80ee3b43335d92bdeb3bb0667cf6da83a018e4c0cd5803004bf6c300b9bee029246d16bd817ff235fcc22bb8c729929499afbf90bf787e98479db5ff571d3d727059d34c1f14454ff5f0a1d2d025437c2d8db4a7be7b901c067b929a0028fe8bb74fa96cb84831ccd89138329708d12c76bd4f5f371e43d0a2d234e5db2b3d6d5164e773594ab201dc9498078b48d4303dd8a89bf81c76d1424084ebf8d96107cb2623fb1cb67617257a5c7c6e56a8614271256b9dd80c76b6d668de4ebe17574ad617f5b1133f45a6d8621e127fcc99d8e788c535da9f557d91903b4e388108f02e9539a681d42e61f8e2f8b06654d4dec308690902a5c76f55b3d79b7c9a0ce994494bc60eff79ff41debc3f2684f40fc912f09035aae022148238ba6f5cfb92f54a5fb28cbb417ff01f39cc464e95929fba5e19be0251bef59879303063e6392c3a49032af3d03d5c9027868d5d6a187698dd75dfc295d2789a0e6cf391a380cc625b0a49f3084f45558ac273b0bbe62a8614db194983b2e207cef7deb1fa6a0bd39b0215d72bf646b599f187ee0009b7b458bb4930a1aea55222099446a0250a975447ff52", "openwall"},
	{"$keepass$*2*6000*222*e54497d3d9be3e310a817a13515225a87773ba71557a88673c34db824550be7b*d405c4f7e3c7b2b142fda44c3d55d3afab1c91a6aca7c81c1ff7e61b3f03be85*7eb45af0af777ecb57f0159b9ffa528b*0af7d9facefb20378e8666389de7586ea72e9527dc78bf5dfe5f1b455060a3e6*9b0d1893678dea77f88bf66e6986adbc5a8095e4a09c7e9744bad42ac49133a7", "password"},
	{"$keepass$*1*50000*124*f7465d646bab0a86197fcf2b778ea9c1*ec24a474b0745f9ff1de44ac3e0a274dda83375ecec45eb9ddc40b524fb51df2*f7f17dd2a15c4cf13fb4c8a504298fb3*e7765dba9ed64686a2c0b712de95bd0051a20b331ea0f77133e6afbb9faa1479*1*608*e5802225bf18755620355ad67efa87335532197ce45ee8374a5d23478557414b110426904671c49b266672c02e334c4261d52a9a0723d050329319f8d3b06a6d9507e5b30c78823beea101f52bde5ecdb6b6d0d2627fc254678416b39d2ba43ebce229c0b25f8c530975bc617be602d36e95a6e83c99c7264d5cc994af762460942830ac06b03d30c84c000d01061a938c274d78d383040c8cf5e69e7fbbaf6b46a7061399087f1db2747cd83afdb2b36e6077cecdc3b5c3b3f29f3a1ef537e8c798f8d614f9866a19a53b463aa81632e9aca43ebff9c787ca20a416a4051f16e4ececb84ea853fcc48a988e2d77cb385a2add3b858a18ee73783695a093628a0082d928ffeea39db585a478647e29395fdf2e3e8f54dc5b8277712d8cf5e8a266780944889fb46408b8afb614c3b8e7152b8cc865368d0ae000404234c11c8a77ebc521326683c00967a474cf82336afd1cb8f867db5f6cc7f5c9ae755c0fd0b4c9554ad26bef0b10f0c70978746090034e16922ee9cf38eb251515117cc62da3a62a6fd8a5dab0c10e857b2e2489d2521e1903d6b107c16fd1bf6565fc2953ea3206481ab6c466dba43777076c58ada7cb1883043f4747b2b80731476057598054ea9ec9de1645b4034f6569f579e70a021cc0a490dfa703def725846d0693d7cb02dea430905470db56663953b81b72f7543d6db7713afbcc91919b23cff80290a1053f34516c0b2c7a1f4bec1718994563ae188c2f65e20378537f88be2ebc6c47fbadabbd33414ffa30f115be0abdc89182e0a77d8d5c258d9ec5005415890218eb456fdcb79f1b15031289a0909fc6d8ae48ca6d2d699b6e0cd2e76462", "crackthis"},
	{"$keepass$*1*50000*124*e144905f9aa746e1b2c382c807125d02*dd08f46898a3e75c458a44f34ec5391d3f3eb62b24dbda3d5e486e36312168cc*376ae8d5e8430d0a18e7bb4a0baddf75*5fa8dfc2f440ad296f1562683d06bf2717ae7e8ed343a279f54292f9fc8229ab*1*608*3ce1e03a1452e44b609ebe7326db4ef133ca25c325cc7cc5795ef92358011e2d32a1cb7cadc6f412b1d0a09f67f1444dfec73ed770507683360962d26b0c2b0384bcf9aba2cf1b3e4b5d7083ceaf5f941a2b99ec68d574eb58fe79e94d90b81c8f1f0ccfd35b16d415e8e203c06138eb6a1144520ef98bcdb33d669d2ab4aef2ab739e6dbc3f2ea5c6eef8410ca1555262181d8379b516551eb9d6a23eeb515bd8ef12735a635b25743c1188642486dd1fa4544138a361bcfc108f689bfb90f81d9808adcbd509f057cdbfd1cd31ee8b542956292f9bcca21fabeacc9ba96b335223103a72f94d9b04bcba9d74fada62e0d5bf2da142e413a373ea3c97ff1d50109532f5d041c5f77bea28cdea00388ab9dd3afc72bc266ff44c34221d751738545056e83d7558cf02ffc6f5a57163526ffff9a7de1c6276d4815a812c165ef0293bb951bcbc2cf389d20e188a6c24d1bc5322ee0bc6972b765fb199b28d6e14c3b795bd5d7d4f0672352dfed4870cf59480bab0f39f2a20ac162e8365b6e3dcb4a7fec1baafcb8c806726a777c7a5832a0d1c12568c2d9cad8dc04b1ce3506dbc1bf9663d625cfccb2d3c1cb6b96eee0f34e019b0145e903feed4683abe2568f2c0007c02c57b43f4ee585f9760d5b04c8581e25421b6b5bb370a5b48965b64584b1ed444ea52101af2b818b71eb0f9ae7942117273a3aff127641e17779580b48168c5575a8d843a87dee1088e0fde62bb2100e5b2e178daa463aeaeb1d4ff0544445aab09a7bdc684bd948f21112004dcc678e9c5f8cf8ba6113244b7c72d544f37cbc6baed6ddc76b9ccba6480abfb79a80dda4cdf7e218f396a749b4e5f", "password"},
	/* CMIYC 2013 "pro" hard hash */
	{"$keepass$*2*6000*222*a279e37c38b0124559a83fa452a0269d56dc4119a5866d18e76f1f3fd536d64d*7ec7a06bc975ea2ae7c8dcb99e826a308564849b6b25d858cbbc78475af3733f*d477c849bf2278b7a1f626c81e343553*e61db922e9b77a161e9b674ddadfb8c660d61b5f68d97a3b1596ae94cfa9d169*7c80c7db9de77f176e86ba11697152c4c8f182bdb8133ad1bca22e9ec5bc275b", "Sh4RK%nAD0*"},
	/* twofish version 1 hash from http://openwall.info/wiki/john/sample-non-hashes#KeePass */
	{"$keepass$*1*50000*1*1ff21bd79aa8e9c3f439281a4ce6a97b*cfbdb00057ee0c9e889ca9d93b069ab5ae19f78852bc21aae4f60d0d325e0034*c1a7e6138a49a2dcfb3a84afbc1d918b*a704f9d060f0de5a070155d1d5a8727da92f404242cb3aa2b9aa53a145f87474*1*608*c2d3d18e416af56788d1c3e4257da9ce6e5dcad4db012d7422d17b4527bbb2bb994d9db03907ae01cc1565f5fd0729b930c9ee352426c57de5dee7e941e1d6aedeaf2b0e6509819385de9b4dd6a09979b3edfa0959a7186c422031e426f18d295c55ac616aabeec99f89e696be1d585950ef16a94ae610f2449cc3964bb63ec6043ef36c89117bc78e99e5fbf083b48cb84f85a964e8a037018b3afc2cc55fbe7d74cbdb53d5a54bcd202a1d0a342dbf48a8f7a24264cde8d800a506bf134008b1d8d9b8dd80c19511d9f43b3c23b19eb4a7dcf584f80c49961f73dcba3d2d0390a39a683ddcc8771b49cc3c673ea0aa902d075e25bc814608e2e6d1d6218a6379fd677bc5daaa18b6f5a021d2f661338ca8cc3645dc6cddb860af222a5cdb59a5e2a2c1921203344ced4e2154446239f6c1af8c1bace8207e0f519ea9c08db2f5d0bde0416b09ef6c530213e648641ae56c9af9fbdcb0a286cc4de121655697b9eb00c0fd89ed7269c3859eca20e0c7b60be8d2a1323eb915139cf90c55f9cff01a5bdf757e09ee6d64c2de9aec8d3ea42feeb67caf51b9ba1a80b435e271fdb7f9144ca31e41671768b2c5e8adf70245fdf52005de418efbe2a156d19eeb2ed9e97a0ddb133d11bd8655356d9d3edbbdbf9d0db345b2eb2c1f550ce070f5b0f8f8e58a6ffd52ae8089627dc4a0dac4b4846349066bfa0d2f395d2cb3871e57e353d622e0904a9f54a3e4706797d95b34619f792c15ab8efb3ac523becc3023f01aaad169bc08db8d01e2dd22eff8f6b4f7b741d196bc3de466590011e6d5c9703a19c07d96d26fe1ad93d0931454730ee1f3146428a126d1ed02763f827ff4", "twofish"},
	/* keyfile test cases*/
    {"$keepass$*1*6000*0*1a1d38235ccbeae4ca2a9edfbd3b290c*8e1e81b37a6161b6033fbd6dd350aaeaa0712cf2649fe40e3fbbaa4b61684f54*d9517d352aea00c2b7f57f1154b9c0a0*0a8ae9b13347402c242d7cde4d58d01f1e129287eaf62df768856bbb9d0633a1*1*1360*6555a7e9eca9d5a2c9504a5c888846f0a8902fa31e3dc90f8fcc118856d5daabcaaf4316c4d589e11cce5b9a209e9a7ec1db5b848a706c78f7c7dfac4fd9ea86ac15af500518766dbf4525ee7c1b477a8fec4abdd6f4ad36894ec5aee0c9a5662c5091ceb61b3aa99ff3eacd687ed797b0a1e8ceecd5c51456cb1f70dadf0fda190752e4efe4fb101d5fc5d7745ff01d68cb4c0cc32c6003f85c310e43d7d659748bfc260cbb329c4076c2c9948386c74bb967362a98d6490dbe340f5d440b557b105edd5561836fbb6894f4a1d9a5cd0182536a28f60ca268d682065f8f5226e24a07d635a3c4f04760094cee033fb2f7c3a0cbdf7f174d31c827f6911a75ca95b21332bb47ea6359aa2d70ff4b16e8481cd536e0ec4ba90963edda754b6e0e694855e4f266899b3dd2b0f74c3e688caa376b22810945249ac4e1c38e8d1093ce272ed45d26037a1fd6e0cfcdbdf096c8b2795ba736641bafe9938b6eb2b40ea347f9c49952c118d86ec671c065e3c94f0de2409fec2fde318ad7e6dd0189baf4fa0044fc1d2974b9dafb1608f4bca525706e44ca6af09e305ad29f5e4ba0831145713d5d8b6d6d955c4b5ca031e34b4292aee5383179e1e0afe92ee6565e69825c90bb5e79612a4ad4a3babbd4a75b5481ea710c93595781b71532c17730409482e6b59bb9831be4efadadf36eda5bc5fcf0f3541aaba6662807e531a3e28078f5960e50f80e624c5434b545c1232fdd64359f53b90d6635107f4f005ac02110eebdbdda4f2c92addd686059e9d799a55902526f87f78b8844e2000f82e7b5c8ba3a19fe26117c43f69ba26eee75cc385737791ca4554ce935af26c50331963e500605e87ac3602a76669bf6318e797ef01fe1c25e567cc864de11bd00f555fdf188648bf4179658e325be39a4050b7b01553422e5cd1bbaf5e8f75ce34f0e92f1253c880d4e77f484f14817e288f01efbfe1a8f8b90e9d18b86898856bdf3ee6b5754853cb99a746fa0b753f1a49f529a89d9a0c2fbd5365477be829190dbf491bc886f66ae1bfe014a7e23a420f76a4a0d0d5ebcea51dc0021651a6cdbe5c89a7ae8bfdae2e30d404c31790c0aba8791793ce3072adf21e5a3c5b5e4f9cea82ebff5070e13f94300d5688523ba2a142ae8f82f6ef940e69beba1d665ab17a2ae471500fc48ded336b27450f08dfe07fa5e556963f035a01950f43b2f649bf7f552e9ee7154f5ffdec109fd5bdf0e879d044ef4b78e590ac769efcdd7dad74228872af966d2e8d976336de1ee4289e933288b5b0b43195df1c248176ac944f5e99918dbc067f93d15e95602c9cb8246f378377785b7ebfee44f81b385a3e1c9c5276e4b477c4841af871e6b0e3f4387c58cea01fe2aff04df0f51ac93757172d7537ee0df51ec931564ed2c8a11a45da8c03644d0bc93a14d9f79555250b9c8245690bc1c72ea7e9104a9f570680f704c1f8759a65e210e1b9a855b46ed6801354175b27fc288a7bc39a2003f4400c124ec41d7f54f67be99f778895d9c3e33623a346021215a369487457e78322dbd71a3d969b3e22dfea987ac93d5c4f8252142824f5a67e54a2b1b78ea928fbb63653e122555f6c76150f2541bdad6524f69964c91e9175406d0b824e175e63c7677d990341ee69c4ca9612a05e3bd2ed304c45cd97051aaf0b63c0d917af8d01723e215bb93f816b51d79e29e4e885b98f8ca8320443503c07e67b4d546f544ffced62ef7298a8ac6175f77c180900f638466cd15d6511d7b16992a8e0674563c02fe7776079ee92739bc142a1e601b3aaee284f6f828656e43e58b93bcfd5f69b6aa8c003788d1ae88f569f64402d64e18cb8ffc2268013fe4da9ba7da557da3e259623168b7fd57cf0e4c8327bae66e02bc12978725022ef4cc03b4021d3a*1*64*3a96fb77fbbbca7336ee699f17be31fde552191128553c6d89bfce4035dc0af0", "choupinette"},
    {"$keepass$*2*6000*222*aa511591cb50394d044f31abb2febdb2788c9ee41d78a53f3efe0f83fdd64e81*7ceab79302a794cef818d9426e53a78458f82e72575967c4fb3788d4bc685874*1c5c1c0c475ee2f22bd56e9c75cfd67c*e7bf79115c83a0236260c71c17a816f9bd9288a683eb4b5e0d48666c66e97774*53f26838a293b392bfde1ad21b444b834cf5c02155a1378ac496653b2f3779ec*1*64*98df4f35fe74c031992d81a639305c4520f303fd1ca4bb09b53e33032b44c46a", "kukudanlaplace"},
    // KDBX 3.x with ChaCha20
    {"$keepass$*2*6000*2*e852737a797fb642a2814e5965aba3473644a56ea67998526ce5e6f0e256a56a*fb300459b1e8c52fefa8e72676b57563565475b1c1306c266a48ccc2010e6a94*03027f86819941d1d0f3f2f5*af0f6c5e4319e6c10fdb95f44ded70f3115ae7dc28ec83fd3676c92076505ded*e0ab7f438903eb91dd8bc13c52c5a1c02e34b107ae16710bc57858c8c85fecd0", "openwall"},
    {NULL}
};

char (*keepass_key)[PLAINTEXT_LENGTH + 1];
keepass_salt_t *keepass_salt;

int keepass_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	long long algo;
	int version, res, contentsize, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* version */
		goto err;
	version = atoi(p);
	if (version != 1 && version != 2)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* rounds */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* offset */
		goto err;
	if (!isdec(p))  /* this field contained file offsets in the past, this is hard to validate */
		goto err;
	algo = atoll(p);
	if (algo < 0 || algo > 2)
		algo = 0;
	if (version == 1 && algo > 1) /* Unsupported combo */
		goto err;
	if (version == 2 && algo == 1) /* TODO, v2 w/ Twofish */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* final random seed */
		goto err;
	res = hexlenl(p, &extra);
	if (extra || (res != 32 && res != 64))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* transf random seed */
		goto err;
	if (hexlenl(p, &extra) != 64 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* env_iv */
		goto err;
	res = hexlenl(p, &extra);
	if ((res != 32 && res != 24) || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* hash or expected bytes*/
		goto err;
	if (hexlenl(p, &extra) != 64 || extra)
		goto err;
	if (version == 1) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* inline flag */
			goto err;
		res = atoi(p);
		if (res != 1)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* content size */
			goto err;
		contentsize = atoi(p);
		if (contentsize > MAX_CONT_SIZE) {
			static int warned;

			if (!ldr_in_pot && warned < contentsize) {
				fprintf(stderr,
				        "%s: Input rejected due to larger size than compile-time limit.\n"
				        "Bump MAX_CONT_SIZE in keepass_common.h to >= 0x%x, and rebuild\n",
				        self->params.label, contentsize);
				warned = contentsize;
			}
			goto err;
		}
		if ((p = strtokm(NULL, "*")) == NULL)	/* content */
			goto err;
		if (!contentsize || hexlenl(p, &extra) / 2 != contentsize || extra)
			goto err;
		p = strtokm(NULL, "*");
		// keyfile handling
		if (p) {
			res = atoi(p);
			if (res == 1) {
				if ((p = strtokm(NULL, "*")) == NULL)
					goto err;
				res = atoi(p);
				if ((p = strtokm(NULL, "*")) == NULL)
					goto err;
				if (res != 64 || strlen(p) != 64 || !ishexlc(p))
					goto err;
			}
			else
				goto err;
		}
	}
	else {
		if ((p = strtokm(NULL, "*")) == NULL)
			/* content */
			goto err;
		if (hexlenl(p, &extra) != 64 || extra)
			goto err;
		p = strtokm(NULL, "*");
		// keyfile handling
		if (p) {
			res = atoi(p);
			if (res == 1) {
				if ((p = strtokm(NULL, "*")) == NULL)
					goto err;
				res = atoi(p);
				if ((p = strtokm(NULL, "*")) == NULL)
					goto err;
				if (res != 64 || strlen(p) != 64 || !ishexlc(p))
					goto err;
			}
			else
				goto err;
		}
	}

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *keepass_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static keepass_salt_t cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$keepass$*" */
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);
	if (cs.version == 1) {
		p = strtokm(NULL, "*");
		cs.key_transf_rounds = atoi(p);
		p = strtokm(NULL, "*");
		// cs.offset = atoll(p); // Twofish handling hack!
		cs.algorithm = atoll(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < 16; i++)
			cs.final_randomseed[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.transf_randomseed[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 16; i++)
			cs.enc_iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.contents_hash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.isinline = atoi(p);
		if (cs.isinline == 1) {
			p = strtokm(NULL, "*");
			cs.contentsize = atoi(p);
			p = strtokm(NULL, "*");
			for (i = 0; i < cs.contentsize; i++)
				cs.contents[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
					+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
		p = strtokm(NULL, "*");
		if (p) { /* keyfile handling */
			p = strtokm(NULL, "*");
			cs.keyfilesize = atoi(p);
			p = strtokm(NULL, "*");
			for (i = 0; i < 32; i++)
				cs.keyfile[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
					+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
			cs.have_keyfile = 1;
		}
	}
	else {
		p = strtokm(NULL, "*");
		cs.key_transf_rounds = atoi(p);
		p = strtokm(NULL, "*");
		// cs.offset = atoll(p);  // Twofish handling hack
		cs.algorithm = atoll(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.final_randomseed[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.transf_randomseed[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 16; i++)
			cs.enc_iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.expected_bytes[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < 32; i++)
			cs.contents[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		if (p) { /* keyfile handling */
			p = strtokm(NULL, "*");
			cs.keyfilesize = atoi(p);
			p = strtokm(NULL, "*");
			for (i = 0; i < 32; i++)
				cs.keyfile[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
					+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
			cs.have_keyfile = 1;
		}
	}
	MEM_FREE(keeptr);

	if (cs.algorithm != 0 && cs.algorithm != 1 && cs.algorithm != 2)  // offset hijacking!
		cs.algorithm = 0;  // AES

	return (void *)&cs;
}

void keepass_set_key(char *key, int index)
{
	strnzcpy(keepass_key[index], key, PLAINTEXT_LENGTH + 1);
}

char *keepass_get_key(int index)
{
	return keepass_key[index];
}

unsigned int keepass_iteration_count(void *salt)
{
	keepass_salt_t *my_salt = salt;

	return (unsigned int)my_salt->key_transf_rounds;
}

/*
 * The version shouldn't have a significant impact
 * on performance. Nevertless, report it as the 2nd
 * "tunable cost".
 */
unsigned int keepass_version(void *salt)
{
	keepass_salt_t *my_salt = salt;

	return (unsigned int)my_salt->version;
}

unsigned int keepass_algorithm(void *salt)
{
	keepass_salt_t *my_salt = salt;

	return (unsigned int)my_salt->algorithm;
}

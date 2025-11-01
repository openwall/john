/*
 * KDE KWallet cracker patch for JtR. Written by Narendra Kangralkar
 * <narendrakangralkar at gmail.com> and Dhiru Kholia <dhiru at openwall.com>.
 *
 * Also see https://github.com/gaganpreet/kwallet-dump ;)
 *
 * This software is Copyright (c) 2013 by above authors and it is hereby
 * released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_kwallet;
#elif FMT_REGISTERS_H
john_register_one(&fmt_kwallet);
#else

#include <string.h>
#include <openssl/blowfish.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha.h"
#include "pbkdf2_hmac_sha512.h"

#define FORMAT_LABEL            "kwallet"
#define FORMAT_NAME             "KDE KWallet"
#define FORMAT_TAG              "$kwallet$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "SHA1 / PBKDF2-SHA512 " SHA512_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "SHA1 / PBKDF2-SHA512 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA512 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      16
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               4  // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests kwallet_tests[] = {
	{"$kwallet$112$25be8c9cdaa53f5404d7809ff48a37752b325c8ccd296fbd537440dfcef9d66f72940e97141d21702b325c8ccd296fbd537440dfcef9d66fcd953cf1e41904b0c494ad1e718760e74c4487cc1449233d85525e7974da221774010bb9582b1d68b55ea9288f53a2be6bd15b93a5e1b33d", "openwall"},
	{"$kwallet$240$e5383800cf0ccabf76461a647bf7ed94b7260f0ac33374ea1fec0bb0144b7e3f8fa3d0f368a61075827ac60beb62be830ece6fb2f9cfb13561ed4372af19d0a720a37b0d21132a59513b3ab9030395671c9725d7d6592ad98a4754795c858c59df6049522384af98c77d5351ddc577da07ea10e7d44b3fbc9af737744f53ed0a0a67252599b66a4d1fc65926d7097dc50f45b57f41f11934e0cfc4d5491f82b43f38acde1fd337d51cf47eb5da1bcd8bff1432d7b02f0d316633b33ced337d202a44342fc79db6aea568fb322831d886d4cb6dcc50a3e17c1027550b9ee94f56bc33f9861d2b24cbb7797d79f967bea4", ""},
	{"$kwallet$240$f17296588b2dd9f22f7c9ec43fddb5ee28db5edcb69575dcb887f5d2d0bfcc9317773c0f4e32517ace087d33ace8155a099e16c259c1a2f4f8992fc17481b122ef9f0c38c9eafd46794ff34e32c3ad83345f2d4e19ce727379856af9b774c00dca25a8528f5a2318af1fcbffdc6e73e7e081b106b4fbfe1887ea5bde782f9b3c3a2cfe3b215a65c66c03d053bfdee4d5d940e3e28f0c2d9897460fc1153af198b9037aac4dcd76e999c6d6a1f67f559e87349c6416cd7fc37b85ee230ef8caa2417b65732b61dbdb68fd2d12eb3df87474a05f337305c79427a970700a1b63f2018ba06f32e522bba4d30a0ec8ae223d", "pythonpythonpythonpythonpython"},
	{"$kwallet$136$82ce94a078eff93d43f610b9b71c32d0547c07978a9f868726a4b49e4e87f0c9e1e4e5994d3be71193c7388750333d0154aa43e1fb36319147a25c8ea4c0ecfaf8f9a866da37bdb2ab1013d696dc13e18e45bd8d8b8322d78317d36691c4688fee22e82b1c99674d3fe9b1c137789528de2a9e372490c939304c372d5188af66b2eebffb336cba49", "pwlength15-fooo"},
	{"$kwallet$136$9e7ac9608e41aa2e367aa68d3b3bceb8a28dafc46a911d054376d63f4f03d7319370c9db5a1efa63838e68933bd95de8672ea1101b1a97f58993bd0f033de011556ebcfbba2b7a651c6825ad8172848f3b1cd8eaeabd1832ffdd0c9db8d0f255592071c755c6a94a58bc178dc5a01947be15d57d1d035e053c43a383781310a9b59841f47fd65d3d", "pwlength16-foooo"},
	{"$kwallet$136$3e22fa6c46ff3261b9e706f67a5d12dd52bf104c633f4e441e9bc11038fd852a185765bdfdd5ef1f25c341f589c96dbff9e243b95687e0978eb21c8d1dc79b1d7165b689c8781b368ec00e9fb4226b9aa5227757da6ee848ffd714f765453ba4763af252f7c59e3c6b5c756c307b635b7ffed757d7aca224c96ac6667f89fa7b12aea3311a1a18d2", "pwlength17-foobar"},
	{"$kwallet$136$7dbc3370b98efd78bb1eedbced16743e86e2d1aeb2de1c2afb4194af9bf2a2c1c548cd7870392e4048c211e9bae36f966d3e0cfd082f843851fafd44d3c07c36dc2b01bc346142c952312e48528179c86cd1fa2e9645d30c78b4c89d2fc368bed35a412944c4151aa420a7d6638f47db1b768360cda34b65f3bd131f55fead07fbfee73d595263ba", "pwlength31-moderatelylongiguess"},
	{"$kwallet$136$7866a7aa491b74d0e5cdf4a8fec2cfaed63d5b0462fb4b8fe94871e4b32ce28ef0c93021f85d459f4d5497578f1f675c5d911709628b5b78a28bd117d9c05d02f902645efd0e9f2caa473af3a1a782896d014c255618ff17ac5164f9e2d10b531767f2ac29559efb582599b0e059d5f6b4e3ce42eaeb1d9963792d9657b80d59afe31e8bc137b2c6", "pwlength32-andthisiskindalongtoo"},
	{"$kwallet$136$d419e5def3fa650fe9aeaaaf2a8130eab70cc2aca952268565b64369e7c31cdb3211acf54a602ee8d425307948038b41e1fbdedb44e6d1f276e8e0215e26103f52208be4d284159e350cdbda9856bb3b65fb62a5374e6b53723467ce772dc8f764bb57bcd5410033e2697d607e6b03c49e294a1d87ec8415f0f937b935db564cc94f7ae75d79eca8", "pwlength33-thisisthirtythreechars"},
	{"$kwallet$136$9c7c85c9a4218e21eef7368fcdd72d6dc1994edcb572f0f26e6e565b033b0ead7e021a15fa8341de9da0c8367654727d691d9327e256424945178092da06f17a9b26d1709bb61a6a8ac2e67473883626d90949a4f2d80ac189c5c3d3de76d4a83f045617b54537a94ca8d2a17510d09637c35377f9421a6d142aeab4510f4b08495d15bbad07d78b", "pwlength47-thepasswordlengthisreallylongherenow"},
	{"$kwallet$136$5e272365db021211921090023f0aef977771d0125641bd79e8ee6952638e6821b3a998a55a2919d3e3267264e2da71db128fff1ad9f139bffa501d5015204854e208beed504f475f2b606ae4e8857c605b559e1270da664411bb23d678188c9b3787170c15cd497674ff58f542ae79e6559de741beb326033c2a7fe1313cb4a276056a8d846b5698", "pwlength48-heresalmostenoughspacetotellsomestory"},
	{"$kwallet$136$c103a08cc3e799a2f1c5a3b0e6f0fce4375795eb361b043bd967d69f99fb80babcecbe3d6edf4f6ef2ca4ebb4da39634cca13445cc03840a8b1092ab04022bb47cfe0945b2c3d66c8d2499dc271f944521f00c6316ea731891539496f54d78d6854bd8a8e1406d18b3348545a4c8d07319f6d8148dd1e6f275fd74bd870283c189b59f815306b8c0", "pwlength49-lastoneforthesefortysomethingpasswords"},
	{"$kwallet$136$081554e2ce5e261877a1f38011bb4aab58bef0e1cd6c480dc7d74c0a99a998c363d2ce1c6ec88cc3afeb919fcf00141a90fda15bb30a8ae3787a2795f8a0bd97c9389f36f25077d68edb61c913900d55248a8675f6067a18e32e26fe512ab4dceecd7b9a7a1b59ac1b7a420b6d103648b8c7ffd295166299c1cde4628605a0243f26296363f177ed", "pwlength63-hereitsgettingkindofridiculoustoreachtherequiredsize"},
	{"$kwallet$136$3571cc7a09ee75d33dc7571ca0a5cf975076491bf765485f51984be511d07af8843ade8ad899d18b67c7ffa2ce4d14af3a780c43669c79b10607b5cfdeb01573599df62021f49942f5128de2313e7bd5c33bc54fee8eeb579f1d97d318db2998842b9958f1b92b2db4170ff4b19db6459b9062cff40035fcfd6ce108618e907764f6e6fa2079b734", "pwlength64-weneedmoreexampleswithlongerpasswordshesaidwouldbefun"},
	{"$kwallet$136$283bcb57373ef37c43f57887cf022c4ba435141ff561f5b99f28389ba4cfc9503440c396ccfeb3434d2e143c5a25a43d9c86ac81f5fcd903648975bfb5369417e33674a33010075299ca5360c26dd31f959d31efdbd25b6af8c92c4303625b7be842dbbc5ce536bd1fd62afcf8121e0d0f68d57f62eba9cb9915705e9fb2b5bb7c4bd49fba6718ab", "pwlength65-thisissolongimrunningoutofideaswhattotypeasthepassword"},
	{"$kwallet$136$f26a06b3c20086992b9f12e234d864a5b3257999e6ee6418bc8036c942fb0a2186b0a91e1f43a77d497d950b5519ed16eb58f5a0b11ecdf84e841f4c4e7c212dfeca9b08284dfdaf97e953f5a1e8a69038c1f33dd0a78f4e1299386884da082ff22948689eedd04d3f58c492a11688030725c30935e5a3d460fcefc2604ac2ad36d5d329582861a2", "pwlength125-onehundredtwentyfivecharactersinakwalletpasswordisreallymuchandibetnobodyevercreatedsuchawalletintheancientformat"},
	// modern KWallet hashes
	{"$kwallet$88$b4e0299dc00fbb467f622fa2f0d7b275a82014e947ae20583bcbd4a32d8bb1402f0e7baca2177ef11b86f9ce4bcbed7b638a0697202b1737a15b2cdddcc01c43748d4528f59ce402c31da30d265f8d8a02b20baeefc6e946$1$56$8f90f3b63faf4049373703f896d3511136696af6ce60b92010daa397c6eb8ea4c867288e61694002d3c152ef4d8e3119bf39cbcd6b65edb8$50000", "openwall"},
	{"$kwallet$1488$f0732de12d063958715ceb5cf6d06024229cd340484d9cbc1f61279fa36a8152ecb2757505d5091af831d6846a7d4e8ff6d5b09e69a7c9c52e4d8c40e70785e4547d3cf8060e3dce2d2987f63cd5d32b00a286a9828b6b1e133fcc96959a612914e404b0cdb3a447e254e52ab692f6c3aa61d2c6f9c54f84a8d4222e1120a15209f97560c6a52db008ac087a79dfc88eae581a125d773fd00c9b3056e67d6a5b38199a2fa48945dc0c6cbb9495f74cdf419979ce63ee5da03a331d12a504400410f97ae92617e302e09f33a4c7db49c3693fbaa5df7636156c8743606d7bd52c9024b7c8da792a0334edb23e7a0eb7962d74ff1fe430d29615d39e325b8a92af297794912ab6075ee68f7d28134da57c8cbc2b3b10899c17533085012643a8020344c9d093792e698026b29c6fec65c4574a66a1e51c62b1b98e1a40d474c425ebd41e6b58159a92b43f29d2b76a9c24e01b0db31752ceef34bd7cec1bee7cb559cfda214a59ee642aa2875a8c8986ce752caf8218d99571c3d5d5a69fa2463c38c0d7d5372b74f6bff961aaaceb7d3a8b0026716f9d6a84fa0d5fe92ef975f98cb72b3b0065d270a61d3e52b8ece2f14046ed340bd3bc259058c288dea1566704bf078802e712b0111c170762a22dde5852eb151c9949236ecad79f8dc1a16769d61afbc84a38adfb3654d1e49dd281d4a98a023f7f19d647c891d9ea92958419be0d3b4988bcf52cb2ebe2e0e00717cf429413a304aa8c7b48f2c46eddfa424dd708cffcbb9f97840c1b2ac8494bad3cdaa968b4eb4df0857422fe65be7c0493547662ccc45aa6d22362f3acd8868eb0849e8f4da0275e590ae592986105b19748fbd7f9c27da80d13c05fb923053802bb117bff3298e86e2ec3076a8095efbb6a7754dc8704080d2131a1b95a2f3491d8705b7b14e1953f269a1c93863ae7580d7913ce8f6eb85153f462e7c8d22f51b73b46b0334f5dfe72b4b0cc89762935663149e05fe5c07f702e8e246995505818807506d469d168781cda4e61ea13916a000c6ca17b13bed6e6e91aa5db1182d31fd6702c1e0a451dfb72f8e634be3cc0e931c68dffed47d8c7e43ee53ba1b80e3c320a1084d6a89f8c44b638e5479fdfa814f7d5a83ce7c14e9db59e79ba68877be3c03d419ac4ee3e76fab8336b166ef1e90a0c94365694a17e0facc949819af0a248aa424772270cf4261cf6f287e44d72b6913e73d60d85e000e5e882811b178c7b478b58acd111d463d8e552413db3cc3c7ef78662c57810e8694a6f5676128bb68fc897cef3a18dc2b1a3140a5508f2d7f09a1909256612e98d99600161ade28ca01fb22995260c3c50284f53e2544c51c63cd2f2f03ae7053570f422e8fea241c3fb0f75acf43bbc94e1daee1ce57e3e9e2118fd7249a1cccab6d4ed346ef127dfdd4b05af8e04539a0b3b6a44fd896b56719eacec4430193f343ccb284d4e4be99c96ff7c991f635c1dd7f425c49af11e37fd6dcbebb14392748a90f05a8363c8a85d775eb1ac116eff94f9b6660db7224f25bd298844e1498c8bc1bd3b4b7eb8ecb0fc9536b3270c16a297bdfe44af5fd76dd848308a7f45655c694bd63341ccda9d201de855395964359d42255157954b1c96049bce36c03193934c4f022becfdf195a5136d06523f1b33a1d10752732b00e77adb0fe9c482ba8c8c31a1b06016ccee80da5a2cbf9bd056c3e6923cbfda827524caa7b3f5f847bed08585c73fc6d35c7ca574c2a7c7bdc421c599e92d9015ada3576b9ba8b9da8b19dd23038cdf95d116e47e2441ffddec32a1483f8fa7319b11d6c285b17ed1b575f7df744a61def6e9f0c8ee0cd0f91820de067fedb8bd1095b5dc54f22ccc037bb9d15c31175c0a2757bdac390b9d1ece7ae4e1289d4cbff2c1edd050bfb5216f4683249d007659d9c8020ef14acf8d12beb639fb836a6e67afc29a85daa8369c6c99689876affd56c4faea180c07c6731a6b8e84bef4647a04f8e3796f32a5d00f61d69ebacfdeb638a2d604e19a044550c174903b812c215d4d355b9de100230da86365743b67cc3623bd211ad115e45ef2e6b292d7bfa77c018eb76713$1$56$9fdd02d06743356dfb7759f7c3118d95b7ca4f54ae02cf0cb2cca3f9dfe805e5dedc2c2b5c4267bf29cd3a5f80c887e1eedfcdeac78e6887$50000", "eel-bronze-aghast-blissful-duh-duration-outrank-shrunk"},
	{"$kwallet$88$69fca2d9a5004b6a8c4dc56e27e0046840a5b960121462270caf2d6b39db6e1d87b50d36e1bdfa6468e98c63de980d882af639a71e03438f6263864490a32c5cecb425c30fd216de5aa0af9e4cb8dad3a8ebece09dcf0884$1$56$d12685e20a1e7e9e87f357b78f72f5e059ad7b49295f159aa5af775ef11ec5de14bb978f0e1ab9aa29d365848e4b6f68260408fdfd0f43db$50000", "openwall"},
	{"$kwallet$88$d93b084704e76898b1157b9965316e2c1f837d758e63005bf5f8865fcf929051b118cbda3aaffbff86cba4c715fc749c173368be796d0e37b327db7f832e20b7accb3e7ac519c38a13b056ad8ca03240da64deed72293634$1$56$bbe9dd83359eb451fc7759c91d457bbe9c74dab3ed30c10a3a8f0ef1e0bb2cfab32e6e68f6e8c1fb788f22073b76d03c98d52dc9a50a991e$50000", "openwall"},
	{"$kwallet$520$d931157b758d2fcd343a9fd5823da60c79dc15b596389d61ac046a2f268f8660a87d1aaa001e66f1a24405f153921b79809043f214446ccfd5fdfd5d50e86efac53e1ce96b450af39062fc101eb1aa463acba15d870552aa3321468fa56c68e7c1b3b4a3f19c44c1ecc7b9c07a09a6e5bf3a41a811914b7f11a0e4afecbefb7621e0bf8ee0b38337c385ae86b92d1604d8824ed94a9bb53621b530463db60d5eff60d21cc79ee6fb2302d069c9a1fccf021dd88a9af299ed166112b162bcd4615dd2f759ab505db916e61b6486c835b4d57c7bd967cb3eaa23e9f8a70b9eff8ae5298318057deb092f3cb48c9e519548a807c894ea6070aedda33e5ae03d423f4b737e27f5f0738da7f25b29581e85fa8011190f3c3419298896c612082accb55b3ba5d280998c54ad1630edae05758a5584288d8c51803935b9f757f945e33f2b351dd8022b9f15d427a96e359e29e7fd569ee774d770baa9720f9717a3d882d693f9d3562428400bc40728a49180430d2d47f1a880ae22a3fd5d696607bf93db00df0d47d6058623a7c7f091c9ff47bb62b9ddaf9df56002cb542350f270d8302351359d68857bf13e5693ba111ffc45227af10572818d785cc115b0b6633371f4ef5baf7870ab33bc98b3bddb5f63d1decf8f85e3732b9b3a95dff93b2398809108ce236c268eeedfa14637b2d73ec507bff15b76d136ac601e8c5a9c3d4e2f94816fd4fcf01e$1$56$6278a23465d8cfc3d6117e97f684c3e13bf3c747b6681649103c373a3703512ee6a76080fd0019bbe4e1554e2397f435bce21b96ac5d27e8$50000", "eel-bronze-aghast-blissful-duh-duration-outrank-shrunk"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned char ct[0x10000];
	unsigned int ctlen;
	// following fields are required to support modern KWallet files
	int kwallet_minor_version;
	unsigned char salt[256];
	int saltlen;
	int iterations;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int res, extra;
	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* ctlen */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res < 64 || res > sizeof(cur_salt->ct) || (res & 7))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* ct */
		goto err;
	if (hexlenl(p, &extra) != res*2 || extra)
		goto err;

	if ((p = strtokm(NULL, "$")) != NULL) {
		if (strcmp(p, "1")) /* minor version */
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)	/* saltlen */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p); /* saltlen */
		if (res > sizeof(cur_salt->salt))
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)	/* iterations */
			goto err;
		if (!isdec(p) || atoi(p) < 1)
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
	char *ctcopy = xstrdup(ciphertext);
	static struct custom_salt *salt;
	char *keeptr = ctcopy;
	int i;
	char *p;

	ctcopy += FORMAT_TAG_LEN;
	if (!salt) salt = mem_calloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	memset(salt, 0, sizeof(*salt));
	p = strtokm(ctcopy, "$");
	salt->ctlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < salt->ctlen; i++)
		salt->ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	if ((p = strtokm(NULL, "$")) != NULL) { // modern KWallet file
		salt->kwallet_minor_version = atoi(p);
		p = strtokm(NULL, "$");
		salt->saltlen = atoi(p);
		p = strtokm(NULL, "$");
		for (i = 0; i < salt->saltlen; i++)
			salt->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "$");
		salt->iterations = atoi(p);
	} else {
		// Old KWallet files, 0 has been the MINOR version until
		// KWallet 4.13, from that point we use it to upgrade the hash
		// to PBKDF2_SHA512
		salt->kwallet_minor_version = 0;
		salt->iterations = 2000;
	}

	MEM_FREE(keeptr);
	return (void *)salt;
}

static void password2hash(const char *password, unsigned char *hash, int *key_size)
{
	SHA_CTX ctx;
	unsigned char output[80];
	unsigned char buf[20];
	int i, j, oindex = 0;
	int plength = strlen(password);

	// divide the password into blocks of size 16 and hash the resulting
	// individually!
	for (i = 0; !i || i < plength; i += 16) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, password + i, oindex >= 60 ? plength - i : MIN(plength - i, 16));
		SHA1_Final(buf, &ctx);
		// To make brute force take longer
		for (j = 1; j < 2000; j++) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, buf, 20);
			SHA1_Final(buf, &ctx);
		}
		memcpy(output + oindex, buf, 20);
		if (oindex >= 60)
			break;
		oindex += 20;
	}

	if (plength <= 16) {
		// key size is 20
		memcpy(hash, output, 20);
		*key_size = 20;
	}
	else if (plength <= 32) {
		// key size is 40 (20/20)
		memcpy(hash, output, 40);
		*key_size = 40;
	}
	else if (plength <= 48) {
		// key size is 56 (20/20/16 split)
		memcpy(hash, output, 56);
		*key_size = 56;
	}
	else {
		// key size is 56 (14/14/14/14 split)
		memcpy(hash + 14 * 0, output +  0, 14);
		memcpy(hash + 14 * 1, output + 20, 14);
		memcpy(hash + 14 * 2, output + 40, 14);
		memcpy(hash + 14 * 3, output + 60, 14);
		*key_size = 56;
	}
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

// Based on "BlowfishPersistHandler::read" in backendpersisthandler.cpp
static int verify_key_body(unsigned char *key, int key_size, int not_even_wrong)
{
	SHA_CTX ctx;
	BF_KEY bf_key;
	int sz;
	int i, n;
	unsigned char testhash[20];
	unsigned char buffer[sizeof(cur_salt->ct)]; // XXX respect the stack limits!
	const char *t;
	size_t fsize;

	memcpy(buffer, cur_salt->ct, cur_salt->ctlen);

	/* Blowfish implementation in KWallet is wrong w.r.t endianness
	 * Well, that is why we had bad_blowfish_plug.c originally ;) */
	if (!not_even_wrong)
		alter_endianity(buffer, cur_salt->ctlen);

	/*
	 * Potential optimization:
	 * Most of the time we could decrypt just one block containing fsize,
	 * and occasionally bytes 8 to 63, not the whole thing.
	 * Potential security enhancement:
	 * We could also revise the 2john script to omit the actual data and
	 * SHA-1 (everything after initial 64 bytes), but this would be a
	 * "hash" format change.
	 */
	if (cur_salt->kwallet_minor_version == 0) {
		BF_set_key(&bf_key, key_size, key);
		for (i = 8; i < cur_salt->ctlen; i += 8) {
			BF_ecb_encrypt(buffer + i, buffer + i, &bf_key, 0);
		}
	} else if (cur_salt->kwallet_minor_version == 1) {
		key_size = 56;
		BF_set_key(&bf_key, key_size, key);
		sz = cur_salt->ctlen;
		if (not_even_wrong && sz > 64)
			sz = 64; /* we'll skip the SHA-1 check anyway */
		BF_cbc_encrypt(buffer + 8, buffer + 8, sz - 8, &bf_key, buffer, 0);
	}

	if (!not_even_wrong)
		alter_endianity(buffer, cur_salt->ctlen);

	/* verification stuff */
	t = (char *) buffer;

	// strip the leading data
	t += 8;	// one block of random data

	// strip the file size off
	fsize = 0;
	fsize |= ((size_t) (*t) << 24) & 0xff000000;
	t++;
	fsize |= ((size_t) (*t) << 16) & 0x00ff0000;
	t++;
	fsize |= ((size_t) (*t) << 8) & 0x0000ff00;
	t++;
	fsize |= (size_t) (*t) & 0x000000ff;
	t++;
	if (fsize > (size_t) (cur_salt->ctlen) - 8 - 4) {
		// file structure error
		return -1;
	}

	for (i = n = 0; i < fsize && i < 52; i++)
		if (!t[i])
			n++;
	if (n >= 12) /* actually seen was 30 to 32 zero bytes out of 52 */
		return 0;

	if (not_even_wrong)
		return -2;

	/* This only works for the original wrong code, not weirder */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, t, fsize);
	SHA1_Final(testhash, &ctx);
	// compare hashes
	sz = cur_salt->ctlen;
	for (i = 0; i < 20; i++) {
		if (testhash[i] != buffer[sz - 20 + i]) {
			return -2;
		}
	}

	return 0;
}

static int verify_key(unsigned char *key, int key_size)
{
	if (!verify_key_body(key, key_size, 0))
		return 0;
	if (cur_salt->kwallet_minor_version == 1 && !verify_key_body(key, key_size, 1))
		return 0;
	return -1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char key[MIN_KEYS_PER_CRYPT][56]; /* 56 seems to be the max. key size */
		int key_size[MIN_KEYS_PER_CRYPT];
		int i;

		if (cur_salt->kwallet_minor_version == 0) {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				password2hash(saved_key[index+i], key[i], &key_size[i]);
				cracked[index+i] = !verify_key(key[i], key_size[i]);
			}
		} else if (cur_salt->kwallet_minor_version == 1) {
#ifdef SIMD_COEF_64
			int len[MIN_KEYS_PER_CRYPT];
			unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];

			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				len[i] = strlen(saved_key[i+index]);
				pin[i] = (unsigned char*)saved_key[i+index];
				pout[i] = key[i];
			}
			pbkdf2_sha512_sse((const unsigned char **)pin, len, cur_salt->salt, cur_salt->saltlen, cur_salt->iterations, pout, 56, 0);
#else
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				pbkdf2_sha512((const unsigned char*)(saved_key[index+i]),
					strlen(saved_key[index+i]), cur_salt->salt,
					cur_salt->saltlen, cur_salt->iterations,
					key[i], 56, 0);
			}
#endif
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
				cracked[index+i] = !verify_key(key[i], 56);
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

static void kwallet_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int tunable_cost_version(void *_salt)
{
	struct custom_salt *salt = (struct custom_salt *)_salt;
	return salt->kwallet_minor_version;
}

static unsigned int tunable_cost_iterations(void *_salt)
{
	struct custom_salt *salt = (struct custom_salt *)_salt;
	return salt->iterations;
}

struct fmt_main fmt_kwallet = {
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
		{"version", "iterations"},
		{ FORMAT_TAG },
		kwallet_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{tunable_cost_version, tunable_cost_iterations},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		kwallet_set_key,
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
#endif /* HAVE_LIBCRYPTO */

/* ODF cracker patch for JtR. Hacked together during Summer of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.  */

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "gladman_fileenc.h"
#include <openssl/sha.h>
#include <openssl/blowfish.h>
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"odf"
#define FORMAT_NAME		"ODF SHA-1 Blowfish / SHA-256 AES"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		20
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests odf_tests[] = {
	{"$odf$*0*0*1024*16*df6c10f64d191a841812af53874b636d014ce3fe*8*07e28aff39d2660e*16*b124be9f3346fb77e0ebcc3bb80028f8*0*2276a1077f6a2a027bd565ce89824d6a20086e378876be05c4b8e3796a460e828c9803a692caf7a53492c220d1d7ecbf4e2d336c7abf5a7672acc804ca267318252cbc13676616d1fde38820f9fbeef1360067d9de096ba8c1032ae947bde1d0fedaf37b6020663d49faf36b7c095c5b9aae11c8fc2be74148f008edbdbb180b44028ad8259f1215b483542bf3027f56dee5f962448333b30f88e6ae4790b60d24abb286edff9adee831a4b3351fc47259043f0d683d7a25be7e47aff3aedca140005d866e218c8efcca32093c19bbece50bd96656d0f94a712d3c60d1e5342db86482fc73f05faf513ca0b137378126597b95986c372b412c953e97011259aab0839fe453c756559497a28ba88dce009e1e7980436131029d38e56a34f608e6471970d9959068808c898608024db9eb394c4feae7a364ea9272ec4ea2315a9f0407a4b27d5e49a8ab1e3ddce5c84927d5aecd7e68e4437a820ea8743c6b5b4e2abbb47b0001e2f77ceac4603e8774e4ccbc1adde794428c11ae4a7492727b620334302e63f72b0c06c1cf83800366916ee8295176819272d557863a831ee0a576841191482959aad69095831fa1d64e3e0e6f6c6a751bcdadf0fbaa27a17458709f708c04587cb208984c9525da6786e0e5aabefe30ad1dbbef66e85ce9d6dbe456fd85e4135de5cf16d9455976d7ca8de7b1b530661c74c0fae90c0fff1a2b5fcdfab19fcff75fadcec445ed8af6ab5babf1463e08458918be8045083de6db988c37e4be582cfac5cdf741d1f0322fb2902665c7ff347813348109e5d442e91fcb010c28f042da481e807084fcb4759b40ccf2cae77bad00cdfbfba4acf36aa1f74c30a315e3d7f1ca522b6306e8903352aafa51dc523d582d418934398d5eb88120e3656bfb640a239db507b285302a86855ea850ddc9af72fc62dc79336c9bc29ee8314c65adb0574e9c701d73d7fa977edd1d52a1ff2da5b8b94e1a0fdd01ffcc6583758f0a1f51750e45f12b58c6d38b140e5676cf3474224520ef7c52ca5e634f85456651f3d6f43d016ed7cc5da54ea640a3bc50c2b9d3dea8f93c0340d66ccd06efc5ae002108c33cf3a470c4a50f6a6ca2f11b8ad15511688c282b94ba6f1c332e239d10946dc46f763f08d12cb9edc1e79c0e07f7151f548e6d7d20ec13b52d911bf980cac60694e192651403c9a69abea045190e847be093fc9ba43fec55b32f77f5796ddca25b441f259d5c51e06df6c6588c6414899481ba9e06bcebec58f82ff3021b09c6beae13a5d22bc94870f72ab813d0c0be01d91f3d075192e7a5de765599d72244757d09539529a8347e077a36678166e5ed9f73a5aad2e147d8154095c397e3e5e4ba1987ca64c1301a0c6c3e438097ede9b701a105ec38fcb54abb31b367c7740cd9ac459e561094a34f01acee555e60267157e6", "test"},
	{"$odf$*1*1*1024*32*61802eba18eab842de1d053809ba40927fd40b26c69ddeca6a8a652ed9c16a28*16*c5c0815b931f313627100d592a9c972f*16*e9a48b7daff738deaabe442007fb2ec4*0*be3b65ea09642c2b4fdc23e553e1f5304bc5df222b624c6373d53e674f5df01fdb8873cdab7a5a685fa45ad5441a9d8869401b7fa076c488ad53fd9971e97244ecc9416484450d4fb2ee4ec08af4044d7def937e6545dea2ce36bd5c57b1f46b11b9cf90c8fb3accff149ce2d54820b181b9124db9aac131f6436d77cf716423f04d42438eed6f9ca14bd24b9b17d3478176addd5fa0254bf986fccd879e326485790e28b94ad5306868734b5ac1b1ddb3f876382dee6e9428e8230e84bf11b7e85ccbae8b4b424cd73160c380f874b37fbe3c7e88c13ef4bde74b56507d17095c2c32bb8bcded0637e4403107bb33252f72f5886a91b7720fe32a8659a09c217717e4c74a7c2e09fc40b46aa288309a36e86b9f1856e1bce176bc9690555431e05c7b67ff95df64f8f40053079bfc9dda021ab2714fecf74398b867ebef675958f29eaa15eb631845e358a0c5caff0b824a2a69a6eabee069d3d6236d77709fd60438c9e3ad9e42b26810375e1e587eff105ac295327ef8bf66f6462388b7727ec32d6abde2f8d6126b185124bb437753663f6ab1f321ddfdb36d9f1f528729492e0b1bb8d3b9eda3c86c1997c92b902f5160f77587c37e45b5c133b5d9709fea910a2e9b54c0960b0ebc870cdbb858aabe07ed27cba86d29a7e64c6e3863131859314a14e64c1168d4a2d5ca0697853fb1fe969ba968e31359881d51edce287eff415de8e60cec2068bb82157fbcf0cf9a95e92cb23f32e6156daced4bee6ba8c8b41174d01fcd7662911bcc10d5b4478f8209ce3b91075d10529780be4f17e841a1f1833d432c3dc854908643e58b03c8860dfbc710a29f79f75ea262cfcef9cd67fb67d73f55b300d42f4577445af2b9f224620204cfb88de2cbf57931ac0e0f8d98259a41d744cad6a58abc7761c266f4e93aca19356b07073c09ae9d1976f4f2e1a76c350cc7764c27ae257eb69ba4213dd0a7794fa83d220439a398efd988b6dbf0de4c08bc3e4830c9e482b9e0fd1679f14e6f132cf06bae1d763dde7ce6f525ff9a0ebad28aeca16496194f2a6263a20e7afeb43d83c8c936130d6508f2bf68b5ca50375948424193a7fb1106fdf63ff72896e1b2633907f01a693218e3303436542bcf2af24cc4a41621c36768ce9a84d32cc9f3c2b108bfc78c25b1c2ea94e6e0d65406f78bdb8bc33c94a9550e5cc3e995cfbd31da03afb929418acdc89b099415f9bdb7dab7a75d44a696e14b031d601ad8d907e14a28044706c0c2955df2cb34ffea82af367e487b6cc928dc87a33fc7555173e7faa5cfd1af6d3d6f496f23a9579db22dd4a2c16e950fdc90696d95a81183765a4fbddb42c488d40ac1de28483cf1cdddf821d3f859c57b13cb7f21a916bd0d89438a17634c68637f23e2544589e8ae5ee5bced91680c087cb3105cd74a09e88d3aae17d75e", "test"},
	{"$odf$*0*0*1024*16*43d3dbd907785c4fa5282a2e73a5914db3372505*8*b3d676d4519e6b5a*16*34e3f7fdfa67fb0078360b0df4011270*0*7eff7a7abf1e6b0c4a9fafe6bdcfcfeaa5b1886592a52bd255f1b51096973d6fa50d792c695f3ef82c6232ae7f89c771e27db658258ad029e82415962b270d2c859b0a3efb231a0519ec1c807082638a9fad7537dec22e20d59f2bfadfa84dd941d59dd07678f9e60ffcc1eb27d8a2ae47b616618e5e80e27309cd027724355bf78b03d5432499c1d2a91d9c67155b7f49e61bd8405e75420d0cfb9e64b238623a9d8ceb47a3fdb5e7495439bb96e79882b850a0c8d3c0fbef5e6d425ae359172b9a82ec0566c3578a9f07b86a70d75b5ad339569c1c8f588143948d63bdf88d6ed2e751ac07f25ecc5778dc06247e5a9edca869ee3335e5dae351666a618d00ec05a35bc73d330bef12a46fb53b2ff96e1b2919af4e692730b9c9664aca761df10d6cf55396c4d4c268e6e96c96515c527c8fe2716ac7a9f016941aa46e6b03e8a5069c29ec8e8614b7da3e2e154a77510393051a0b693ae40da6afb5712a4ce4ac0ebacda1f45bdccc8a7b21e153d1471665cae3205fbfa00129bf00c06777bfecba2c43a1481a00111b4f0bd30c2378bd1e2e219700406411c6f897a3dfa51b31613cb241d56b68f3c241428783b353be26fa8b2df68ca215d1cf892c10fdef94faf2381a13f8cb2bce1a7dbb7522ef0b2a83e5a96ca66417fd2928784054e80d74515c1582ad356dd865837b5ea90674a30286a72a715f621c9226f19a321b413543fbbdb7cd9d1f99668b19951304e7267554d87992fbf9a96116601d0cee9e23cb22ba474c3f721434400cacf15bae05bbe9fa17f69967d03689c48a26fa57ff9676c96767762f2661b6c8f8afa4f96f989086aa02b6f8d039c6f4d158cc33a56cbf77640fb5087b2d5a5251692bb9255d0ae8148c7157c40031fdb0ea90d5fab546a7e1e1c15bd6a27f3716776c8a3fdbdd4f34c19fef22c36117c124876606b1395bf96266d647aaf5208eefd729a42a4efe42367475315a979fb74dcb9cd30917a811ed8283f2b111bb5a5d2b0f5589b3652f17d23e352e1494f231027bb93209e3c6a0388f8b2214577dca8aa9d705758aa334d6947491488770ed8066f692f8922ff0d852c2d0f965ab3d8a13c6de0ef3cff5a15ee7b64f9b1003817f0cb919ad021d5f3b0b5c1ad58db22e8fbd63abfb40e61065bad008cdffbbe3c563780a548f4515df5c935d9aa2a3033bc8a4011c9c173a0366c9b7b07f2a27de0e55373fb4b0c7726997be6f410a2ee5980393ea005516e89538be796131e450403420d72cdbd75475fd11c50efce5eb340d55d2dd0a67ca45ddb53aa582a2ec56b46452e26a505bf730998513837c96a121e4ad13af5030392ff7fb660955e03f65894733862f2367d529f0e8cdb73272b9ce01491747cb3e1a22f5c85ab6d40ddd35d15b9d46d73600e0971da90f93cb0e9be357c4f1227fbf5b123e5b", "jumper9"},
	{"$odf$*0*0*1024*16*4ec0370ab589f943131240e407a35b58a341e052*8*19cadc01889f78c0*16*dcfcb8baccda277764e4e99833ab9640*0*a7bd859d68298fbdc36b6b51eb06f7055befe08f76ca9833c6e298db8ed971bfd1315065a19e1b31b8a93624757a2583816f35d6f251ff7943be626b3dc72f0b320c9ce5d80b7cc676aa02e6a4996abd752da573ecc339d2c80a2c8bfc28a9f4ceea51c2969adf20c8762b2ee0b1835bbd31bd90d5a638cfe523a596ea95feca64ae20010ad9957a724143e25a875f3cec3cedb4df1c16ac82b46b35db269da98270c813acd5e55a2c138306decdf96b1c1079d9cfd3704d519fbc5a4a547ba5286a7e80dc434f1bf34260433cbb79c4bcbb2a5bfc5a6c2430944ef2e34e7b9c76b21a97003c1fa85f6e9c4ed984108a7d301afe4a8f6625502a4bf17b24e009717c711571da2d6acd25868892bb9e29a77da8018222cd57c91d9aad96c954355e50a4760f08aa1f1b4257f7eb1a235c9234e8fc4ed97e8ad3e5d7d128807b726a4eb0038246d8580397c0ff5873d34b5a688a4a931be7c5737e5ada3e830b02d3efb075e338d71be55751a765a21d560933812856986a4d0d0a6d4954c50631fa3dff8565057149c4c4951858be4d5dca8e492093cfd88b56a19a161e7595e2e98764e91eb51c5289dc4efa65c7b207c517e269e3c699373fe1bf177c5d641cf2cfa4bd2afe8bff53a98b2d64bedc5a2e2f2973416c66791cf012696a0e95f7a4dadb86f925fc1943cb2b75fb3eda30f7779edff7cce95ae6f0f7b45ac207a4de4ec012a3654103136e11eb496276647d5e8f6e1659951fc7ef78d60e9430027e826f2aaab7c93ef58a5af47b92cec2f17903a26e2cc5d8d09b1db55e568bfb23a6b6b46125daf71a2f3a708676101d1b657cd38e81deb74d5d877b3321349cd667c29359b45b82218ad96f6c805ac3439fc63f0c91d66da36bae3f176c23b45b8ca1945fb4a4cea5c4a7b0f6ffd547614e7016f94d3e7889ccac868578ea779cd7e6b015aafd296dd5e2da2aa7e2f2af2ce6605f53613f069194dff35ffb9a2ebb30e011c26f669ededa2c91ffb06fedc44cf23f35d7d2716abcd50a8f561721d613d8f2c689ac245a5ac084fa86c72bbe80da7d508e63d891db528fa9e8f0d608034cd97dfde70f739857672e2d70070e850c3a6521067c1774244b86cca835ca8ff1748516e694ea2b5b42555f0df9cb9ec78825c351df51a76b6fe23b58ab3e87ba94ffbb98c9fa9d50c0c282ed0e506bcad24c02d8b625b4bdac822a9e5c911d095c5e4d3bf03448add978e0e7fab7f8a7008568f01a4f06f155223086bdcfe6879e76f199afb9caeadebaa9ec4ec8120f4ccfc4f5f7d7e3cc4dd0cba4d11546d8540030769c4b6d54abdd51fa1f30da642e5ff5c35d3e711c8931ff79e9f256ac6416e99943b0000bf32a5efdd5cf1cd668a62381febe959ca472be9c1a9bade59dbba07eb035ddb1e64ae2923bd276deed788db7600d776f49339215", "RickRoll"},
	{"$odf$*0*0*1024*16*399a33262bbef99543bae29a6bb069c36e3a8f1b*8*6b721193b04fa933*16*99a6342ca7221c81890035dc5033c16f*0*ef8692296b67a8a77344e87b6193dc0a370b115d9e8c85e901c1a19d03ee2a34b7bf989bf9c2edab61022ea49f2a3ce5a6c807af374afd21b52ccbd0aa13784c73d2c8feda1fe0c8ebbb94e46e32904d95d1f135759e2733c2bd30b8cb0050c1cb8a2336c1151c498b9609547e96243aed9473e0901b55137ed78e2c6057e5826cfbfb94b0d77cb12b1fb6ac2752ea71c9c05cdb6a2f3d9611cb24f6e23065b408601518e3182ba1b8cef4cfcdf6ceecb2f33267cf733d3da715562e6977015b2b6423fb416781a1b6a67252eec46cda2741163f86273a68cd241a06263fdd8fc25f1c30fd4655724cc3e5c3d8f3e84abf446dd545155e440991c5fa613b7c18bd0dabd1ad45beb508cfb2b08d4337179cba63df5095b3d640eadbd72ca07f5c908241caf384ca268355c0d13471c241ea5569a5d04a9e3505883eb1c359099c1578e4bc33a73ba74ceb4a0520e0712e3c88582549a668a9c11b8680368cfbc3c5ec02663ddd97963d9dacefed89912ffa9cd945a8634a653296163bb873f3afd1d02449494fab168e7f652230c16d35853df1164219c04c4bd17954b85eb1939d87412eeeb2a039a8bb087178c03a9a40165a28a985e8bc443071b3764d846d342ca2073223f9809fe2ee3a1dfa65b9d897877ebb33a48a760c8fb32062b51a96421256a94896e93b41f559fdec7743680a8deacff9132d6129574d1a62be94308b195d06a275947a1455600030468dde53639fd239a8ab074ec1c7f661f2c9e8d60d6e0e743d351017d5c3d3be21b67d05310d0c5f3fd670acd95ca24f91b0d84d761d15259848f736ff08610e300c31b242f6d24ac2418cdd1fe0248f8a2a2f5775c08e5571c8d25d65ff573cc403ea9cad3bafd56c166fbcec9e64909df3c6ec8095088a8992493b7180c4dbb4053dcb55d9c5f46d728a97ae4ec7ac4b5941bcc3b64a4af31f7dc673e6715a52c9cdbe23dc21e51784f8314c019fc90e8612fcffe01d026fd9e15d1474e73dedf1d3830da81320097be6953173e4293372b5e5a8ecc49ac8b1a658cff16ffa04a8c1728d02ab67694170f10bc9030939ff6df3f901faa019d9b9fd2ba23e89eb0bbaf7a69a2272ee1df0403e6435aee147da217e8bf4c1ee5c53eb83aac1b3f8772d5cd2a2686f312ac4f4f2b0733593e28305a550dbbd18d3405a464ff20e0d9364cfe49b82a97ef7303aec92004a3476cf9ad012eaaf10fd07d3823e1b6871e82113ecfe4392854de9ab21ab1e33ce93d1abb07018007f50d641c8eb85b28fd335fd2281745772c98f8f0bba3f4d40ba602545ef8a0db3062f02d7ee5f49b42cbe19c0c2124952f98c49aff6927110314e54fe8d47a10f13d2d4055c1f3f2d679d4043c9b2f68b2220b6c6c738f6402c01d000c9394c8ed27e70c7ee6108d3e7e809777bab9be30b33a3fb83271cbf3b", "WhoCanItBeNow"},
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[32 / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int cipher_type;
	int checksum_type;
	int iterations;
	int key_size;
	int iv_length;
	int salt_length;
	unsigned char iv[16];
	unsigned char salt[32];
	unsigned char content[1024];
} *cur_salt;

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$odf$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 6;	/* skip over "$odf$*" */
	p = strtok(ctcopy, "*");
	cs.cipher_type = atoi(p);
	p = strtok(NULL, "*");
	cs.checksum_type = atoi(p);
	p = strtok(NULL, "*");
	cs.iterations = atoi(p);
	p = strtok(NULL, "*");
	cs.key_size = atoi(p);
	p = strtok(NULL, "*");
	/* skip checksum field */
	p = strtok(NULL, "*");
	cs.iv_length = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.iv_length; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.salt_length = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	for (i = 0; i < 1024; i++)
		cs.content[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	free(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	ctcopy += 6;	/* skip over "$odf$*" */
	p = strtok(ctcopy, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	free(keeptr);
	return out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char key[32];
		unsigned char hash[32];
		BF_KEY bf_key;
		int bf_ivec_pos;
		unsigned char ivec[8];
		unsigned char output[1024];
		if(cur_salt->checksum_type == 0 && cur_salt->cipher_type == 0) {
			SHA_CTX ctx;
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, (unsigned char *)saved_key[index], strlen(saved_key[index]));
			SHA1_Final((unsigned char *)hash, &ctx);
			derive_key(hash, 20, cur_salt->salt,
					cur_salt->salt_length,
					cur_salt->iterations, key,
					cur_salt->key_size);
			bf_ivec_pos = 0;
			memcpy(ivec, cur_salt->iv, 8);
			BF_set_key(&bf_key, cur_salt->key_size, key);
			BF_cfb64_encrypt(cur_salt->content, output, 1024, &bf_key, ivec, &bf_ivec_pos, 0);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, output, 1024);
			SHA1_Final((unsigned char*)crypt_out[index], &ctx);
		}
		else {
			SHA256_CTX ctx;
			AES_KEY akey;
	                unsigned char iv[32];
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, (unsigned char *)saved_key[index], strlen(saved_key[index]));
			SHA256_Final((unsigned char *)hash, &ctx);
			derive_key(hash, 32, cur_salt->salt,
					cur_salt->salt_length,
					cur_salt->iterations, key,
					cur_salt->key_size);
			memcpy(iv, cur_salt->iv, 32);
			memset(&akey, 0, sizeof(AES_KEY));
			if(AES_set_decrypt_key(key, 256, &akey) < 0) {
				fprintf(stderr, "AES_set_derypt_key failed!\n");
			}
			AES_cbc_encrypt(cur_salt->content, output, 1024, &akey, iv, AES_DECRYPT);
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, output, 1024);
			SHA256_Final((unsigned char*)crypt_out[index], &ctx);
		}
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void odf_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main odf_fmt = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		odf_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		odf_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

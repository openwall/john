/*
 * This software is Copyright (c) 2016, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_bks;
#elif FMT_REGISTERS_H
john_register_one(&fmt_bks);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "hmac_sha.h"
#include "twofish.h"
#include "sha.h"
#include "loader.h"
#include "simd-intrinsics.h"
#include "pkcs12.h"

#define FORMAT_LABEL		"BKS"
#define FORMAT_NAME		"BouncyCastle"
#define ALGORITHM_NAME		"PKCS#12 PBE (SHA1) " SHA1_ALGORITHM_NAME
#define PLAINTEXT_LENGTH	31
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		sizeof(uint32_t)
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x507 // FIXME: format lacks cost
#if !defined(SIMD_COEF_32)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	4
#else
#define MIN_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT	(SSE_GROUP_SZ_SHA1 * 4)
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               16 // Tuned w/ MKPC for core i7
#endif

#define FORMAT_TAG		"$bks$"
#define FORMAT_TAG_LENGTH	(sizeof(FORMAT_TAG) - 1)

#define MAX_STORE_DATA_LENGTH	8192 // XXX ensure this is large enough

static struct fmt_tests tests[] = {
	{"$bks$0$1$20$2036$20$a2c6157bea089967ccfa13670ae992a1265ab7b5$01001a636861726c65732070726f78792073736c2070726f7879696e6700000140737320ac000000000005582e353039000004623082045e30820346a003020102020101300d06092a864886f70d01010505003081913123302106035504030c1a436861726c65732050726f78792053534c2050726f7879696e6731243022060355040b0c1b687474703a2f2f636861726c657370726f78792e636f6d2f73736c3111300f060355040a0c08584b3732204c74643111300f06035504070c084175636b6c616e643111300f06035504080c084175636b6c616e64310b3009060355040613024e5a3020180f31383939313233313132303030305a170d3338303932343033313930355a3081913123302106035504030c1a436861726c65732050726f78792053534c2050726f7879696e6731243022060355040b0c1b687474703a2f2f636861726c657370726f78792e636f6d2f73736c3111300f060355040a0c08584b3732204c74643111300f06035504070c084175636b6c616e643111300f06035504080c084175636b6c616e64310b3009060355040613024e5a30820122300d06092a864886f70d01010105000382010f003082010a02820101008349587455efb272e397a31d3b52d9b13115c93f320766d2d451117f45c40285506027079ed439cabb94d44f1ae136eb1e79bf77abe43345ad1d436809cf9e035c439272f3ca917dcadd7fbd0e3929f1a345f0b89096130bbd116f8d3ab5655789b7b0831325bd22903f198da6bdda30c08dfd17ce9ab51c48555264307bcf789a2b6c48df4ecaf3ea2c092ee737ad8f397900ac03303bfe2ae43549030a7866cb6fe9b04b9f6ec498b4e7369e99b45491bf093858a77c72f8adc818e018d413265e39446be514f78eb57a23aa88f630776f861a9163e04ad38ee8a5c9219d0fc23f6b9a6324455dea6f4a6a251eca1fa3d6288cb89fd12a2062a3a015a56f250203010001a381bc3081b9300f0603551d130101ff040530030101ff307706096086480186f842010d046a136853534c2050726f7879696e6720697320656e61626c656420696e20436861726c65732050726f78792e20506c6561736520766973697420687474703a2f2f636861726c657370726f78792e636f6d2f73736c20666f72206d6f726520696e666f726d6174696f6e2e300e0603551d0f0101ff040403020204301d0603551d0e04160414bb27f4cb2eb6dbb058101bbd803f38d208d76129300d06092a864886f70d010105050003820101000041f935f30b209e56360f7e3d9c30314a213323c47edcea1467600a50ffe4e8e39dfca8c8d34463c34745ff04c870f1df28bb772db0cf1bca677b70842c742bc6d5fb00559ad643c6bf2c95bd0b855a961d7d6a3eada9c642e9a789474c4ad838c6f732d8d859548d30829df7a32d098fe3f00147daf08c0b37dd597184c1e27a61ea42050c73994e809013cb21e37bf84bf923bcefea6164fd28ab9058ccc48f1f486fc1c47ebd8a9c933f542401b11f36a003e47b141a41c7b326d18d023e11edb445699aa44800254ea33f174fd5eb1ccce6a09365751ff905988c06315b5575067bf65ec24cad1a6a601846d1d2f51f1f420a2762990b044000619d1c8400$3b798574df20a2be48edb0b0c687cce2cf5c293c", "secret"},
	// https://github.com/doublereedkurt/pyjks/blob/master/tests/keystores/bks/christmas.bksv1
	{"$bks$0$1$20$1730$20$a9e6ba49c14bd8fd2c973d48f0241a4208effcfd$020009706c61696e5f6b657900000154b6ca8fa5000000000200035241570003444553000000084cf2fe915d082a430400127365616c65645f707269766174655f6b657900000154b6ca8f6e000000010005582e3530390000019c3082019830820101a003020102020100300d06092a864886f70d01010b050030123110300e06035504030c0752534131303234301e170d3136303531353233343030385a170d3138303531353233343030385a30123110300e06035504030c075253413130323430819f300d06092a864886f70d010101050003818d0030818902818100b7201edbbf265bb253c299533704df2c990978c16e97a04b9556a6af1df11e60e5e138502fc1337879dfdd4461ede4f08b3303fd1b80befb1be09d9c3fcffc2c1caeb9c83d0142dac39d7c341bd4bc07b7fee23c162941f4b4fb221d9f93388cce2b21beffdd458be9244babf34e28f25ae620b4b883617bb5e9851364c0dd350203010001300d06092a864886f70d01010b05000381810097c7fb5997212b8ff7afa863be886d1d1a0947b7392d83a6304b60cbb76a9f7172095f123254aafdd315d933650993df354f82ac85d9467178ba8eda397149cf0df4dbba9d7bdbdffd83b710c2c8c8bf25ef4dda3d49cca820159eeb97b133c5f324219b4d1294d524a85d5e6b77e38f42814052f5134a938d29342b21bed1a4000002ac00000014ad6391270981b833ba68bbfa225f087ab7e345240000075cea5b86ca6a5e80e0b1fd06a745bcc2bef875e4746db35c59a00bbac4f398cf202fe97b60813848b21c7a36f3faccac560bd05506f5b44322ed519af34190bdf10905e81d8569c3c32db3238bfefee5328c21883d82c6b9a9e07cf975aa8559368b2f9212a7e01103c21c5136e6da0b0ecdd8bcba1e071f9f084d59349c18d4e6af418ab0ca9ce73fa4bd38e1bf84e809f001069f9c821d3ee44bb23182d229b782607bd47e68e7ff299ed1e28f7cb3cb03af5ef90711db5b306ec592a2bef7a5559a06290eaab19ab77a02caf3297e24bdc1aeb14d99d2e838863f355c738d91e4496e4f10f5a7bde22c0425524e164f198407ad99d5433fdbd6bd2adf50bbe2c909ae4e18effa5fb62059614aa646639fe4963f5e34d33b030e708fe5a816cb3d9596a0e394114f2622ce7694174e2399de1e04ae42022cceb2f5da0c273f7fc6f45bd7991b8e85df594a171a0fe64a73e1b9a0f57492eaaa35d5498c7ebbd28fcd23c12a006fc147cd5209168eadf40b53d4196066352e7cf562858c62dd746f43c48542d174857d03142a680b975948ebba31ad1010d1a7fbf8cbc3c0b16c376d8567212666aa01a420db3028695c289f0625e4d8fb872c358fb9e821c6346055d7c04ec545688cd011e9f60ba2e80959ec8fed703044ea7422d0ce4f7a401a05db9afc30b39c64b0e118599f39124df1c28298ee625a3c0095e0ecb14ae72dacc8106a52a258ea1e2554005bfa7c4e90e1a999a949e6bead7f333de2bb036b047c86cb1e6c8931d189b07647e500c04f8c4772fa630c328d60b0cb3a9e209ba0e574194dd96f4f4e6465273ae7c6c5d73eec505da065294803971584a60b2222bff62b36ad59cfcff893999ff484f2849186284303c1c2369445d466850ec7737d8313229af62576bfc2962284650400117365616c65645f7075626c69635f6b657900000154b6ca8f9500000000000000d400000014a39c93f59d151905a421db0646b31841d7ddb375000004e5faab6bfd6d6ddef0253fb9669a8ce679b583b4d8e18d42a62504e916c9647ff3b00eaad96e5410ab11bbf642e297c60954bdb065da4db0a69e0b2e6baa5ed8361939d4aec7599919d20cbaf05483655a4a5bb7fcc1b7ff33196a7df54779245d14f2f68636d1983d03c2af9ebbc78ed57116f58b019d810a8d9f03b45b4d56b2fbfeab0f7c8d506e1add5cd83fe06be0873cff5a198d213085df165dbf8d98371b9bf2d9ecc67a91f8ac731eecdbc7c46661fe4efb470da50100046365727400000154b6ca8f6e000000000005582e3530390000019c3082019830820101a003020102020100300d06092a864886f70d01010b050030123110300e06035504030c0752534131303234301e170d3136303531353233343030385a170d3138303531353233343030385a30123110300e06035504030c075253413130323430819f300d06092a864886f70d010101050003818d0030818902818100b7201edbbf265bb253c299533704df2c990978c16e97a04b9556a6af1df11e60e5e138502fc1337879dfdd4461ede4f08b3303fd1b80befb1be09d9c3fcffc2c1caeb9c83d0142dac39d7c341bd4bc07b7fee23c162941f4b4fb221d9f93388cce2b21beffdd458be9244babf34e28f25ae620b4b883617bb5e9851364c0dd350203010001300d06092a864886f70d01010b05000381810097c7fb5997212b8ff7afa863be886d1d1a0947b7392d83a6304b60cbb76a9f7172095f123254aafdd315d933650993df354f82ac85d9467178ba8eda397149cf0df4dbba9d7bdbdffd83b710c2c8c8bf25ef4dda3d49cca820159eeb97b133c5f324219b4d1294d524a85d5e6b77e38f42814052f5134a938d29342b21bed1a403000c73746f7265645f76616c756500000154b6ca8f9f0000000000000009020305070b0d1113170400117365616c65645f7365637265745f6b657900000154b6ca8f9a000000000000003c00000014b3cd07a06cc6354ffaae1a63a297e46ed8791ff800000437fc0a1b31876167b84e1d85b00dfdae0ee0ad42ad3cfdae41f8022e1a719f56eb00$fdf1915288bcaa30ad5192bcc327db290b1c21e0", "12345678"},
	// https://github.com/doublereedkurt/pyjks/blob/master/tests/keystores/bks/christmas.bksv2
	{"$bks$0$2$160$1141$20$de18c5bf26bbce0c7a3e6b9685f3028c3a58c5c2$020009706c61696e5f6b657900000154b6ca8fe3000000000200035241570003444553000000084cf2fe915d082a430400127365616c65645f707269766174655f6b657900000154b6ca8fbd000000010005582e3530390000019c3082019830820101a003020102020100300d06092a864886f70d01010b050030123110300e06035504030c0752534131303234301e170d3136303531353233343030385a170d3138303531353233343030385a30123110300e06035504030c075253413130323430819f300d06092a864886f70d010101050003818d0030818902818100b7201edbbf265bb253c299533704df2c990978c16e97a04b9556a6af1df11e60e5e138502fc1337879dfdd4461ede4f08b3303fd1b80befb1be09d9c3fcffc2c1caeb9c83d0142dac39d7c341bd4bc07b7fee23c162941f4b4fb221d9f93388cce2b21beffdd458be9244babf34e28f25ae620b4b883617bb5e9851364c0dd350203010001300d06092a864886f70d01010b05000381810097c7fb5997212b8ff7afa863be886d1d1a0947b7392d83a6304b60cbb76a9f7172095f123254aafdd315d933650993df354f82ac85d9467178ba8eda397149cf0df4dbba9d7bdbdffd83b710c2c8c8bf25ef4dda3d49cca820159eeb97b133c5f324219b4d1294d524a85d5e6b77e38f42814052f5134a938d29342b21bed1a4000002ac00000014755493361b0d7e3d4daed45a75199454cfe61585000005acae83870b92b606cc44facf5ce35598be2da231bf4ae80da2c2157f89e841d27e98416e569fca7842acf0542f6b4027682c565bcad8a169c4a641929f19be3935446cf41c5994bf8a5b3fef45b640dacd9396e501a957e5d8d0a93bdf308640378788b6c0be629a8b6bd8cfa874ee3d71998ff6dd550a7865e36b373981ca42a70c0228193b717a98ea0da7817cb6f8f7d4fc4061acb6a39eb4bce14b98a94388f28ddd87dfbc13ac925fb2c1dd7a907485a34d66832b72eb92cb8e60c09c17b3a95769a81e773c248256146f5c3c8f04ffb26a75a8314c9c3be058963c9907a52e2f05cc1ca4921ac0b34ec8f6a1b27013f57399c20c681ef3f0f6f5a2879a2af4a7e746d2ddfd0b33917abd005dc59225fda2a7d1fe026ce8014e85bfc8e23932b3ae6af53a6ebe52def1f89942ec899eff2e74324ce45329c02114003dfc26211fdc3a0f3a9045331c2b0fe20c0985e4e24725c959c19c87b1679f76c2aefe447413adddf992bdc143b023373c894ebed1e2106236ebbbc8bf6d71c5770c50aab7c38e054299391ccaba845b11f88f40e12d126fa94584621921355caf293e876b71ba9e74d7577a83737ca92e581454bd1f6ea271379846aca2dc032d53181d7b8f61f98cbc43215023b512b39176650db6dabb6d038f7890d1d730da57e2f4595e9edc6466cf1eca12fd35413834a957cc341181439de13971c67794d8fadf2bcb296cf8e1a2058957af2a194e32599626f86d4dae838f944c7d495c9a36c72190fdd2cf55bafd12134383832bb8c23597d0dcc87754f575e77ccc802ba0f3d7662f01db277d95bcddec55927af67753e07c0d4ee509465a122c6b0adb097d92158479d4836dc2e03b3a493d44dda8eb9895327216460d2926e122868af3f6f82db073af041b66668e2e16b882690400117365616c65645f7075626c69635f6b657900000154b6ca8fcc00000000000000d400000014921f89acc2d3f90372e5b61a04294b6efb34075100000434a69feb6389d6bb8b561139a8c877ae1ae87167a709008e55350abbdd8fa0a77dbe1609e2685fcae5c42825c7dc65ac0dc2fce4a4d8688b71eaaa094461cadce7c74d9a4bfb507d7fb4d31567d934f5e69829c12bdccc494876fd3fa12bde21c3c1525e05c580c87a4272212f0c3bce9fc9a32716ebfb50333563529a2bbc92a56a811c083135ed2fc38d4a203d3bc2fa3cddeac9e8d6cbc760beaedb8dd9312e8d30be0f6976f9ab7681c5902ab210c2d11202d9181a8d250100046365727400000154b6ca8fbd000000000005582e3530390000019c3082019830820101a003020102020100300d06092a864886f70d01010b050030123110300e06035504030c0752534131303234301e170d3136303531353233343030385a170d3138303531353233343030385a30123110300e06035504030c075253413130323430819f300d06092a864886f70d010101050003818d0030818902818100b7201edbbf265bb253c299533704df2c990978c16e97a04b9556a6af1df11e60e5e138502fc1337879dfdd4461ede4f08b3303fd1b80befb1be09d9c3fcffc2c1caeb9c83d0142dac39d7c341bd4bc07b7fee23c162941f4b4fb221d9f93388cce2b21beffdd458be9244babf34e28f25ae620b4b883617bb5e9851364c0dd350203010001300d06092a864886f70d01010b05000381810097c7fb5997212b8ff7afa863be886d1d1a0947b7392d83a6304b60cbb76a9f7172095f123254aafdd315d933650993df354f82ac85d9467178ba8eda397149cf0df4dbba9d7bdbdffd83b710c2c8c8bf25ef4dda3d49cca820159eeb97b133c5f324219b4d1294d524a85d5e6b77e38f42814052f5134a938d29342b21bed1a403000c73746f7265645f76616c756500000154b6ca8fe30000000000000009020305070b0d1113170400117365616c65645f7365637265745f6b657900000154b6ca8fd1000000000000003c000000146c18877619eac9f77da0d86bd8a18639eb084f5f000004bd0c558b25c1657b8b9c25079e64196fe43e9fec0ef5d44b2d8a0dbd09c92a8b4e00$3b99d6fd87755af63606414be2b75b9cfa3751c7", "12345678"},
	// christmas.uber
	{"$bks$1$1$20$1141$20$fcc7b038c0ca3e1b99e0bc1192ed999a66129a2d$c561a20373785bfa46d530192cfe16c3edf9ccacc75e53d2c1c7bafd64c77d1aea9c52817d9a93224bf49cca1273de0856d32a82f4ce97b550abb98fd9f82297814784774396bea9fb3282fdb75b33ed59d52a5eefc2486b0726dc2156ca8257f41d033f8c41276ce78c2155b80eeb97d9a3d8e065a73bb9d5ab1840d60ea56cc04b00a87346d8a580829b9e437869b4a39626b1d17e169589de1e78e8cd6261dcd8b48a3ae52b89f90b2af60f395aff5cca0281c5b6f5b4dcdb8d9a30090e41dc033c0a0426d03c35ec1264c5ca1710c32d69fe6f222cd913f56392d3c4e3c80a0a6118bd4054a3f932728b9f855ac3ed45f1ec9209c2be6e807ec427e576781244df751f52f858c23a7985ed667ed739eee6151ad0d28f520406eb30a8c27da2fd5cdb471cd73e5c1f0c746527414a65efa39b336aeb43f03c556f01e4aec7f464313d4f238316ab229d854bc48e6dad068c9a56a00f2c188cea1baeea08420f1ee82789a089678b9bf134b95147c83f0962e5f45c96e5a9b43628c4df0f415885f857932d9344c409a25d8ff7918d228ddc25a5940f18f00f1a83b7ccbe520dca92eb9a360857857c46a70c0becfff0a66286488313835406e6e9e9053d1e139226e82471171f1748a0447b2efd015d87399118c548a048270c61034c832265bd9104be3ea7910c9e730c2d2ddfb5edc761634a388ae364c91b2662ce4e437e0f954cf14dee83e01dec7c7aeb8d0c63ed099e8ec28aa64b54368159ec819d69fb028554ad32af7318602b98fa2d0cfed206ae8973a6c305c80f8972f9b245808364d599c9cd6847ba2ee44e9fe07be2c2323ea28ff8d8965036849085d9947153730a367e955b67d195510c6a73993c403224bc5877bcf04be2b9c42c7fe3ea28c953e4c21278b3e12f21a541758f41b08689eba4985ad18e6e113f3abef6479df04aac104079ab8677cfeae33bc090d47f7f17c1386bdf099282fa079a48ce4f94d661f4ec762892faf680131f0372555f3436ac7b364eb64570d1b46e3d8ebd97236d01abe217c8a95ab0ba097a56f45f96c18b777343e7214748262f083a9fdcd4e4331e50d17dc58dfedfa459e87bd71be8a09283b25b1a0e6daba7d03ca2580c02edcae8e43f2d8ebdff37385bdcfa73f057d636c970278a01b7a1f02878e1961ef5a7fab4bd2e788bf356688f5b47d1573db600d91474c5a802ce27c789fd02df30ab719f8bcd7c58eb5bd45b9e20d1bb2f26c1f3cdd32247dd7268f56cb187734e0d977a5b2aef80622960156042b65448eee980f7d77d8b2519aa5f216a6300c8b534220feaf56ade0369e5082fc4dd623f134abef8b8253b4e7dc8a9a40188598b18512ba77d009c5fbdd2159fd8707dfea97b1e7e8c4297dd7499aaaa7c09097f057badc385e9de29a2b668529fc280f6cea1078d0d79834763a24ba38f19e4654dfe7cbb9ff08f122509433a3d9d055b864c8a9a88518fd93e50ee9c7f678aaf52c25f3f4858996add60e6c21204c1e22fbb02b9090578cc1f42861dc93f955d81f00decee8fe7405367ee986835b0be865084964226e47c77c764b823421383299e76fbcfd64c2ad085681110f772e4c2f526eab0d6a7a771814613f745230ac8bd1055c5612f17cb3b5c4459b809f082bb11bfdee8d1db48d0616e51ee77594ad92a417027665beb208888f5b030a022bf9850d69d18e883fcb4c47274db3708d5a5c59bc1e25842de6dce350d1c2c16d7f9c7103ed15c6f25508cc27199569d24bf7e55e960a0006e177470a1a3cc33f540324565c0a67d20a2c7b8389e8aa375e4b4515d451ce0dce43cf99a2a6f2f6adba5206c243a8aa2a974a2737923b61f8c3c86253fe896fd9c8ab9a66f17086dde38b539cb23a2d7e261299d8dc12639cdbd56a5813026a3670f9ac79346b302b00f1c3d41fd566d9e3a3ad2d756948f5f97e1967fcc1410a1078191fb89b51a137a70ae505dfa65a96b9e4d70f562b4f2c715c1f782fd79d02f98aead88f1eb5d8722b4fef4699218f003f99270b852a0f892f9f23827820900288a4a1fa5978b44bd3035de46f6aa8a3e32ade38190756658836c0fde5b9b34a16a8e97cdcbace80bb86d88dceaeb9a2b87ff2a02bd004bb1d4f08232b91b476b3ca0873ef132b0a70d939a11c4fe66bc2b113eba14c2e4728499441b6f26ec014968c95e71ff23d33c4267c67af21b393a770e03a8781b10159a20cfceab34dc592a394e11fd649cfe71eaf7ef7de863d1a6eff623a67b7cc94b114cc646df2380e4851c614eb54d59476419964063d9f85661c079719ba4d2ce5872820f18a34f384dd48fb20907c8ffa521ef3e6a4302524c442a2230f8b574a82e78f1e699d3b2621132bda6a3238e9b41bd773d3d476dfc11ef549683b789e286a54d4c8ea01a727f9bdbfd6310e8882b2ed26b75edc9958cabe3beed1cc167c7f2ab759326b0e4026ac63e2489ea4da6814fbf547a6637fc1d0fc78f79c5517b7e329ea226c2d29281cac160a7709953ab1dcdb731e68b940106bee0d9d68720b66d2953ad3d2185596850dbb4cfc3654161fbfee8be7258b9a46a82e8c8c908fc93c235b9ae101b4e66c7b52434fe6c4147f035cd5d42a4a8b047d33d907e89018a994f343f241643ad1273ca8d486de956931e7f94c197460ec09c100fb27ef98d1e57e1cb736adb943a83193ce586aa5c61e5c0bd25f5fd846beb9cb8212643b752e0373f17a0061a5b350b4d06b405c5c0949b5733996eb67262893ecb4bd1213a04ad4c7900b441c103250a01b41075b70f13c26937b149e41c180f55b8d472273679032c1a16058d05e43fedcde7164527ca82b160cc9deb53675bbe0db70a47a5decc64f500d9dd7686240366$0000000000000000000000000000000000000000", "12345678"},
	{NULL}
};

#ifdef _MSC_VER
#define custom_salt bks_custom_salt
#define cur_salt    bks_cur_salt
#endif

static struct custom_salt {
	int format; // 0 -> BKS keystore
	int version; // BKS version
	int hmac_key_size;
	int iteration_count;
	int saltlen;
	unsigned char salt[20];
	int store_data_length;
	unsigned char store_data[MAX_STORE_DATA_LENGTH];
	unsigned char store_hmac[20];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static size_t *saved_len;
static int *cracked, any_cracked;  // "cracked array" approach is required for UBER keystores

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_len));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));
	Twofish_initialise();
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int format, version, saltlen, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // format
		goto bail;
	if (!isdec(p))
		goto bail;
	format = atoi(p);
	if (format != 0 && format != 1) // 0 -> BKS keystore, 1 -> UBER keystore
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // version
		goto bail;
	if (!isdec(p))
		goto bail;
	version = atoi(p);
	if (version != 1 && version != 2) // BKS, BKS-v1
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // hmac_key_size
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iteration_count
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // saltlen
		goto bail;
	if (!isdec(p))
		goto bail;
	saltlen = atoi(p);
	if (saltlen > 20)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) > saltlen * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // store_data
		goto bail;
	if (hexlenl(p, &extra) > MAX_STORE_DATA_LENGTH * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // store_hmac
		goto bail;
	if (hexlenl(p, &extra) != 20*2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;

	p = strrchr(ciphertext, '$');
	if (!p)
		goto bail;
	p = p + 1;
	if (!ishexlc(p))
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;
	memset(&cs, 0, sizeof(cs));

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.format = atoi(p);
	p = strtokm(NULL, "$");
	cs.version = atoi(p);
	p = strtokm(NULL, "$");
	cs.hmac_key_size = atoi(p);
	p = strtokm(NULL, "$");
	cs.iteration_count = atoi(p);
	p = strtokm(NULL, "$");
	cs.saltlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.saltlen; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	cs.store_data_length = hexlenl(p, 0) / 2;
	for (i = 0; i < cs.store_data_length; i++)
		cs.store_data[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	if (cs.format == 0) { // BKS keystore
		for (i = 0; i < 20; i++)
			cs.store_hmac[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
#if !ARCH_LITTLE_ENDIAN && !defined(SIMD_COEF_32)
		alter_endianity(cs.store_hmac, 20);
#endif
	}
#if !ARCH_LITTLE_ENDIAN && !defined(SIMD_COEF_32)
	alter_endianity(cs.store_hmac, 20);
#endif
	MEM_FREE(keeptr);

	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int index;
	const int count = *pcount;

	if (any_cracked) {
		memset(cracked, 0, sizeof(*cracked) * count);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#if !defined(SIMD_COEF_32)
		if (cur_salt->format == 0) {
			unsigned char mackey[20];
			int mackeylen = cur_salt->hmac_key_size / 8;
			// mackeylen is only 2 bytes, and this results in lot
			// of collisions (which work just fine)
			//
			// FMT_NOT_EXACT can be turned on for BKS keystores
			// for finding more possible passwords
			unsigned char store_hmac_calculated[20];

			pkcs12_pbe_derive_key(1, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_MAC_KEY,
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->saltlen, mackey, mackeylen);

			hmac_sha1(mackey, mackeylen, cur_salt->store_data,
					cur_salt->store_data_length,
					store_hmac_calculated, 20);

			if (!memcmp(store_hmac_calculated, cur_salt->store_hmac, 20))
			{
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		} else if (cur_salt->format == 1) {
			unsigned char compute_checkum[20];
			unsigned char iv[16];
			unsigned char key[32];
			Twofish_key tkey;
			int datalen = 0;
			unsigned char store_data_decrypted[MAX_STORE_DATA_LENGTH];
			SHA_CTX ctx;

			pkcs12_pbe_derive_key(1, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_IV,
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->saltlen, iv, 16);
			pkcs12_pbe_derive_key(1, cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_KEY,
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->saltlen, key, 32);
			Twofish_prepare_key(key, 32, &tkey);
			datalen = Twofish_Decrypt(&tkey, cur_salt->store_data, store_data_decrypted, cur_salt->store_data_length, iv);
			if (datalen < 0)
				continue;
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, store_data_decrypted, datalen - 20);
			SHA1_Final(compute_checkum, &ctx);

			if (!memcmp(compute_checkum, store_data_decrypted + datalen - 20, 20))
			{
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
#else
		size_t lens[SSE_GROUP_SZ_SHA1], j;
		const unsigned char *keys[SSE_GROUP_SZ_SHA1];
		// Load keys, and lengths
		for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
			lens[j] = saved_len[index+j];
			keys[j] = (const unsigned char*)(saved_key[index+j]);
		}

		if (cur_salt->format == 0) {
			unsigned char *mackey[SSE_GROUP_SZ_SHA1], real_keys[SSE_GROUP_SZ_SHA1][20];
			int mackeylen = cur_salt->hmac_key_size / 8;
			// mackeylen is only 2 bytes, and this results in lot
			// of collisions (which work just fine)
			//
			// FMT_NOT_EXACT can be turned on for BKS keystores
			// for finding more possible passwords
			unsigned char store_hmac_calculated[20];

			for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j)
				mackey[j] = real_keys[j];
			pkcs12_pbe_derive_key_simd_sha1(cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_MAC_KEY,
					keys, lens, cur_salt->salt,
					cur_salt->saltlen, mackey, mackeylen);

			for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
				hmac_sha1(mackey[j], mackeylen, cur_salt->store_data,
						cur_salt->store_data_length,
						store_hmac_calculated, 20);

				if (!memcmp(store_hmac_calculated, cur_salt->store_hmac, 20))
				{
					cracked[index+j] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
					any_cracked |= 1;
				}
			}
		} else if (cur_salt->format == 1) {
			unsigned char iv_[SSE_GROUP_SZ_SHA1][16], *iv[SSE_GROUP_SZ_SHA1];
			unsigned char ckey_[SSE_GROUP_SZ_SHA1][32], *ckey[SSE_GROUP_SZ_SHA1];
			Twofish_key tkey;
			int datalen = 0;
			unsigned char store_data_decrypted[MAX_STORE_DATA_LENGTH];
			SHA_CTX ctx;

			for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
				iv[j] = iv_[j];
				ckey[j] = ckey_[j];
			}
			pkcs12_pbe_derive_key_simd_sha1(cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_IV,
					keys,
					lens, cur_salt->salt,
					cur_salt->saltlen, iv, 16);
			// lengths get tromped on, so re-load them for the load keys call.
			for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j)
				lens[j] = saved_len[index+j];
			pkcs12_pbe_derive_key_simd_sha1(cur_salt->iteration_count,
					MBEDTLS_PKCS12_DERIVE_KEY,
					keys,
					lens, cur_salt->salt,
					cur_salt->saltlen, ckey, 32);
			for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
				unsigned char compute_checkum[20];
				Twofish_prepare_key(ckey[j], 32, &tkey);
				datalen = Twofish_Decrypt(&tkey, cur_salt->store_data, store_data_decrypted, cur_salt->store_data_length, iv[j]);
				if (datalen < 0)
					continue;
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, store_data_decrypted, datalen - 20);
				SHA1_Final(compute_checkum, &ctx);

				if (!memcmp(compute_checkum, store_data_decrypted + datalen - 20, 20))
				{
					cracked[index+j] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
					any_cracked |= 1;
				}
			}
		}
#endif
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

static void set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_bks = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_OMP | FMT_HUGE_INPUT,
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

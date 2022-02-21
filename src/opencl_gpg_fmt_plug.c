/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for GPG format.
 *
 * This software is Copyright (c) 2012 Dhiru Kholia <dhiru at openwall.com>,
 * Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net> and it is hereby
 * released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Converted to use 'common' code, Feb29-Mar1 2016, JimF.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_OPENCL && HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_gpg;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_gpg);
#else

#include <stdint.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "opencl_common.h"
#include "options.h"
#include "gpg_common.h"
#include "twofish.h"

#define FORMAT_LABEL		"gpg-opencl"
#define FORMAT_NAME		"OpenPGP / GnuPG Secret Key"
#define ALGORITHM_NAME		"SHA1/SHA2 OpenCL"
#define BENCHMARK_LENGTH	7
#define SALT_SIZE		sizeof(struct gpg_common_custom_salt*)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} gpg_password;

typedef struct {
	uint8_t v[32];
} gpg_hash;

typedef struct {
	uint32_t length;
	uint32_t count;
	uint32_t key_len;
	uint8_t salt[SALT_LENGTH];
} gpg_salt;

struct fmt_tests gpg_tests[] = {  // from GPU
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*667*2048*387de4c9e2c1018aed84af75922ecaa92d1bc68d48042144c77dfe168de1fd654e4db77bfbc60ec68f283483382413cbfddddcfad714922b2d558f8729f705fbf973ab1839e756c26207a4bc8796eeb567bf9817f73a2a81728d3e4bc0894f62ad96e04e60752d84ebc01316703b0fd0f618f6120289373347027924606712610c583b25be57c8a130bc4dd796964f3f03188baa057d6b8b1fd36675af94d45847eeefe7fff63b755a32e8abe26b7f3f58bb091e5c7b9250afe2180b3d0abdd2c1db3d4fffe25e17d5b7d5b79367d98c523a6c280aafef5c1975a42fd97242ba86ced73c5e1a9bcab82adadd11ef2b64c3aad23bc930e62fc8def6b1d362e954795d87fa789e5bc2807bfdc69bba7e66065e3e3c2df0c25eab0fde39fbe54f32b26f07d88f8b05202e55874a1fa37d540a5af541e28370f27fe094ca8758cd7ff7b28df1cbc475713d7604b1af22fd758ebb3a83876ed83f003285bc8fdc7a5470f7c5a9e8a93929941692a9ff9f1bc146dcc02aab47e2679297d894f28b62da16c8baa95cd393d838fa63efc9d3f88de93dc970c67022d5dc88dce25decec8848f8e6f263d7c2c0238d36aa0013d7edefd43dac1299a54eb460d9b82cb53cf86fcb7c8d5dba95795a1adeb729a705b47b8317594ac3906424b2c0e425343eca019e53d927e6bc32688bd9e87ee808fb1d8eeee8ab938855131b839776c7da79a33a6d66e57eadb430ef04809009794e32a03a7e030b8792be5d53ceaf480ffd98633d1993c43f536a90bdbec8b9a827d0e0a49155450389beb53af5c214c4ec09712d83b175671358d8e9d54da7a8187f72aaaca5203372841af9b89a07b8aadecafc0f2901b8aec13a5382c6f94712d629333b301afdf52bdfa62534de2b10078cd4d0e781c88efdfe4e5252e39a236af449d4d62081cee630ab*3*254*2*3*8*b1fdf3772bb57e1f*65536*2127ccd55e721ba0", "polished"},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*668*2048*e5f3ef815854f90dfdc3ad61c9c92e512a53d7203b8a5665a8b00ac5ed92340a6ed74855b976fc451588cc5d51776b71657830f2c311859022a25412ee6746622febff8184824454c15a50d64c18b097af28d3939f5c5aa9589060f25923b8f7247e5a2130fb8241b8cc07a33f70391de7f54d84703d2537b4d1c307bdf824c6be24c6e36501e1754cc552551174ed51a2f958d17c6a5bd3b4f75d7979537ee1d5dcd974876afb93f2bcda7468a589d8dba9b36afbe019c9086d257f3f047e3ff896e52783f13219989307bf277e04a5d949113fc4efcc747334f307a448b949ee61b1db326892a9198789f9253994a0412dd704d9e083000b63fa07096d9d547e3235f7577ecd49199c9c3edfa3e43f65d6c506363d23c21561707f790e17ea25b7a7fce863b3c952218a3ac649002143c9b02df5c47ed033b9a1462d515580b10ac79ebdca61babb020400115f1e9fad26318a32294034ea4cbaf681c7b1de12c4ddb99dd4e39e6c8f13a322826dda4bb0ad22981b17f9e0c4d50d7203e205fb2ee6ded117a87e47b58f58f442635837f2debc6fcfbaebba09cff8b2e855d48d9b96c9a9fb020f66c97dffe53bba316ef756c797557f2334331eecaedf1ab331747dc0af6e9e1e4c8e2ef9ed2889a5facf72f1c43a24a6591b2ef5128ee872d299d32f8c0f1edf2bcc35f453ce27c534862ba2c9f60b65b641e5487f5be53783d79e8c1e5f62fe336d8854a8121946ea14c49e26ff2b2db36cef81390da7b7a8d31f7e131dccc32e6828a32b13f7a56a28d0a28afa8705adbf60cb195b602dd8161d8b6d8feff12b16eb1ac463eaa6ae0fd9c2d906d43d36543ef33659a04cf4e69e99b8455d666139e8860879d7e933e6c5d995dd13e6aaa492b21325f23cbadb1bc0884093ac43651829a6fe5fe4c138aff867eac253569d0dc6*3*254*2*3*8*e318a03635a19291*65536*06af8a67764f5674", "blingbling"},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*668*2048*8487ca407790457c30467936e109d968bdff7fa4f4d87b0af92e2384627ca546f2898e5f77c00300db87a3388476e2de74f058b8743c2d59ada316bc81c79fdd31e403e46390e3e614f81187fb0ae4ca26ed53a0822ace48026aa8a8f0abdf17d17d72dfa1eba7a763bbd72f1a1a8c020d02d7189bd95b12368155697f5e4e013f7c81f671ca320e72b61def43d3e2cb3d23d105b19fe161f2789a3c81363639b4258c855c5acd1dd6596c46593b2bfec23d319b58d4514196b2e41980fbb05f376a098049f3258f9cdf1628c6ff780963e2c8dc26728d33c6733fbac6e415bd16d924a087269e8351dd1c6129d1ac7925f19d7c9a9ed3b08a53e207ffbfba1d43891da68e39749775b38cbe9e6831def4b4297ce7446d09944583367f58205a4f986d5a84c8cf3871a7e2b6c4e2c94ff1df51cd94aecf7a76cd6991a785c66c78f686e6c47add9e27a6b00a2e709f1383f131e3b83b05c812b2ec76e732d713b780c381b0785f136cd00de7afa0276c95c5f0bb3a4b6ad484d56e390c11f9d975729ae1665189190fd131f49109f899735fd2c2efbafd8b971b196d18aeff70decc9768381f0b2243a05db99bd5911d5b94770ee315e1fe3ab0e090aa460d2c8d06a06fef254fd5fa8967386f1f5d37ea6f667215965eefe3fc6bc131f2883c02925a2a4f05dabc48f05867e68bb68741b6fb3193b7c51b7d053f6fd45108e496b9f8f2810fa75ffe454209e2249f06cc1bfc838a97436ebd64001b9619513bcb519132ce39435ed0d7c84ec0c6013e786eef5f9e23738debc70a68a389040e8caad6bd5bb486e43395e570f8780d3f1d837d2dc2657bbded89f76b06c28c5a58ecaa25a225d3d4513ee8dc8655907905590737b971035f690ac145b2d4322ecc86831f36b39d1490064b2aa27b23084a3a0b029e49a52b6a608219*3*254*2*3*8*0409f810febe5e05*65536*ce0e64511258eecc", "njokuani."},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*348*1024*e5fbff62d94b41de7fc9f3dd93685aa6e03a2c0fcd75282b25892c74922ec66c7327933087304d34d1f5c0acca5659b704b34a67b0d8dedcb53a10aee14c2615527696705d3ab826d53af457b346206c96ef4980847d02129677c5e21045abe1a57be8c0bf7495b2040d7db0169c70f59994bba4c9a13451d38b14bd13d8fe190cdc693ee207d8adfd8f51023b7502c7c8df5a3c46275acad6314d4d528df37896f7b9e53adf641fe444e18674d59cf46d5a6dffdc2f05e077346bf42fe35937e95f644a58a2370012d993c5008e6d6ff0c66c6d0d0b2f1c22961b6d12563a117897675f6b317bc71e4f2dbf6b9fff23186da2724a584d70401136e8c500784df462ea6548db4eecc782e79afe52fd8c1106c7841c085b8d44465d7a1910161d6c707a377a72f85c39fcb4ee58e6b2f617b6c4b173a52f171854f0e1927fa9fcd9d5799e16d840f06234698cfc333f0ad42129e618c2b9c5b29b17b7*3*254*2*3*8*7353cf09958435f9*9961472*efadea6cd5f3e5a7", "openwall"},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*668*2048*97b296b60904f6d505344b5b0aa277b0f40de05788a39cd9c39b14a56b607bd5db65e8da6111149a1725d06a4b52bdddf0e467e26fe13f72aa5570a0ea591eec2e24d3e9dd7534f26ec9198c8056ea1c03a88161fec88afd43474d31bf89756860c2bc6a6bc9e2a4a2fc6fef30f8cd2f74da6c301ccd5863f3240d1a2db7cbaa2df3a8efe0950f6200cbc10556393583a6ebb2e041095fc62ae3a9e4a0c5c830d73faa72aa8167b7b714ab85d927382d77bbfffb3f7c8184711e81cf9ec2ca03906e151750181500238f7814d2242721b2307baa9ea66e39b10a4fdad30ee6bff50d79ceac604618e74469ae3c80e7711c16fc85233a9eac39941a564b38513c1591502cde7cbd47a4d02a5d7d5ceceb7ff920ee40c29383bd7779be1e00b60354dd86ca514aa30e8f1523efcffdac1292198fe96983cb989a259a4aa475ed9b4ce34ae2282b3ba0169b2e82f9dee476eff215db33632cdcc72a65ba2e68d8e3f1fed90aaa68c4c886927b733144fb7225f1208cd6a108e675cc0cb11393db7451d883abb6adc58699393b8b7b7e19c8584b6fc95720ced39eabaa1124f423cc70f38385c4e9c4b4eeb39e73e891da01299c0e6ce1e97e1750a5c615e28f486c6a0e4da52c15285e7cf26ac859f5f4190e2804ad81ba4f8403e6358fbf1d48c7d593c3bac20a403010926877db3b9d7d0aaacd713a2b9833aff88d1e6b4d228532a66fe68449ad0d706ca7563fe8c2ec77062cc33244a515f2023701c052f0dd172b7914d497fdaefabd91a199d6cb2b62c71472f52c65d6a67d97d7713d39e91f347d2bc73b421fb5c6c6ba028555e5a92a535aabf7a4234d6ea8a315d8e6dcc82087cc76ec8a7b2366cecf176647538968e804541b79a1b602156970d1b943eb2641f2b123e45d7cace9f2dc84b704938fa8c7579a859ef87eca46*3*254*2*3*8*d911a3f73b050340*2097152*347e15bee29eb77d", "password"},
	/* SHA1-CAST5 salt-iter, DSA key */
	{"$gpg$*17*42*1024*d974ae70cfbf8ab058b2e1d898add67ab1272535e8c4b9c5bd671adce22d08d5db941a60e0715b4f0c9d*3*254*2*3*8*a9e85673bb9199d8*11534336*71e35b85cddfe2af", "crackme"},

	/* gpg --gen-key --s2k-digest-algo SHA256 --s2k-cipher-algo AES */
	{"$gpg$*1*668*2048*92f639f5a56692a0fb3bd32ca5d91099b49d4cf283da7d272ed51bdf337a4960e361eeb302d418c3f9620d94a077bcf888b56f892d87e2f330ecab3934ebc080ac440b4bb7cd1f79565f0a8b7331c2302d725451fbeff51ff2f25e69708555edfb353dfcab9ce33f6071ccaa2d32ad93a73082be621a8ec43a66f984551607d1e366892386e2f3cc0bdf6447216d0fbc8402c86d54cf0fd8fc133c4899a5a4b1b36cedfb5b11e804856885a7230def7718684f99f995df24f985706f0c1311d15d9a043b6a0096f5e0bb751c61a07517372441887de0532b35d5e4f9d5b35b2119715ca51a4a59227a3031fbd24f25d06ae8b6d17c1b5998aba281733cc6260930916c0d4fb84bf0cf4e7112b07bf5d78a97716599be4bed78d741757ea7149db2d1c9ff35d3b69f80dd7152ed99642b695c88c0f075ffd8a360f30a3e6160d2c5b99e41418f47ac6f9615c1a4d73b0f05c8d11d8ea18b9ea6bf9e6d2a7642f253b7ee742389a9dc19bb81261061b578609b73ad314e6e5c6afe68640abc62f5009e659fa64790689f7befe5009e396cc63d79493e56371a080c0c94c8f0036dbe9ac5a8861befc5882168f7866ec225641a2cf91d8318fcf660699d1e0272b4e0df7751c84e48513a5d26c27a12bf7f9e6965321a97f0b8162f4861fea9c78ee4bc3110b2d412f38081781f0aba5a43b92af148c4e3d9affa1f6b3a42cfcf7c7275b95445777ae51ed200bdb30606432ff05d132232ee9e8a92eba811b96422ba3390f3dbe23f8d6c5ed5cbee361f980e58394c0a8d0f9e9e1186dbb5defcf5bf3c9b44f55598a0b119b71a8bd8edf6428555e36e76785954997f40409beeea578740fb77334c4a396bfac3a24f8628212737ff6d7ffa3802e7bacd06e3e81344eebd1e60a72efa5f45e09151f55d838fda78007190c040851e5f67*3*254*8*7*16*1d1d7a3090537117d6d18e3b8dc41433*65536*d5285754134a9a05", "12345678"},
	/* gpg --gen-key --s2k-digest-algo SHA256 --s2k-cipher-algo CAMELLIA128 */
	{"$gpg$*1*668*2048*cce4298ada379aa74719ec266478e8711d7aa880ac552a15577ecb35c5d2f48a78d2b2fa1b015764c747b4632a7fe53675f2e117c64c0c4312e182c45ddcf988ed402de11ee93294e465070e052d198313bb822e88f31bcb1e3206271d8a5833d035effdce53648167663790e502574d1c5cf51fad8ae968bb155b75b22306f65cc37b27e0d6ba9b8e39b567c4853b41b21b9556b21a96f7f20477784118614b821e47d80ebc168d8b763e2bddfc37b7c55af838c9cff3be0e18da6da8f3671ab3c990fe541aedbb2ea8b43060f8cba4651baa4b8c498740064b95511c1e55d2125f99d636aec077ea0a606c1e9d9c919f0ed7f54a877907b45c544e534a843d8fded7334e66b74acc0a67b7ad6ffc317e93215e63ad083515d2394841ba52476096537cf0c436016031698d1497c7983e37fcd8ce4f184b6daa31cb5a2d7631355fc561bf681e309f6474163278ba8fd25e3dcc28342cc3b5c288d3cc95bc1c0746cc082b78f43cf3161d9c6551d56fbf23d83a8e10ae9380f754a2c0b74b93359d1b16213bb81625f301493ba6b347a1e5fb79745f7c8e317814e0e861f4fdb85f988f48ead7012f8e13a58fa07e33761efe64cb39b4bcf1f19d1f8b14f5bfc46c7703922273582bd99c266492247b2281c2565c03fe5270f0e858036ea4c994d4afd2029cc184a877189817dce9b5da2c8f89ea8914a0cc29dc4786aef6638e1983467ff574d2a4cc704bef7a7070c3b2bbb2f23e7c0fd8cf00365decae26a2d8ab45093587b3f8c3224bf7b8dd6c4a43853ef5c9c6eb6df0f2a77b126f55b49f77de5dc382a8327ed6fa24f379a4e9d1296cb0a9066b902f510aca6560f9e50bdd9663a269cdba41dd212dac569845c13226f2cd5311527705b24d698cb0acfb44b8a60bb4d3113ef2cb2cc7d597a889612c7f73aca5f8fd70a7*3*254*8*11*16*65a45645f3abe401f3345713d8eadfdf*65536*48e94f48bcda5a55", "abc"},
	/* gpg --gen-key --s2k-digest-algo SHA256 --s2k-cipher-algo AES256 */
	{"$gpg$*1*668*2048*4cb57f4b39dc6fc9137f99c9f4799e7a7b3dfa40fe6890e18b7b32c866aa8c63aa35ee1b3d2b5a223120a145fd066d082674552c6c89169c6f9a06efb238ba69c7d8b7826501bdbf6b92dfd7c97f5b9388a2afa6a8f985dbc8c962c56ed92a9f6dca3566e98647df5d31fec885608623e830fcf3346177a0e572dfe23610ae90c323bbb4cc54d857b7ea7642477c490a2fc875f3f7cc7889367f7ba3161df2a6c48218a06468146deeb66fc2d754420b3a967f418696eec725ad7d3093dc17924a2770949dd68f8efa79ddfdccbc7c23091fa7342a72b02f8288a14e7b9c51653a7d4f6044456b72a46033e3eb1855708c3bd310e10fb0f460ac362008d08526cb255e8a3efea5f6741a314b71d5fb811e42d1b3be79e546fcd52bc4d18ce3dcbe6c0b1816c25047bc8d81cbf21b57ba6bb12ab363fb17dd51176a5231e15b2740a66aff37d5b74547fc2af2448e6e83cf2ecbc7f897724e3d802becabdcf9ff2b2d977e45ff170899b1c3714a293b783ef758152c3072ad20a8b36b661c0af40c24e277dcefb3a869cce9a1e7f3afbd0abdbcbf87c309d2cb3fe36bd0069dd60da6651dc6e557d486953ef98699bee86b82baaa412f41c5952b3bec9ab43329f895a76dfd3e0e46bcd10277b1f57dfe43375a330c5c6e953c890c9e075f24fc1a9bdc38ea2ecaf0a4bc58026a545eacc317aee3eeebb39725b3ea6e1171ad600576b36e3d592909b73a4a3841c97a38db51f2579cd93d23560b9486e6a2d4d0a966efb31225c79d3214ed9da5b31b235b26f98a2b2f62f01684cf959056e978fd4ede44f4feaa35a8d411010a0a6df89a5d41eef39d64edea9c6dd79aa3ce9fdb4b41e88389776aafaedb3372e26633f13a63c4a62d2546e9b0c1e0d542991a2f8e9d76a630a20707d42073374308a409fe2a05b1476de07bb25679*3*254*8*9*16*ccdac5fce9ae3ec503390424a918aedb*65536*7dfbd9389fd9de2c", "openwall"},
	/* SHA256-AES256 salt-iter */
	{"$gpg$*1*348*1024*8f58917c41a894a4a3cdc138161c111312e404a1a27bb19f3234656c805ca9374bbfce59750688c6d84ba2387a4cd48330f504812cf074eba9c4da11d057d0a2662e3c7d9969e1256e40a56cce925fba29f4975ddb8619004def3502a0e7cf2ec818695c158243f21da34440eea1fec20418c7cf7dbe2230279ba9858201c00ae1d412aea1f59a66538fb739a15297ff9de39860e2782bf60a3979a5577a448925a0bc2d24c6bf3d09500046487a60bf5945e1a37b73a93eebb15cfd08c5279a942e150affbbe0d3084ab8aef2b6d9f16dc37b84334d91b80cf6f7b6c2e82d3c2be42afd39827dac16b4581be2d2f01d9703f2b19c16e149414fdfdcf8794aa90804e4b1dac8725bd0b0be52513848973eeadd5ec06d8a1da8ac072800fcc9c579172b58d39db5bc00bc0d7a21cf85fb6c7ce10f64edde425074cb9d1b4b078790aed2a46e79dc7fa4b8f3751111a2ff06f083a20c7d73d6bbc747e0*3*254*8*9*16*5b68d216aa46f2c1ed0f01234ebb6e06*131072*6c18b4661b884405", "openwall"},

	/* gpg --gen-key --s2k-digest-algo SHA512 --s2k-cipher-algo AES */
	{"$gpg$*1*668*2048*1de86a75cca20667506b71e729cf77e10ec148a948a94199910506e783eba52bf074f5d1d1f4819adbe28c7b51b464069ba3e44fceb62eef3038d3dfe8f7bc6012c9abc35769439730a8aabe99e4603fd2201303e82b413617d8fbaf95fdaee3d16d38a74df86a814f487e78b5c84093187529ebc54232a945628205b2eaf13ffeb41f94b1482a73f3aeb97f297d2398d94be2782a1f24244430cf251553dce8571c99ccbd6fe46e6863b25fe132420d1f49acdf9bf413c2155a794b5cf45cea8bc4d958fee20b5523cc42343a106fca60068f93aedd6d4f6021bee5a22b70969c1c8369a615de3f46867bc9364d0cdde141672c102ae42cb338c21d0ec6dd4eec923345201b3b3f97e94b7f60defb2a733616cdcd50c4254689441ab25d3ffe8adb56ef6654f35b446f05a56eef24a4bcdd52cc2b4590667f56d31c6182a757ad0ca1d1377cb04ac3a0711b25cb978ce51f19b5affe648153fa96ee3204b4043478ea20903aa7ff7f2f71cfcff802de73d709776d2dcf611d2936366c7a42edd7ab12ce4cf354eef5c27118ee89f3bb6f9de37b8e64e6db3071ea0b6de83ed27568e25672b56eacad2fee9a8872ea17b6a5fef7e14c3fece236842d2cef0c2044dbdcb2a3b317f64aaad1703844e0ebe1a5e0a90f137b62735d65dc51cf0357abe7ffd25d41d0e23fa9fc03b1be7b73f6fb8a9db04aed18cec473b0c93ffd981cc54cfd779e116c46ee621f3aa4b2e16a8ab8017a234cf26ac77f433e4544bd5761c8b263ae1b8023f6d1aca73bae1d2da5bbf7824406f5e2ff976fbf6e4b9484f020e9346648435d341de2e06a9e607059f847c5007a078dec2f08f466fc219ea5c4762d678af9b4737466e6af46edab495305a4d30124cc30d67fd3d38787cf763e362fe4484722e22b5f584e7cf64ec2c05390252a23583da9ca*3*254*10*7*16*5dfa8dd3acc0c05f3b1666f0e9243ef9*65536*75807ba0c8e4917f", "12345678"},
	/* gpg --gen-key --s2k-digest-algo SHA512 --s2k-cipher-algo AES */
	{"$gpg$*1*668*2048*fc59c117c35e67a90ee4fabc451a0a61d719d9f913cd796a3d1cc5dd788a9df62bff604ca19a3ee23ea068e3d0747d1897a5ceee21646799f4734ec4a2d02574255f6eace9674e368c2b4588b8892541ab53907795e25b9afd849d9b1d99f3e90b2b3520caa4262e318b63d3796339878752aaeb9ca636c57a5a9fc12ba621954acead99129d6e87d80674bdce027cd8e7e9865f1ca8ea66f41e298807447f89df5f9a701b42f9f153f43ee16d4e0e2ec7688ab68640553bd5db14c6d9469346e510ea31554537aca0a2108a353be41e1af12a62b78463576d5978d104f22e2b39296181c0a67e5d96f60ad5e1e2693ed37e1d20ed97712c0af5e774d30bf244bd6392a24cd2afdd1b44d856c5363006ccaad5fbd8a9b0afee03c1c326718a97b141297133267cbd128c45e753a6eff6d903e6c937322f72e62f1abe04d0c344eecc3e49b512bb1fe819b8a231502a3f1182bcc0387b0ad65342b97722330c2f271e5e9e21da40b59fd92af047dc4840f40e2c3f8b1fb8acb8cd33ac32e8d3d37eb60d682b45a2ff14623416330f978d90a07f1ec377ccb7ef8288d5ca8cfe31d486dfb748e53b42bb99d3eb674e5462bcb9ff3a8e1b2542780356073f75bb5dd110ac9670d89362ec6f29f988600da58b2d3d446f279e402b09ef4f3160ce5cd0e13861f735c40b7d0bc2b6447ce27b9aaf5c0358745e6e1f108eb1321fd0f4eb8cd5065ebf6bef9b7e097fb217eba65cc26c59e6553c2badfae570cc709cff0b32b398be68b19b4597e9889fc1163cc8e7a77a09cf3dcc63cbaee12c8be34a7eee47edc71bc11b91a939a7ca2dc5d305a1edddcc172f309873a2c8cbcb9caf8e11710e681b310f12678edd211fb3d0bb93c606253c5096c189e3be5cbc28633647e3d3b8ca14af6c76ce450b9258c241ef41d87f46cc33e790a1de*3*254*10*7*16*19424e6ddf44d9af244edc31e7090900*65536*fa31f69128e5fe9c", "abcdef"},
	{NULL}
};

static int *cracked;
static int any_cracked;
static int new_keys;

static cl_int cl_error;
static gpg_password *inbuffer;
static gpg_hash *outbuffer;
static gpg_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;
static cl_kernel crypt_kernel_sha256, crypt_kernel_sha512;

static size_t insize, outsize, settingsize, cracked_size;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char *warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	insize = sizeof(gpg_password) * gws;
	outsize = sizeof(gpg_hash) * gws;
	settingsize = sizeof(gpg_salt);
	cracked_size = sizeof(*cracked) * gws;

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);
	cracked = mem_calloc(1, cracked_size);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	// SHA-1 S2K
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");

	// SHA-256 S2K
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha256, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha256, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha256, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");

	// SHA-512 S2K
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha512, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha512, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha512, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		MEM_FREE(cracked);
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	Twofish_initialise();
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DSALT_LENGTH=%d",
		         PLAINTEXT_LENGTH, SALT_LENGTH);
		opencl_init("$JOHN/opencl/gpg_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "gpg", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		crypt_kernel_sha256 = clCreateKernel(program[gpu_id], "gpg_sha256", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		crypt_kernel_sha512 = clCreateKernel(program[gpu_id], "gpg_sha512", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
	                       create_clobj, release_clobj,
	                       sizeof(gpg_password), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 300);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel_sha256), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel_sha512), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return gpg_common_valid(ciphertext, self, 0);
}

static void set_salt(void *salt)
{
	gpg_common_cur_salt = *(struct gpg_common_custom_salt **)salt;
	currentsalt.length = SALT_LENGTH;
	memcpy((char*)currentsalt.salt, gpg_common_cur_salt->salt, currentsalt.length);
	currentsalt.count = gpg_common_cur_salt->count;
	currentsalt.key_len = gpg_common_keySize(gpg_common_cur_salt->cipher_algorithm);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

#undef set_key
static void set_key(char *key, int index)
{
	uint32_t length = strlen(key);

	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);

	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint32_t length = inbuffer[index].length;

	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		new_keys = 0;
	}

	// Run kernel
	if (gpg_common_cur_salt->hash_algorithm == HASH_SHA1) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					crypt_kernel, 1, NULL,
					&global_work_size, lws, 0, NULL,
					multi_profilingEvent[1]), "Run kernel");
	} else if (gpg_common_cur_salt->hash_algorithm == HASH_SHA256) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					crypt_kernel_sha256, 1, NULL,
					&global_work_size, lws, 0, NULL,
					multi_profilingEvent[1]), "Run kernel");
	} else if (gpg_common_cur_salt->hash_algorithm == HASH_SHA512) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					crypt_kernel_sha512, 1, NULL,
					&global_work_size, lws, 0, NULL,
					multi_profilingEvent[1]), "Run kernel");
	}

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		if (gpg_common_check(outbuffer[index].v, gpg_common_keySize(gpg_common_cur_salt->cipher_algorithm))) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
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

struct fmt_main fmt_opencl_gpg = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"s2k-count", /* only for gpg --s2k-mode 3, see man gpg, option --s2k-count n */
			"hash algorithm [2:SHA1 8:SHA256 10:SHA512]",
			"cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]",
		},
		{ FORMAT_TAG },
		gpg_tests
	},
	{
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		gpg_common_get_salt,
		{
			gpg_common_gpg_s2k_count,
			gpg_common_gpg_hash_algorithm,
			gpg_common_gpg_cipher_algorithm,
		},
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

#endif /* HAVE_OPENCL && HAVE_LIBCRYPTO */

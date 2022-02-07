/*
 * Common code for the ODF/StarOffice/LibreOffice format.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#include <openssl/blowfish.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "odf_common.h"
#include "johnswap.h"
#include "sha2.h"
#include "aes.h"
#define OPENCL_FORMAT
#include "pbkdf2_hmac_sha1.h"

struct fmt_tests odf_tests[] = {
	{"$odf$*0*0*1024*16*df6c10f64d191a841812af53874b636d014ce3fe*8*07e28aff39d2660e*16*b124be9f3346fb77e0ebcc3bb80028f8*0*2276a1077f6a2a027bd565ce89824d6a20086e378876be05c4b8e3796a460e828c9803a692caf7a53492c220d1d7ecbf4e2d336c7abf5a7672acc804ca267318252cbc13676616d1fde38820f9fbeef1360067d9de096ba8c1032ae947bde1d0fedaf37b6020663d49faf36b7c095c5b9aae11c8fc2be74148f008edbdbb180b44028ad8259f1215b483542bf3027f56dee5f962448333b30f88e6ae4790b60d24abb286edff9adee831a4b3351fc47259043f0d683d7a25be7e47aff3aedca140005d866e218c8efcca32093c19bbece50bd96656d0f94a712d3c60d1e5342db86482fc73f05faf513ca0b137378126597b95986c372b412c953e97011259aab0839fe453c756559497a28ba88dce009e1e7980436131029d38e56a34f608e6471970d9959068808c898608024db9eb394c4feae7a364ea9272ec4ea2315a9f0407a4b27d5e49a8ab1e3ddce5c84927d5aecd7e68e4437a820ea8743c6b5b4e2abbb47b0001e2f77ceac4603e8774e4ccbc1adde794428c11ae4a7492727b620334302e63f72b0c06c1cf83800366916ee8295176819272d557863a831ee0a576841191482959aad69095831fa1d64e3e0e6f6c6a751bcdadf0fbaa27a17458709f708c04587cb208984c9525da6786e0e5aabefe30ad1dbbef66e85ce9d6dbe456fd85e4135de5cf16d9455976d7ca8de7b1b530661c74c0fae90c0fff1a2b5fcdfab19fcff75fadcec445ed8af6ab5babf1463e08458918be8045083de6db988c37e4be582cfac5cdf741d1f0322fb2902665c7ff347813348109e5d442e91fcb010c28f042da481e807084fcb4759b40ccf2cae77bad00cdfbfba4acf36aa1f74c30a315e3d7f1ca522b6306e8903352aafa51dc523d582d418934398d5eb88120e3656bfb640a239db507b285302a86855ea850ddc9af72fc62dc79336c9bc29ee8314c65adb0574e9c701d73d7fa977edd1d52a1ff2da5b8b94e1a0fdd01ffcc6583758f0a1f51750e45f12b58c6d38b140e5676cf3474224520ef7c52ca5e634f85456651f3d6f43d016ed7cc5da54ea640a3bc50c2b9d3dea8f93c0340d66ccd06efc5ae002108c33cf3a470c4a50f6a6ca2f11b8ad15511688c282b94ba6f1c332e239d10946dc46f763f08d12cb9edc1e79c0e07f7151f548e6d7d20ec13b52d911bf980cac60694e192651403c9a69abea045190e847be093fc9ba43fec55b32f77f5796ddca25b441f259d5c51e06df6c6588c6414899481ba9e06bcebec58f82ff3021b09c6beae13a5d22bc94870f72ab813d0c0be01d91f3d075192e7a5de765599d72244757d09539529a8347e077a36678166e5ed9f73a5aad2e147d8154095c397e3e5e4ba1987ca64c1301a0c6c3e438097ede9b701a105ec38fcb54abb31b367c7740cd9ac459e561094a34f01acee555e60267157e6", "test"},
	{"$odf$*1*1*1024*32*61802eba18eab842de1d053809ba40927fd40b26c69ddeca6a8a652ed9c16a28*16*c5c0815b931f313627100d592a9c972f*16*e9a48b7daff738deaabe442007fb2ec4*0*be3b65ea09642c2b4fdc23e553e1f5304bc5df222b624c6373d53e674f5df01fdb8873cdab7a5a685fa45ad5441a9d8869401b7fa076c488ad53fd9971e97244ecc9416484450d4fb2ee4ec08af4044d7def937e6545dea2ce36bd5c57b1f46b11b9cf90c8fb3accff149ce2d54820b181b9124db9aac131f6436d77cf716423f04d42438eed6f9ca14bd24b9b17d3478176addd5fa0254bf986fccd879e326485790e28b94ad5306868734b5ac1b1ddb3f876382dee6e9428e8230e84bf11b7e85ccbae8b4b424cd73160c380f874b37fbe3c7e88c13ef4bde74b56507d17095c2c32bb8bcded0637e4403107bb33252f72f5886a91b7720fe32a8659a09c217717e4c74a7c2e09fc40b46aa288309a36e86b9f1856e1bce176bc9690555431e05c7b67ff95df64f8f40053079bfc9dda021ab2714fecf74398b867ebef675958f29eaa15eb631845e358a0c5caff0b824a2a69a6eabee069d3d6236d77709fd60438c9e3ad9e42b26810375e1e587eff105ac295327ef8bf66f6462388b7727ec32d6abde2f8d6126b185124bb437753663f6ab1f321ddfdb36d9f1f528729492e0b1bb8d3b9eda3c86c1997c92b902f5160f77587c37e45b5c133b5d9709fea910a2e9b54c0960b0ebc870cdbb858aabe07ed27cba86d29a7e64c6e3863131859314a14e64c1168d4a2d5ca0697853fb1fe969ba968e31359881d51edce287eff415de8e60cec2068bb82157fbcf0cf9a95e92cb23f32e6156daced4bee6ba8c8b41174d01fcd7662911bcc10d5b4478f8209ce3b91075d10529780be4f17e841a1f1833d432c3dc854908643e58b03c8860dfbc710a29f79f75ea262cfcef9cd67fb67d73f55b300d42f4577445af2b9f224620204cfb88de2cbf57931ac0e0f8d98259a41d744cad6a58abc7761c266f4e93aca19356b07073c09ae9d1976f4f2e1a76c350cc7764c27ae257eb69ba4213dd0a7794fa83d220439a398efd988b6dbf0de4c08bc3e4830c9e482b9e0fd1679f14e6f132cf06bae1d763dde7ce6f525ff9a0ebad28aeca16496194f2a6263a20e7afeb43d83c8c936130d6508f2bf68b5ca50375948424193a7fb1106fdf63ff72896e1b2633907f01a693218e3303436542bcf2af24cc4a41621c36768ce9a84d32cc9f3c2b108bfc78c25b1c2ea94e6e0d65406f78bdb8bc33c94a9550e5cc3e995cfbd31da03afb929418acdc89b099415f9bdb7dab7a75d44a696e14b031d601ad8d907e14a28044706c0c2955df2cb34ffea82af367e487b6cc928dc87a33fc7555173e7faa5cfd1af6d3d6f496f23a9579db22dd4a2c16e950fdc90696d95a81183765a4fbddb42c488d40ac1de28483cf1cdddf821d3f859c57b13cb7f21a916bd0d89438a17634c68637f23e2544589e8ae5ee5bced91680c087cb3105cd74a09e88d3aae17d75e", "test"},
	{"$odf$*0*0*1024*16*43d3dbd907785c4fa5282a2e73a5914db3372505*8*b3d676d4519e6b5a*16*34e3f7fdfa67fb0078360b0df4011270*0*7eff7a7abf1e6b0c4a9fafe6bdcfcfeaa5b1886592a52bd255f1b51096973d6fa50d792c695f3ef82c6232ae7f89c771e27db658258ad029e82415962b270d2c859b0a3efb231a0519ec1c807082638a9fad7537dec22e20d59f2bfadfa84dd941d59dd07678f9e60ffcc1eb27d8a2ae47b616618e5e80e27309cd027724355bf78b03d5432499c1d2a91d9c67155b7f49e61bd8405e75420d0cfb9e64b238623a9d8ceb47a3fdb5e7495439bb96e79882b850a0c8d3c0fbef5e6d425ae359172b9a82ec0566c3578a9f07b86a70d75b5ad339569c1c8f588143948d63bdf88d6ed2e751ac07f25ecc5778dc06247e5a9edca869ee3335e5dae351666a618d00ec05a35bc73d330bef12a46fb53b2ff96e1b2919af4e692730b9c9664aca761df10d6cf55396c4d4c268e6e96c96515c527c8fe2716ac7a9f016941aa46e6b03e8a5069c29ec8e8614b7da3e2e154a77510393051a0b693ae40da6afb5712a4ce4ac0ebacda1f45bdccc8a7b21e153d1471665cae3205fbfa00129bf00c06777bfecba2c43a1481a00111b4f0bd30c2378bd1e2e219700406411c6f897a3dfa51b31613cb241d56b68f3c241428783b353be26fa8b2df68ca215d1cf892c10fdef94faf2381a13f8cb2bce1a7dbb7522ef0b2a83e5a96ca66417fd2928784054e80d74515c1582ad356dd865837b5ea90674a30286a72a715f621c9226f19a321b413543fbbdb7cd9d1f99668b19951304e7267554d87992fbf9a96116601d0cee9e23cb22ba474c3f721434400cacf15bae05bbe9fa17f69967d03689c48a26fa57ff9676c96767762f2661b6c8f8afa4f96f989086aa02b6f8d039c6f4d158cc33a56cbf77640fb5087b2d5a5251692bb9255d0ae8148c7157c40031fdb0ea90d5fab546a7e1e1c15bd6a27f3716776c8a3fdbdd4f34c19fef22c36117c124876606b1395bf96266d647aaf5208eefd729a42a4efe42367475315a979fb74dcb9cd30917a811ed8283f2b111bb5a5d2b0f5589b3652f17d23e352e1494f231027bb93209e3c6a0388f8b2214577dca8aa9d705758aa334d6947491488770ed8066f692f8922ff0d852c2d0f965ab3d8a13c6de0ef3cff5a15ee7b64f9b1003817f0cb919ad021d5f3b0b5c1ad58db22e8fbd63abfb40e61065bad008cdffbbe3c563780a548f4515df5c935d9aa2a3033bc8a4011c9c173a0366c9b7b07f2a27de0e55373fb4b0c7726997be6f410a2ee5980393ea005516e89538be796131e450403420d72cdbd75475fd11c50efce5eb340d55d2dd0a67ca45ddb53aa582a2ec56b46452e26a505bf730998513837c96a121e4ad13af5030392ff7fb660955e03f65894733862f2367d529f0e8cdb73272b9ce01491747cb3e1a22f5c85ab6d40ddd35d15b9d46d73600e0971da90f93cb0e9be357c4f1227fbf5b123e5b", "jumper9"},
	{"$odf$*0*0*1024*16*4ec0370ab589f943131240e407a35b58a341e052*8*19cadc01889f78c0*16*dcfcb8baccda277764e4e99833ab9640*0*a7bd859d68298fbdc36b6b51eb06f7055befe08f76ca9833c6e298db8ed971bfd1315065a19e1b31b8a93624757a2583816f35d6f251ff7943be626b3dc72f0b320c9ce5d80b7cc676aa02e6a4996abd752da573ecc339d2c80a2c8bfc28a9f4ceea51c2969adf20c8762b2ee0b1835bbd31bd90d5a638cfe523a596ea95feca64ae20010ad9957a724143e25a875f3cec3cedb4df1c16ac82b46b35db269da98270c813acd5e55a2c138306decdf96b1c1079d9cfd3704d519fbc5a4a547ba5286a7e80dc434f1bf34260433cbb79c4bcbb2a5bfc5a6c2430944ef2e34e7b9c76b21a97003c1fa85f6e9c4ed984108a7d301afe4a8f6625502a4bf17b24e009717c711571da2d6acd25868892bb9e29a77da8018222cd57c91d9aad96c954355e50a4760f08aa1f1b4257f7eb1a235c9234e8fc4ed97e8ad3e5d7d128807b726a4eb0038246d8580397c0ff5873d34b5a688a4a931be7c5737e5ada3e830b02d3efb075e338d71be55751a765a21d560933812856986a4d0d0a6d4954c50631fa3dff8565057149c4c4951858be4d5dca8e492093cfd88b56a19a161e7595e2e98764e91eb51c5289dc4efa65c7b207c517e269e3c699373fe1bf177c5d641cf2cfa4bd2afe8bff53a98b2d64bedc5a2e2f2973416c66791cf012696a0e95f7a4dadb86f925fc1943cb2b75fb3eda30f7779edff7cce95ae6f0f7b45ac207a4de4ec012a3654103136e11eb496276647d5e8f6e1659951fc7ef78d60e9430027e826f2aaab7c93ef58a5af47b92cec2f17903a26e2cc5d8d09b1db55e568bfb23a6b6b46125daf71a2f3a708676101d1b657cd38e81deb74d5d877b3321349cd667c29359b45b82218ad96f6c805ac3439fc63f0c91d66da36bae3f176c23b45b8ca1945fb4a4cea5c4a7b0f6ffd547614e7016f94d3e7889ccac868578ea779cd7e6b015aafd296dd5e2da2aa7e2f2af2ce6605f53613f069194dff35ffb9a2ebb30e011c26f669ededa2c91ffb06fedc44cf23f35d7d2716abcd50a8f561721d613d8f2c689ac245a5ac084fa86c72bbe80da7d508e63d891db528fa9e8f0d608034cd97dfde70f739857672e2d70070e850c3a6521067c1774244b86cca835ca8ff1748516e694ea2b5b42555f0df9cb9ec78825c351df51a76b6fe23b58ab3e87ba94ffbb98c9fa9d50c0c282ed0e506bcad24c02d8b625b4bdac822a9e5c911d095c5e4d3bf03448add978e0e7fab7f8a7008568f01a4f06f155223086bdcfe6879e76f199afb9caeadebaa9ec4ec8120f4ccfc4f5f7d7e3cc4dd0cba4d11546d8540030769c4b6d54abdd51fa1f30da642e5ff5c35d3e711c8931ff79e9f256ac6416e99943b0000bf32a5efdd5cf1cd668a62381febe959ca472be9c1a9bade59dbba07eb035ddb1e64ae2923bd276deed788db7600d776f49339215", "RickRoll"},
	{"$odf$*0*0*1024*16*399a33262bbef99543bae29a6bb069c36e3a8f1b*8*6b721193b04fa933*16*99a6342ca7221c81890035dc5033c16f*0*ef8692296b67a8a77344e87b6193dc0a370b115d9e8c85e901c1a19d03ee2a34b7bf989bf9c2edab61022ea49f2a3ce5a6c807af374afd21b52ccbd0aa13784c73d2c8feda1fe0c8ebbb94e46e32904d95d1f135759e2733c2bd30b8cb0050c1cb8a2336c1151c498b9609547e96243aed9473e0901b55137ed78e2c6057e5826cfbfb94b0d77cb12b1fb6ac2752ea71c9c05cdb6a2f3d9611cb24f6e23065b408601518e3182ba1b8cef4cfcdf6ceecb2f33267cf733d3da715562e6977015b2b6423fb416781a1b6a67252eec46cda2741163f86273a68cd241a06263fdd8fc25f1c30fd4655724cc3e5c3d8f3e84abf446dd545155e440991c5fa613b7c18bd0dabd1ad45beb508cfb2b08d4337179cba63df5095b3d640eadbd72ca07f5c908241caf384ca268355c0d13471c241ea5569a5d04a9e3505883eb1c359099c1578e4bc33a73ba74ceb4a0520e0712e3c88582549a668a9c11b8680368cfbc3c5ec02663ddd97963d9dacefed89912ffa9cd945a8634a653296163bb873f3afd1d02449494fab168e7f652230c16d35853df1164219c04c4bd17954b85eb1939d87412eeeb2a039a8bb087178c03a9a40165a28a985e8bc443071b3764d846d342ca2073223f9809fe2ee3a1dfa65b9d897877ebb33a48a760c8fb32062b51a96421256a94896e93b41f559fdec7743680a8deacff9132d6129574d1a62be94308b195d06a275947a1455600030468dde53639fd239a8ab074ec1c7f661f2c9e8d60d6e0e743d351017d5c3d3be21b67d05310d0c5f3fd670acd95ca24f91b0d84d761d15259848f736ff08610e300c31b242f6d24ac2418cdd1fe0248f8a2a2f5775c08e5571c8d25d65ff573cc403ea9cad3bafd56c166fbcec9e64909df3c6ec8095088a8992493b7180c4dbb4053dcb55d9c5f46d728a97ae4ec7ac4b5941bcc3b64a4af31f7dc673e6715a52c9cdbe23dc21e51784f8314c019fc90e8612fcffe01d026fd9e15d1474e73dedf1d3830da81320097be6953173e4293372b5e5a8ecc49ac8b1a658cff16ffa04a8c1728d02ab67694170f10bc9030939ff6df3f901faa019d9b9fd2ba23e89eb0bbaf7a69a2272ee1df0403e6435aee147da217e8bf4c1ee5c53eb83aac1b3f8772d5cd2a2686f312ac4f4f2b0733593e28305a550dbbd18d3405a464ff20e0d9364cfe49b82a97ef7303aec92004a3476cf9ad012eaaf10fd07d3823e1b6871e82113ecfe4392854de9ab21ab1e33ce93d1abb07018007f50d641c8eb85b28fd335fd2281745772c98f8f0bba3f4d40ba602545ef8a0db3062f02d7ee5f49b42cbe19c0c2124952f98c49aff6927110314e54fe8d47a10f13d2d4055c1f3f2d679d4043c9b2f68b2220b6c6c738f6402c01d000c9394c8ed27e70c7ee6108d3e7e809777bab9be30b33a3fb83271cbf3b", "WhoCanItBeNow"},
/*
 * Some StarOffice hashes.
 * This first one is made with StarOffice "buggy SHA-1", see #3089
 */
	{"$sxc$*0*0*1024*16*00c20dee73d4990cfe1c8faf92ab5b0f517e0e19*8*36a0707abdd14c24*16*b6763f444c0a350458f25cf3957ca293*756*760*0b73bae4a465a7afa6573251583defc55496bf565cfd824a98c1c3ba05a07c5891286f89974f12193582c8b04597e7c539eead4afb84cbfd4e13e278ca29804ddb190efb8d5d3ea2b4919b2d84f39186971c33c67b0db0841ea1caeb94f65b5d6be4b69e5651eea303da4e79ac8509dc8bd5f7567e698f8422c847600fc4ab19ebabaf0ec84e0fb3900e584598d22465320ea7aa1ee77909378f41257a78aeca2b699c3d6b7481efd6a124e9e4ea8f8eeb7c4e9c7226ff1665cc37095254eed618cbeba9f383fed9983441606380bef22289408109a08b7d31c01c885a53292407a036a4ae41b1e91004aa46ed0c0d5b2462d37696c57e008335228071265edf4bcae020536ca4f7fd0d71ceb3f418d62cd07a884f646ad6e5392d4f84d5a8424a91e264988cfa3df9ed4c44d2c5018c905641cfe546ec4d2b9b0da4fb4e11241e7b26b38898a5acfd7679e3e0f5fb843b2690b3a43a29f26990e102434dfd80908319e12c96f7a0697a1fe3812ef10240eefff7295b5c884212cc3d1d4139e3ba65ae715317d76774a0c90e93a20d4f508c502cd8bbbebf1a9eb4c64cb9d40231f7d355582c44c4fad1634adc2c68e75694b0c45d05e89a766a513d7eb0d8ce2467463506ed5374a3ce2bbdc45d5f2858bf70a4ddf47c6f41a50691aebeee797d21f685aff45cfb6a99f34720665c5b8aac0bdda78b21876e73d5361888c0eda04c3f4ab7d40164b34f543d59c25258c6d0a1817c50a18d08109e905e754ac76748574434d5e6be04bc18736674c7d14a79929cccf57f6ecc169d5bf6e1e2beca732728e10e03002035d4e0ea0680c4a1471af374d86a891e4c1dce6266fccfa537174b243c583a9150c4df4102c943aad869bc72d8d6310eadc72dc4b7eeccf053dc0c3dacb4bc572045f4c76a521d84d1154b616b89f76d1a0cc4ce353d001f86353b7a4879e9f7846cd0b1d55ee85a6f57ec27583da7137c99752ed24ed69197c80e22a58f6302eee6af2f2a41ca3270f09f317ebd5a0ad799ad8f250d535c648ebedbfdba9770f2ea33492a057019a915c130303030", "openwall"},
	{"$sxc$*0*0*1024*16*4448359828281a1e6842c31453473abfeae584fb*8*dc0248bea0c7508c*16*1d53770002fe9d8016064e5ef9423174*860*864*f00399ab17b9899cd517758ecf918d4da78099ccd3557aef5e22e137fd5b81f732fc7c167c4de0cf263b4f82b50e3d6abc65da613a36b0025d89e1a09adeb4106da28040d1019bb4b36630fc8bc94fe5b515504bf8a92ea630bb95ace074868e7c10743ec970c89895f44b975a30b6ca032354f3e73ec86b2cc7a4f7a185884026d971b37b1e0e650376a2552e27ba955c700f8903a82a6df11f6cc2ecf63290f02ffdd278f890d1db75f9e8bd0f437c4ec613d3c6dcb421bbd1067be633593ba9bd58f77ef08e0cca64c732f892567d20de8d4c444fa9c1c1adc5e4657ef9740cb69ce55c8f9e6b1cfed0739ef002f1e1c1e54a5df50a759d92354f78eb90a9d9378f36df7d1edd8002ea0d637604fcd2408494c2d42b1771e2a2a20b55044836f76db4ed71e8a53f55a04f9437946603e7246c2d2d70caf6be0de82e8977fab4de84ca3783baedac041195d8b51166b502ff80c17db78f63d3632df1d5ef5b14d8d5553fc40b072030f9e3374c93e929a490c6cfb170f04433fc46f43b9c7d27f3f8c4ed759d4a20c2e53a0701b7c3d9201390a9b5597ce8ba35bd765b662e2242b9821bbb63b6be502d2150fff37e4b7f2a6b592fd0e319a7349df320e7fe7da600a2a05628dc00e04d480c085417f676bd0518bc39d9a9be34fc0cb192d5fa5e0c657cdf7c1ad265a2e81b90ac8b28d326f98b8f33c123df83edc964d2c17a904d0df8bd9ecbf629929d6e48cadc97f49a8941ada3d219e8c0f04f37cecc9a50cc5307fd2a488c34829b05cd1615ae0d1ef0ce450529aa755f9ae38332187ffe4144990de3265afaacb9f0f0fb9c67f6210369f7a0cc5bb346412db08e0f4732f91aa8d4b32fe6eece4fba118f118f6df2fb6c53fa9bc164c9ab7a9d414d33281eb0c3cd02abe0a4dd1c170e41c1c960a8f12a48a7b5e1f748c08e1b150a4e389c110ea3368bc6c6ef2bee98dc92c6825cbf6aee20e690e116c0e6cf48d49b38035f6a9b0cd6053b9f5b9f8360024c9c608cbba3fe5e7966b656fa08dec3e3ce3178a0c0007b7d177c7c44e6a68f4c7325cb98264b1e0f391c75a6a8fd3691581fb68ef459458830f2138d0fd743631efd92b742dfeb62c5ea8502515eb65af414bf805992f9272a7b1b745970fd54e128751f8f6c0a4d5bc7872bc09c04037e1e91dc7192d68f780cdb0f7ef6b282ea883be462ffeffb7b396e30303030", "openwall"},
	{"$sxc$*0*0*1024*16*64983af0b26a6ee614e6c65b32c1d906f70c6397*8*259cafe530bd09f8*16*8f53ea878d0795cfe05dcc65fb272c20*1024*1024*ffb0f736b69d8433f958e8f475f609948ad7c9dd052f2b92c14cb1b395ffcac043a3def76d58442e131701b3b53d56ea570633bb20c83068542420160f5db3cee5eece05b67b54d0d4cdf3fbfd928d94852924e391aa3f70cad598b48b946399b0cd1e9e7e7d081a888933f8a1973e83166799396e8290771463c623620b51fb5310b9b0e0de3e5597b66a091301ada3ba6a5d7515d1fcf0eff65e543b50f8fe2222619600054eaf69c7aa680c96bc403f115cab32d6d8e8bc0db3904a71ce3eb1283ca73fd6f75845d9b7d0275e4727a0f56bfbf962a9079f51849de2c9dee7f1dadbbae944f442169281004773309b0f8d68f2cf83076fd8b19afbccf5ab7dc58fb9554fee82e2c491d6434a4cef6f3209775343c840bc4bdfab6705000e67412ac74d00f5b6aba1fd21bca5213234a5a1100a9d93daa141a4936723ea77d008a35c9078167a3529706432b36b9ec012c060d093535c85ca6feb75165d620d7d663c3e76b9bf3af614556ed8560b446a8a73649cb935383a30b4fd8fd75522203e4575cf4bc2b7f01a9294310fe021c71acbf68f6f1e95f48c30c14151c51d4fb878a16272ee73753bc750cbd48007c842412ca1dcb6214215b082c00d619a5318e2ebe9149410f501170093784afc2bd71dd9f5a87b349b96661747b1627e8cba8a5c98559fb146fa7e30db4c6f648ce3c2209f84551a7a1cd46d9172ae1354b6d093f89f6f5f58d29c1d7af8830df62e67753caa8166322caa0f8adf4b61d2013d35baa7c002e1d4c83b1cba8aaa57cf4946627fa63ba7a6a5a5c803e8d5a4794845ab670ef950b918a360cd9f12e8f3424ecab1f505cb494ad35f28d12ff183471d0f47bd67e6abd3b8c8e206d11149474a19b5c13d165d8f6dc39cf579fe1000295328aeeb82e0ae8020d2f61e4c3d6e68c25a655ab72aad5e9e74af4cf27c74158fdb1a29a3d76cd658976fa0a30743247408df00a23b593f68861348a6c46af05d21a4b81fedbf5715462ec8ffc5f001a85c43058ac1fab488236588ef0bf08dd8dd7c7fce630a0a996395b503647d9a2f0dd63dd2f939eca8e1849ee4ed41a6d5672d947177e8f890692de879a20dd9e366ec494d270faf0d24fc076172a25998aac218586404687e7c77b55e77e0eff9b1c65c3f8da99deaa86411ab6aca2531d84b364349591bc73e7504163afd23c5208e321883ee611ea7e4e5885086e4fa7196e16b948cb54808b64b94106c74900e3190fd5f6068b490fd0c9c64481771527a0e2d00899fd5b7a9e7f508cc6770018fadf09d965d7a12ad3624d2161d9546d4a7937b5f961d7f7c4714786380c147e1ec6b0583503bd5a139b892831d1ea925993bb86f12e75d9010ceba230a1c286fa3d1d654a1672313cbf0763c05c622cee452f76957c42ba0e853ecda163d15e8600a702ccdc9e8f88a", "Ghe+t0Blaster"},
	{"$sxc$*0*0*1024*16*64983af0b26a6ee614e6c65b32c1d906f70c6397*8*9bb755c8a4fe8c34*16*112b9d41098c8677615755361da473a6*1024*1024*b95f0f2e0e1c7b4ee61168b646804d4b70b615f3c978cec65c9a7ab515417c79625d104373fd5012c3da6b356f8408a3a75edcc8b2aad0aa38bb33edd8933bdadbffde35a350ade73ccb9df29c2996082f5e94e324496835f8dfebe15ca38950e0f435d711ef964aa09915d58287967b5e321ca195a7f90253157afe82329da9a496c97292419b9a94cdb92f919e6d54700466aff61c200c5a355905b5a37c12d77b0e4ffd23f0204cfa664f4c0545f233db8d35af5fe337b459135da398fd23101becb194db305496474ba4179a7355285a9ec935044e1831f290f5f87ed3e00925e7fb4fc6bc38d9f0cfe9abf72560400490d2fd398d2d49516b618f99168602f323dd1786bcca394830341dfbeb377f9b7ef161dc1470f5e92b6152fa7a4f428e8ae40100791491a9e1c9385298522320488f00535866ac6e08354a75b8b2fd293066da7eb6b4ad7f3e13c8dc98cd815b2393f147fdac6279f76fdac9abd0a94131fa84fe4e99634a362a56d60ce588f6e0b66d6f8b6d411511272ffe32181d20e7d2c3d4b680764607afb2c29dcb94a845b920e96f6c27575534f8b7f9ddd93bdcef0d717d0a899fa937e7d2eeeb6d5b0338757f6e69dac72524d4b6f74edce1f937008eb3653bcc31a88712af940cf47ec3f3efd83e4da89d1a6cb7da6cf8d7d41430bc81a4b5d7bb46cad687f2f505e3379143ae274eed6201c3b17c1e05e516a14cbf2351ccf9fdd46e1309afb170bd01eb8f6a1d8e12441525199455fb550e3fc689b1801332b2d985e336b158f846fcbca18fbe6ea21438cf1fb5fdbce8d6350e65d6468342880845675ec721af2fb9df917a3968b4a1a477fc4c74ee38a71a230d77c2a7cf66ae6b83804488cbd25213ebc470cd845a2691b16161a640ebb385aa2381dc91f692f6c4ca2709b5a7e94dfb4548000a29b56f1da08701945d6209fabbd1621b28849fc27810775f1a0e0204d3ae9040a8cfb1386499a39d87149cfc1579de7d059662ad25a67abd42b30bb3608f09142ca030351c3a1e921e4c7bbc11aab846ef42eb5d1418c15ada77539aca096e0678439cd1b60950d2aa0cc4d2004b1ac48dc6a454c5a8e9ea7e910047c7c83895fd614fd9dfd961631eb23757646143c2aeb03c1a6476e78fc4ccf0f02cc1f88ec1b0080a170ac6871dc183939f7a4376965b0dfa7922012582eec4846ee621edc5547a2b9c4893e7f67f76541a4bd4a91827a57b3db5cdea29a2a3cc20238d89c8145c14b037360ad27f54f87317ef70472d6b1fd9f1168bcf8aba6071257b3adebab8d4e115188ed4af3fc3574fdccb4bc7eeb00a6a442f1b96a989b735f5e6059ec72c1677b77f437dcb93066f8591a11071799c3a0ec3b48f6160976aff1928c375358837e1ef02e20397b2e9d8d9c4bff23172c9b4c0b941cb1b49b5bc070f72a14cd384", "M1racl33"},
	{"$sxc$*0*0*1024*16*64983af0b26a6ee614e6c65b32c1d906f70c6397*8*ceb1edb1e3cb72fd*16*f7104c9b2789540f5fd4beef009c0139*1024*1024*709130b940a9663d0a5687133c6f78535d05a72936faed8c2f3c1b4e29423baaabcee4f0d7d57e3ad8d8c090486f974c4d0ce4be5b29ef8e1b02c01b4af1959ed0b277146a45aec35a48997b584b82697803193644eefd88a7eefcae8819839e13702f887278a597dd954babd82bf71bf8ca8559af0e5537be0264e358d36b4f5067960edf608de731e04d117de953386aadee71849edbc494fac3e6b14567a9e9c545a06d402acd3158441829f25478ed0f9086dabd2d3913b123b43c27176f8f08f30312d84e82d47654097a2bce95554357db3ce3d45a7441472067f55e4ea6244a3dedc23db4bea8f549109ffac382cf5b652c5b1ee431bcab1051567c263a9d668c5d6a15a6f8da754914746c1d3c7eb6347bdd8d6a3ac82e4c742fcf8721913c111dfd5398f2698db00f7220d2a3562e02f7f7a6505af3ba1ee10b46f2ab5b5d2f52d288fd12814c6edbcb8d50b6e8716fba0d5962747b971689fe75e94fa36ec39598ea30e15ab2b9c9f22ca04b890a13b18fb3c7a962050426bb2da08c8b993608b9c1ffd0a21e0c74e993242ead8eb30f86d7d2dcdbd4774d85c2e06adbe4b40050ff0ac1a8afe8fbc2175ec4da4676a691b1fce38421175734c20f07a604fea5287e1c33b420aa9db4de9bd97382c161b4ec0818add675e52ebf036aad779f24b824be4b2b013c470ff66cbf44f5800e128a3b328e80a5fd6295b9b3a94e915f9add6710cb9444432751a7a31c3a3422f48a5eabc26d9a52571b8447bdd0a5977ff7153d95337cef7ff2ec29774332fbeed6ee5eed5e12288cc13e14ba9d5ff3dd052e28ba96715f5b95d7ea214ebcd9e60b26308eb11370b824b5cff2644dd2117985b3c25ba8076d4025cf3a3a62da62d5e11d44422a142048e8cd00c7de6a0a55fd5dc09a3ed01dfe35b88268f351b6ff289fee8e52ac29fe32d9990e0d6d87f39727b6a762bac9d509c6ea235fc8bedc3bec2143eae9fd2cb831b798ef8261d72785002638b940947de0aad64f791f9a27e5b091e55adf4aee0649f6785bdd37e0248fedd1759d771aeacacb3ff6e7cf2d045f791428ab61710b54e869213393caf1b6bc99066678351deafc290cecc1f6b40b5532adbbab9a70408c61a437d4483b6a75cb61a55b20881efc0d849e0f60c1887f0fa091672179a145c4ab1b6487a0e939e0123d5aaffa3aec66ab593f9c25d27f22f4a73a999a4ab45e8bc7d71a85e2d40afadad1a1dc0b8389f96f91614293fa205583ef1c3440e3df50e8aa5f1a13e5929b72cd003461ff03d44d8c84bdada176b24459021d398b2b91b61a9c0b553a8714c703d32452c691a33f1581e98c2439514ca3e7deeef90850f8d6d89bf1d3a5762a56ef769ea588f5c1705bfb7b944cfbbb0632718ee3722f4e1929b35706d6413a315a11bc16349af109a7e675df2ab1eebe93", "excel123"},
	/* CMIYC 2013 "pro" hard hash */
	{"$odf$*1*1*1024*32*7db40092b3857fa319bc0d717b60cefc40b1d51ef92ebc893c518ffebffdf200*16*5f7c8ab6e5d1c41dbd23c384fee957ed*16*9ff092f2dd29dab6ce5fb43ad7bbdd5a*0*bac8343436715b40aaf4690a7dc57b0f82b8f25f8ad0f9833e32468410d4dd02e387a067872b5847adc9a276c86a03113e11b903854202eec361c5b7ba74bcb254a4f76d97ca45dbe30fe49f78ce9cf7df0246ae4524b8f13ad28357838559c116d9ed59267f4df91da3ea9758c132e2ebc40fd4ee8e9978921a0847d7ca5c30ef911e0b88f9fc84039633eacf5e023c82dd1a573abd7663b8f36a039d42ed91b4a0665902f174be8cefefd367ba9b5da95768550e567242f1b2e2c3866eb8aa3c12d0b34277929616319ea29dd9a3b9addb963d45c7d4c2b54a99b0c1cf24cac3e981ed4e178e621938b83be30f54d37d6425a0b7ac9dff5504830fe1d1f136913c32d8f732eb55e6179ad2699fd851af3a44f8ca914117344e6fadf501bf6f6e0ae7970a2b58eb3af0d89c78411c6adde8aa1f0e8b69c261fd04835cdc3ddf0a6d67ddff33995b5cc7439db83f90c8a2e07e2513771fffcf8b55ce1a382b14ffbf22be9bdd6f83a9b7602995c9793dfffb32c9eb16930c0bb55e5a8364fa06a59fca5af27df4a02565db2b4718ed44405f67a052738692c189039a7fd63713207616eeeebace3c0a3963dd882c485523f49fa0bc2663fc6ef090a220dd5c6554bc0702da8c3122383ea8a009837d549d58ad688c9cc4b8461fe70f4600539cd1d82edd4e110b1c1472dae40adc3126e2a09dd2753dcd83799841745160e235652f601d1257268321f22d19bd9dc811afaf143765c7cb53717ea329e9e4064a3cf54b33d006e93b83102e2ad3327f6d995cb598bd96466b1287e6da9967f4f034c63fd06c6e5c7ec25008c122385f271d18918cff3823f9fbdb37791e7371ce1d6a4ab08c12eca5fceb7c9aa7ce25a8bd640a68c622ddd858973426cb28e65c4c3421b98ebf4916b8c2bfe71b2afec4ab2f99291a4c4d3312521850d46436aecd9e2e93a8619dbc3c1caf4507bb488ce921cd8d13a1640e6c49403e0416924b3b1a01c9939c7bcdec50f057d6f4dccf0afc8c2ad37c4f8429c77cf19ad49db5e5219e965a3ed5d56d799689bd93642602d7959df0493ea62cccff83e66d85bf45d6b5b03e8cfca84daf37ecfccb60f85f3c5102900a02a5df015b1bf1ef55dfb2ab20321bcf3325d1adce22d4456837dcc589ef36d4f06ccdcc96ef10ff806d76f0044e92e192b946ae0f09860a38c2a6052fe84c3e9bb9380e2b344812376c6bbd5c9858745dbd072798a3d7eff31ae5d509c11b5269ec6f2108cb6e72a5ab495ea7aed5bf3dabedbb517dc4ceff818a8e890a6ea9a91bab37e8a463a9d04993c5ba7e40e743e033842540806d4a65258d0f4d5988e1e0011f0e85fcae3b2819c1f17f5c7980ecd87aee425cdab4f34bfb7a31ee7936c60f2f4f52aea67aef4736a419dc9c559279b569f61995eb2d6b7c204c3e9f56ca5c8a889812a30c33", "juNK^r00M!"},
	/* Created by LibreOffice Impress 5.4.4.1 in December, 2017 */
	{"$odf$*1*1*100000*32*3d7d3b74666814c1a50e4a68ce264198db4730ddc4f07f57647b6147143db261*16*60b496b3fee4ccfbc4512ff9a9ec2d59*16*841daefbb62e7b5ea50a4838f310ef7b*0*95e332c5ff7454222a324bd2ba290c5b80dc416b9117c4ae2f4633c9143aea330f54194c5b28735064dc3b386094ff18ac0c9f4a7354cc07bd96f511dbc7ff72ce051532f8e5edf0e83249631081723c348aea26f41b1a0f7b52f6602c87fc5b248f51033af4e6130263c296c02bdb8edb89ddf2c3d66fc27ed73028f2da17c0cbce5c657c0b435acf7d3a10c6a1b10d6fc5767a505b28481615a1aa6a3f8ec51745806c7f042ca52cec5f3270755a12fc5bcbb47b3055bd3b0c3005af5837c89cdd89061011614486f8801798b5a844e82985793037f2e6aabaa1452c66e743b224854a3eb55e74e5193125351ccad7f16ba3db2763e5c42bc900d4169ae457dd1ed68f62e1eaabe00462bccc0e5a8f935ab1ec7ec1f42e4af01a3c5413f1d5c686e79ea5efc605b78797b85a8844ee88b10aa3d7a42f0dfd928a4d1348c46e0b73e71b35ea32926cb5153f1ed9a11780bd7924e7231a42fe38179805a9097e5cfa9b517c25b2948a1414d50890c3dbd2d8b90439884def12ef5fcf3d7163a92f6dcf093700cef83140dbd11946d679288c4810cca8e19dbe05327d0d2c64eab6ca710506ae55c5249a96f73fb1ce9ca7bcf94b7a53e810fda658b4fbbb01a81c6eb3863ffef843c8211e0050ccd651e6d6f7df4ddcd00b24c1b37e1e2af1b8e565240975c400a06113da1aefae005fa86e94b9ba3624d06671bc35fe20b885d1d654bd0a4d1ae4acc37535fef1480c58ee302977c44d646fd414d7cf65e820c22a5ce8eee5f742f7763be4395ba97dc8405820557868c2344522908d4346c5c4843ec8bcc5737e7fd67415190ecc5f0da256a90d3e094d10a264678b1d27cabeace80fee6488d7b637f6ea1fb1fefce7a3d51114772de59ebf73a6796184807a3c058430223d1792cf8dc4ca0c290d812787a107314b7f0cd5151e2432f770b2ee4d4c5c0e61f4845f9cbe7ebe1ee2a7dc112bbe15cf1e111c39b11d6c50fae0402ed23c48da2e011e7aca37e88f5a3941cdce3e5a1960c265953e1ea9d820ced2b86563200ec52bbbdb79fbf28809ae97a1a7ad64af6230054601157359ed3f13973dff8ee0eb1a684f68565586cbd0c40d1a460e2fc0f78cbd5ff669bee30bf34bba1ad2e56e288a4daf072827fa69ada422515e72e0ff7555fea57580e5b7e86732a2a5a4fa42c6071a22c12128d7e98b4b0babd313e967f9909b5ee7240fe0a9070a7dbd551e8af4267277d42c57e80fe5198cb29f0e495be6371b723da695199789470ccbd64e63f17aaa748d3fe41401d50e863b5bc545b97e02b591c0f1035e9218fe4f4da9e43d4011d3dd869fb7d0eceebf3076d63b3862586843b6525e2e3b3c58ae71f394bf911324c38f32abe54f37d124d7a1945a6f94f82ae825c627ea5f161a842df957fd46a2131b6b61f646a4c4cf645db89f09debeeb", "åbc"},
	{NULL}
};

int odf_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	char cipher_type, checksum_type;
	int res, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* cipher type */
		goto err;
	if ((p[0] != '0' && p[0] != '1') || p[1])
		goto err;
	cipher_type = p[0];
	if ((p = strtokm(NULL, "*")) == NULL)	/* checksum type */
		goto err;
	if ((p[0] != '0' && p[0] != '1') || p[1])
		goto err;
	checksum_type = p[0];
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* key size */
		goto err;
	if (strcmp(p, "16") && strcmp(p, "32"))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* checksum field (skipped) */
		goto err;
	res = hexlenl(p, &extra);
	if (extra)
		goto err;
	if (res != 40 && res != 64) // 2 hash types (SHA-1 and SHA-256)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv length */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 16 || res < 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt length */
		goto err;
	if (strlen(p) >= 10)
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 32 || res < 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* something (used for original_length from star office hashes) */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 1024 || res < 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* content */
		goto err;
	res = strlen(p);
	if (res > 2048 || (res & 1))
		goto err;
	if (!ishexlc(p))
		goto err;

	if (cipher_type != checksum_type) {
		fprintf(stderr, "ODF: unsupported combination of cipher and hash types\n");
		goto err;
	}

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *odf_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$odf$*" */
	p = strtokm(ctcopy, "*");
	cs.cipher_type = atoi(p);
	p = strtokm(NULL, "*");
	cs.checksum_type = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.key_size = atoi(p);
	strtokm(NULL, "*");
	/* skip checksum field */
	p = strtokm(NULL, "*");
	cs.iv_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.iv_length; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.salt_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.original_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; p[i * 2] && i < 1024; i++)
		cs.content[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	cs.content_length = i;
	if (cs.original_length == 0)
		cs.original_length = cs.content_length;
	MEM_FREE(keeptr);

	return (void *)&cs;
}

void *odf_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[32+1];  // max(SHA-1, SHA-256)
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i, type, len;
	char *ctcopy = xstrdup(ciphertext + FORMAT_TAG_LEN);

	memset(&buf, 0, sizeof(buf));
	p = strtokm(ctcopy, "*");
	type = atoi(p);
	strtokm(NULL, "*");
	strtokm(NULL, "*");
	strtokm(NULL, "*");
	p = strtokm(NULL, "*");

	len = 20; // sha1
	if (type == 1)
		len = 32;
	for (i = 0; i < len; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(ctcopy);

	return out;
}

char *odf_prepare(char *fields[10], struct fmt_main *self) {
	if (!strncmp(fields[1], "$sxc$*", 6)) {
		static char *buf = NULL;
		char *cp, *part1, *part2;
		size_t len1, len2;
		int i;
		const size_t max_len = 3*1024;
		if (!buf)
			buf = mem_alloc_tiny(max_len, 4);
		/* $sxc$*1*2*3*4*5*6*7*8*9*10*11*12 */
		/* ^^^^^^ replace tag; remove ^^^ field #11. */
		part1 = cp = fields[1] + 6;
		for (i = 0; i < 10; ++i) {
			cp = strchr(cp, '*');
			if (!cp)
				return fields[1];
			++cp;
		}
		len1 = cp - part1;
		cp = strchr(cp, '*');
		if (!cp)
			return fields[1];
		++cp;
		part2 = cp;
		len2 = strlen(part2) + 1;
		if (FORMAT_TAG_LEN + len1 + len2 > max_len)
			return fields[1];
		cp = buf;
		memcpy(cp, FORMAT_TAG, FORMAT_TAG_LEN);
		cp += FORMAT_TAG_LEN;
		memcpy(cp, part1, len1);
		cp += len1;
		memcpy(cp, part2, len2);
		return buf;
	}
	return fields[1];
}

int odf_common_cmp_exact(char *source, char *pass, struct custom_salt *cur_salt) {
	unsigned char key[32];
	unsigned char hash[32];
	unsigned char *binary;
	BF_KEY bf_key;
	int bf_ivec_pos;
	unsigned char ivec[16];
	unsigned char output[1024];
	unsigned int crypt[8];
	SHA_CTX ctx;

	binary = odf_get_binary(source);

	if (cur_salt->checksum_type == 0 && cur_salt->cipher_type == 0) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (unsigned char *)pass, strlen(pass));
		SHA1_Final(hash, &ctx);
		pbkdf2_sha1(hash, 20, cur_salt->salt,
				   cur_salt->salt_length,
				   cur_salt->iterations, key,
				   cur_salt->key_size, 0);
		bf_ivec_pos = 0;
		memcpy(ivec, cur_salt->iv, 8);
		BF_set_key(&bf_key, cur_salt->key_size, key);
		BF_cfb64_encrypt(cur_salt->content, output, cur_salt->content_length, &bf_key, ivec, &bf_ivec_pos, 0);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, output, cur_salt->original_length);
		SHA1_Final((unsigned char*)crypt, &ctx);
		if (!memcmp(crypt, binary, 20))
			return 1;
		// try the buggy version.
		if ((cur_salt->original_length & 63) >> 2 == 13) {
			SHA1_odf_buggy(output, cur_salt->original_length, crypt);
			if (!memcmp(crypt, binary, 20))
				return 1;
		}
	} else {
		SHA256_CTX ctx;
		AES_KEY akey;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (unsigned char *)pass, strlen(pass));
		SHA256_Final((unsigned char *)hash, &ctx);
		pbkdf2_sha1(hash, 32, cur_salt->salt, cur_salt->salt_length,
			    cur_salt->iterations, key, cur_salt->key_size, 0);
		memcpy(ivec, cur_salt->iv, 16);
		AES_set_decrypt_key(key, 256, &akey);
		AES_cbc_encrypt(cur_salt->content, output, cur_salt->content_length, &akey, ivec, AES_DECRYPT);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, output, cur_salt->content_length);
		SHA256_Final((unsigned char*)crypt, &ctx);
		if (!memcmp(crypt, binary, 32))
			return 1;
	}
	return 0;
}

/*
 * The format tests all have iteration count 1024.
 * Just in case the iteration count is tunable, let's report it.
 */
unsigned int odf_iteration_count(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int) my_salt->iterations;
}

/*
 * 2nd cost is crypto, 0=BF 1=AES
 */
unsigned int odf_crypto(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int) my_salt->cipher_type;
}


typedef struct
{
    uint32_t st[5];
    uint32_t cnt;
    unsigned char buf[64];
} SHA1_CTX_buggy;

#define rol(n, bits) (((n) << (bits)) | ((n) >> (32 - (bits))))
#define W2(i) (W[i&15] = rol(W[(i+13)&15]^W[(i+8)&15]^W[(i+2)&15]^W[i&15],1))
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+W[i]+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+W2(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+W2(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+W2(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+W2(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

static void SHA1Hash_buggy(uint32_t st[5], const unsigned char buf[64]) {
	uint32_t a, b, c, d, e, W[16];

#if ARCH_LITTLE_ENDIAN
	uint32_t *p32 = (uint32_t*)buf;
	for (a = 0; a < 16; ++a)
		W[a] = JOHNSWAP(p32[a]);
#else
	memcpy((char*)W, buf, 64);
#endif

	a = st[0];
	b = st[1];
	c = st[2];
	d = st[3];
	e = st[4];
	R0(a, b, c, d, e, 0);
	R0(e, a, b, c, d, 1);
	R0(d, e, a, b, c, 2);
	R0(c, d, e, a, b, 3);
	R0(b, c, d, e, a, 4);
	R0(a, b, c, d, e, 5);
	R0(e, a, b, c, d, 6);
	R0(d, e, a, b, c, 7);
	R0(c, d, e, a, b, 8);
	R0(b, c, d, e, a, 9);
	R0(a, b, c, d, e, 10);
	R0(e, a, b, c, d, 11);
	R0(d, e, a, b, c, 12);
	R0(c, d, e, a, b, 13);
	R0(b, c, d, e, a, 14);
	R0(a, b, c, d, e, 15);
	R1(e, a, b, c, d, 16);
	R1(d, e, a, b, c, 17);
	R1(c, d, e, a, b, 18);
	R1(b, c, d, e, a, 19);
	R2(a, b, c, d, e, 20);
	R2(e, a, b, c, d, 21);
	R2(d, e, a, b, c, 22);
	R2(c, d, e, a, b, 23);
	R2(b, c, d, e, a, 24);
	R2(a, b, c, d, e, 25);
	R2(e, a, b, c, d, 26);
	R2(d, e, a, b, c, 27);
	R2(c, d, e, a, b, 28);
	R2(b, c, d, e, a, 29);
	R2(a, b, c, d, e, 30);
	R2(e, a, b, c, d, 31);
	R2(d, e, a, b, c, 32);
	R2(c, d, e, a, b, 33);
	R2(b, c, d, e, a, 34);
	R2(a, b, c, d, e, 35);
	R2(e, a, b, c, d, 36);
	R2(d, e, a, b, c, 37);
	R2(c, d, e, a, b, 38);
	R2(b, c, d, e, a, 39);
	R3(a, b, c, d, e, 40);
	R3(e, a, b, c, d, 41);
	R3(d, e, a, b, c, 42);
	R3(c, d, e, a, b, 43);
	R3(b, c, d, e, a, 44);
	R3(a, b, c, d, e, 45);
	R3(e, a, b, c, d, 46);
	R3(d, e, a, b, c, 47);
	R3(c, d, e, a, b, 48);
	R3(b, c, d, e, a, 49);
	R3(a, b, c, d, e, 50);
	R3(e, a, b, c, d, 51);
	R3(d, e, a, b, c, 52);
	R3(c, d, e, a, b, 53);
	R3(b, c, d, e, a, 54);
	R3(a, b, c, d, e, 55);
	R3(e, a, b, c, d, 56);
	R3(d, e, a, b, c, 57);
	R3(c, d, e, a, b, 58);
	R3(b, c, d, e, a, 59);
	R4(a, b, c, d, e, 60);
	R4(e, a, b, c, d, 61);
	R4(d, e, a, b, c, 62);
	R4(c, d, e, a, b, 63);
	R4(b, c, d, e, a, 64);
	R4(a, b, c, d, e, 65);
	R4(e, a, b, c, d, 66);
	R4(d, e, a, b, c, 67);
	R4(c, d, e, a, b, 68);
	R4(b, c, d, e, a, 69);
	R4(a, b, c, d, e, 70);
	R4(e, a, b, c, d, 71);
	R4(d, e, a, b, c, 72);
	R4(c, d, e, a, b, 73);
	R4(b, c, d, e, a, 74);
	R4(a, b, c, d, e, 75);
	R4(e, a, b, c, d, 76);
	R4(d, e, a, b, c, 77);
	R4(c, d, e, a, b, 78);
	R4(b, c, d, e, a, 79);
	st[0] += a;
	st[1] += b;
	st[2] += c;
	st[3] += d;
	st[4] += e;
}

static void SHA1Init_buggy(SHA1_CTX_buggy *ctx) {
	ctx->st[0] = 0x67452301;
	ctx->st[1] = 0xEFCDAB89;
	ctx->st[2] = 0x98BADCFE;
	ctx->st[3] = 0x10325476;
	ctx->st[4] = 0xC3D2E1F0;
	ctx->cnt = 0;
}

static void SHA1Update_buggy(SHA1_CTX_buggy *ctx, const unsigned char *data, uint32_t len) {
	uint32_t i;
	uint32_t j;

	j = (ctx->cnt&63);
	ctx->cnt += len;
	if ((j + len) > 63) {
		memcpy(&ctx->buf[j], data, (i = 64 - j));
		SHA1Hash_buggy(ctx->st, ctx->buf);
		for (; i + 63 < len; i += 64)
			SHA1Hash_buggy(ctx->st, &data[i]);
		j = 0;
	}
	else
		i = 0;
	memcpy(&ctx->buf[j], &data[i], len - i);
}

static void SHA1Final_buggy(unsigned char digest[20], SHA1_CTX_buggy *ctx) {
	unsigned i;
	const unsigned char pad[68] = { 0x80 /* , 0, 0 ... */ };
	uint32_t bits = ctx->cnt<<3;

	i = ctx->cnt & 63;
	if (i < 56) {
		SHA1Update_buggy(ctx, pad, 60 - i);
		if (i >> 2 == 13)
			SHA1Update_buggy(ctx, &pad[4], 64);
	} else {
		SHA1Update_buggy(ctx, pad, 64 - i);
		SHA1Update_buggy(ctx, &pad[4], 60);
	}

#if ARCH_LITTLE_ENDIAN
	bits = JOHNSWAP(bits);
#endif
	SHA1Update_buggy(ctx, (unsigned char*)&bits, 4);
	for (i = 0; i < 20; i++)
	{
		digest[i] = (unsigned char)
			((ctx->st[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
}

// mimic bug in Star/Libre office SHA1. Needed for any string of length 52 to 55 mod(64)
void SHA1_odf_buggy(unsigned char *data, int len, uint32_t results[5]) {
	SHA1_CTX_buggy ctx;
	SHA1Init_buggy(&ctx);
	SHA1Update_buggy(&ctx, data, len);
	SHA1Final_buggy((unsigned char*)results, &ctx);
}

#endif /* HAVE_LIBCRYPTO */

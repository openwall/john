/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  Functions and data which is common among the GPG crackers
 *  (CPU, OpenCL)
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/blowfish.h>
#include <openssl/ripemd.h>
#include <openssl/cast.h>
#include <openssl/camellia.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/des.h>
#include <openssl/aes.h> /* AES_cfb128_encrypt() */

#include "twofish.h"
#include "idea-JtR.h"
#include "sha.h"
#include "sha2.h"
#include "md5.h"
#include "formats.h"
#include "memory.h"
#include "common.h"
#include "gpg_common.h"
#include "loader.h"

#if !AC_BUILT && OPENSSL_VERSION_NUMBER >= 0x10100000
#define HAVE_DSA_GET0_PQG 1
#endif

struct gpg_common_custom_salt *gpg_common_cur_salt;

struct fmt_tests gpg_common_gpg_tests[] = {
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
	/* SHA256-AES256 salt-iter */
	{"$gpg$*1*348*1024*8f58917c41a894a4a3cdc138161c111312e404a1a27bb19f3234656c805ca9374bbfce59750688c6d84ba2387a4cd48330f504812cf074eba9c4da11d057d0a2662e3c7d9969e1256e40a56cce925fba29f4975ddb8619004def3502a0e7cf2ec818695c158243f21da34440eea1fec20418c7cf7dbe2230279ba9858201c00ae1d412aea1f59a66538fb739a15297ff9de39860e2782bf60a3979a5577a448925a0bc2d24c6bf3d09500046487a60bf5945e1a37b73a93eebb15cfd08c5279a942e150affbbe0d3084ab8aef2b6d9f16dc37b84334d91b80cf6f7b6c2e82d3c2be42afd39827dac16b4581be2d2f01d9703f2b19c16e149414fdfdcf8794aa90804e4b1dac8725bd0b0be52513848973eeadd5ec06d8a1da8ac072800fcc9c579172b58d39db5bc00bc0d7a21cf85fb6c7ce10f64edde425074cb9d1b4b078790aed2a46e79dc7fa4b8f3751111a2ff06f083a20c7d73d6bbc747e0*3*254*8*9*16*5b68d216aa46f2c1ed0f01234ebb6e06*131072*6c18b4661b884405", "openwall"},
	/* RIPEMD160-AES256 salt-iter */
	{"$gpg$*1*348*1024*7fc751702c5b678089bbd667000172649b029906ed59ba163bb4418cf384f6e39d07cd4763f874f1afbdacf1ed33544321ad9e664d6428c1865b8ea7d9026b558cc1f9c139ca771c6ceca03d57af635fc9140a3f5d2bec7117a98e6561cbe7efedcee129cf7dc1de39a7b92b7d3e17f45c54bba8ce8b0c8eb73611af8f44d5551c101ebe3d7466e1ae393fbf928bb297de0ce7e64f180bc76c770e72ca5da0c27a3abaf208d51c831f9f9f885269d28aa73a93c2be0185cc71f99381635a8e7c4c48fbe77620bb19a829c62dfed5e9e088fad12ea99003117886715c88a2f9926580d47d99a7f2b38f518bc011051c57c6c6c407bf9944b279db8456a6a4d1d5811558aaf8c108c6157cbeb297d26ab407c8c5d6a0038374f903a93e78ba857d97dc71d709faf0824d7bf092a36c4df2932bb4fd2c967fcbeb296a4ee3f45e550de04e62371ed9874068d9025e0fcf136a823ef0af9ce24f7ed4cc8b*3*254*3*9*16*3a9305fd67934b258d749739a360a6dd*131072*316217f7c4782365", "openwall"},
	/* SHA1-CAST5 salt-iter, DSA key */
	{"$gpg$*17*42*1024*d974ae70cfbf8ab058b2e1d898add67ab1272535e8c4b9c5bd671adce22d08d5db941a60e0715b4f0c9d*3*254*2*3*8*a9e85673bb9199d8*11534336*71e35b85cddfe2af", "crackme"},
	/* MD5-CAST5 salt-iter */
	{"$gpg$*17*42*1024*002170c3c5778fdbeedd788a1eda3827ef7d6d73491c022d5b76d33ff70ccae8d243aab7e2f40afcb4a4*3*254*1*3*8*019e084555546803*65536*49afdb670acda6c6", "MD5-CAST5-openwall"},
	/* gpg --s2k-mode 0 --gen-key*/
	{"$gpg$*1*668*2048*98515325c60af7a5f9466fd3c51fb49e6001567145dba5bb60a23d3c108a86b83793617b63e3fdfd94a07886782feb555e92366aeecb172ad7614ad6a6bbf137aa75a1d44dc550485b2103d194c691f1bf44301fc0d337e00d2b319958f709b4ca0b5cb7af119931abd99dfb75650210fc66be32af0b3dddaf362ef3504ef76cda787b28e17bc173d9c4ff4829713c9ee5d5282df443c7fc112e79da47091cf671b87179b8ce900873321c180ebc45d11a95aaf27610231b6abf1f22f71fdddd694334a752662ae4d62de122f1ff2ba95ba5fab7e5a498edd389d014926dd91c1769bfdd00d65123a8ec3e31d70e0ffe04eb8ef69648b9895c4cd5afc1e0ec81fa032e1b17c876b30241d1f5464535dfd7cf13f31c1bc1aa6150070afb491cca8afe4af9df174a49d1b8ebffe65298fc85ada9cf1ec61db243792d878bf4fdb12592f1a493912340010b173b4ccd49be7f1bc3565e9bdc601c5ecb01253979f64282fb34970d1d7ad1d13987032cda00a74d1d3117393a0cee73c2303fe4c5ba3938959956abfde9f5f24a7590a8d2224c2f2ca2bbc699841bf23f04e9a2a2974dfdd091462b1e93f47b8e3fcd75009f2f50839b3720f33cabc41adf17b4353ec8bc997f449b5fe4f320b8bf0e5e392386e0ef9b665a3680405e7c022a37e2ebeb2c41294455d97783f22137d4051f07ea215f91fa417d378496f5930cbc13dd942249d265c3d4a36e1e1fbed147153f2c3e3d4a43bec4606fcba57e2e4783240062285757ba39e1cc01b8506314a438fb99306a2dbb0cae1dbb5410965a8342cffa4ffcae8e79198404507c4f8d39cc3979c3f407d5d91ed6335e069087a975221c78b02726f234e64ff746a5e814997bbaa11f2885c0d00f242dff3138ff2556d577c125765f0fd08dfa66795ba810e3bb90efcfd9f5c3cb643bdf*0*254*2*3*8*01942c062e4b5eb0", "openwall@12345"},
	/* gpg --s2k-mode 1 --gen-key, old GnuPG versions (e.g GnuPG 1.0.3), uses *new* hash format */
	{"$gpg$*17*24*1024*b0d0b23529f968c0d05fa8caf38445c5bca5c2523ae6cc87*1*255*2*3*8*c5efc5bab719aa63*0*a0ccc71dedfce4d3*128*bb0ccf0f171fbb6438d94fdf24b749461c63902c4dca06f2d5580bca5837899431f1cbc7ccd56db8c9136a4ac7230a21eb6ab51a7c7a24fe23e99dd546eeb07cadb96372b0cb4a7dc2ba31e399d779e8ffa87f6f16c22ab54226a8a565550cfe98bee81001a810749327dca46f4ce7eb4f9726a00069026cb89f9533599cacdb*20*ec99ac865efa5aa7a9f1da411107e02e8e41daf5*128*16ed223362bb289889bf15c0ef3ce88b94892d57ea486f7cd63a1f8f83da3c28a6ee3879787c654c97e4824c75b0efd7f36db36947dfb8c9b1cfe0562c4e7d8b2b600973b9b379a1891200941b3a17361e49ccf157b0797a9d2f7535da0455c8d822b669ed6fc5fec56c71ad5df6fd9d4a4b67458b2e576a144ba2d0f49eff72*128*7991ba80eae8aa9d8adb38ae3c91fe771b7dc0a6f30fdc45d357acd5fcae1176245807972c39748880080d609f4c7e11a6c30d7ad144d848838e4ace2d9716c6e27edb6ef6ca453d7a8a3b0320fe721bc094e891b73f4515f3e34f52dfbf002108b0412bf54142b4d2c411fee99fd0b459de0a3825dc5be078b6e48d7aa5ceae", "wtf@123"},
	/* gpg --s2k-mode 1 --gen-key, old GnuPG versions (e.g GnuPG 1.0.3), uses *new* hash format, ElGamal */
	{"$gpg$*16*36*1024*0a4c2fb9d1ff24b817212a9cc0d3f2d84184a368ff3a04c337566812d037e5fe28933eaa*1*255*2*3*8*b312f3046fdb046c*0*a0ccc71dedfce4d3*128*f9235c132a796b0fd67f59567cf01dcf0a4ebbc8607a1033cefd2d52be40334e8cfba60737751b1bf16e36399340698656255917ca65f1f6f7806f05f686889ef7dc7030dd17dc9b45a1e1f01ab8d8a676d5a1759ac65bd1e2e50282f9926b44a156f7fea5e4ae5883e10f533efb9cd857efb84d23062f9741b4bd2ba70abcb3*1*05*128*e67deba19288e87c93829194698d10169e1f42eb43bba46b563037177ee09801a824fc9be2796fd24f4438c1a72f2e8587e6507ab1a408695a46709b87cc171366eef9ee86bd7935dd0ef6d4efdba738d7d8cb40dfe0f3dec996ebe2153fec9c091b5be0d31e398d8de75de4e346e299a07603242846b87f2b90ed82f9143786", "wtf@123"},
	/* gpg --homedir . --s2k-cipher-algo 3des --simple-sk-checksum --gen-key */
	{"$gpg$*1*650*2048*13f86b7b625701ea33f1d9e3bfc64d70f696a8ae42fb40ba128ae248aabea98e5d1f1a2ffa10e7ead6fde1d0d652de653965098f770a20abe95fe253428dd39856b8ce84c28699164766c864b7ca61723f6f49be4d8304814a522dd7f2798580dead66a55da5203ead2e4499ec8ca6c08e13e7c6b117cfd9381fb32bdeb5d022bc21197f0c095a8e2153809f295194f5f07f55f3c547af1094cc077a1aace9005c7b57558ec4042a1f312b512861a7038d10377df6a98e03239568f556e1e3e2cd1578c621268c3f95b1a4c6ba54dc484fd9b31d561438c68c740f71d8f2ff30ca9747ea350d70a6d1cc6cbaf4f13ecbc366df574ea313859c687ef7c5dc132250aac0982462f7327d3b384c14bd02eec7c460088d3f4439ef8696dcc60f86479a4593259cb300c466f153bc59cea6a2604da1d55e0b02dd673f7b52005349a5356373f49640f26e77af2b94ff2705c7b476993e3ac0845d2c582b769a3e06e9024e518fbf6c459ee9b158f94a12ac65cd720113f88f7dd2af26466d271e67c1a79707e33d6d72189d6b566019720889706c23f66217d20bba7d7174c048e333322fa3fc8a56a176fb2fb14e4f2660dd657c98b91dc80885b26ad7ea30d8ed0e0a88f2467f266d4b0087039a7a502d7db91d2a1286173fbaa0b6781bfe4f4b12ebd28be9b11e26214a83aebbe6cb7bc95a27ebef8c6c20c62cf709d89feb389a577d6c9be9bf1bd4034309ceebbbc0f307ca378051a1e283afdb0dd8a6ad72d2bede3d0f96c30c49b5e0a8bce3e009c4f786258d3d4fa8e0ec35c9bbff056d3648f8d8a03c20edf79757cfb26b6f3682661492052118eb33a92d407c5d4aed72635dededbbf5b46894e9e045416fbab0d5d6f680dea8fa6df38e9dbe4587ab5e5ca77e85b969295fd30a*3*255*2*2*8*7ecb79e68cd01a71*65536*2355a3ead8a0a3c5*256*d7d5db86ab15ca6d9b9138e90d60b9d4697d9535f6f990a930a5cb250a6c367e90e24cd60b3165dd654786c7e94b18fe48760b7cd123e4fefc8a0ffa18ab9e81c9e0b63f7e925483b29c3e639ed02f195cfb5f24b89e5cd802f08f81b63b6602827a95bdbf720c4fe043affb195fb66e1bce7bad691317451038fd9dade9e3a6e0ce2eb9293258434a02cb9134789bed94dd71df0d82192e12c50c60d52005eb85ced465b8992dc1de0899442f7cf26ea676e9db9fa3e28ba98f498d7c63de69394030726e1b1651928f17fc7464a58a3a2c1a683737962282d90bcd781fdab03a85b0b4114c5fcb83777d5ded28bf895b65a322adf7b9a8007e4315f48e9131", "openwall"},
	/* gpg --homedir . --s2k-cipher-algo 3des --simple-sk-checksum --gen-key */
	{"$gpg$*1*650*2048*72624bb7243579c0c77cf1e64565251e0ac9d0dcb2f4b98fa54e1678ee4234409efe464a117b21aff978907cfbf19eb2547d44e3a2e6f7db5bfceb4af2391992f30ff55a292d0c011f05c3ab27a1a3fde1a9fd1fbf05c7e5d200f4b7941efe42b4c5dd8abee6ee3d57c4899e023399c8cfd8d9735e095857b71723ded660d9bd705dba9eb373fab976cd73569934d7dec08f9f0b8451ca15d21549dd4d09b3e7cf832645cdbcb4bac84a963c8d7bfde301fcba31d3e935bbb8a0db483583c8077ea16cfda128e1eef42588082c0038cd9f35bb77f82d138f75ba7640250c4dc49ab60f0ce138999ea6c267a256b3e5d0e0ef30fef9c943462fcb3f0df38f069a3b027e15f36bf353ca4c0340ea9e8963d49136fa47872e0fa62c75345d40b7fe794b676c5e5d9bf50f90f4465b68630fbf72e5c46721b4877c30f004cfc2cfd78903dcfa5893ce9bea86d4be7e933a2d41e55024fb6529a7197da2f4dff4ac7689666b27cad49d640d1fdde37801cf8285818884c41465afb450d6c4cb0de21211a7cafd86399398cc18492cf4b3810bbfe1c08f8b293d1c78ed3a4cfacf92d9633e86fc5591a94d514d7b45af4729c801d405645699201c4a8dea32a9098a86f5a3a7526b42676aa1179b47f070390b9c84b17fafc4a2607d3247b34fafae369f31a63e85a8179db35c9038b616fcaad621cd91bcbbe3e96b2fe09e18d0da0492b66dd9d106eb4617975dea8e9b00b9bdea1b0d9c0737dc168d83be812c91076a3c4430bdd289bec60e1b0c8b314a7886256d95ae01cb4246cae94daaa50ef2b7ed498089872e1296dd5679ea0bbfd6e4ff704124dabbddb572e38fa83fff143bf2946d3e563d7de8cc62e1d51900d3db28c9e80dc5b4b8662268d62141106c111597f38131830ecbea*3*255*2*2*8*b58b33e5bcc1d3cd*65536*2355a3ead8a0a3c5*256*bd18b0eeba7c8dd316d1a60f0828ed50aea29afa2eee307cdbbc5df3e641167136d9d659d67a412215fe577d999c4672ca4e6e0af006469b828868e334062d4b442785c616081ad9c758278564174e74d9a9bf17553b065717053d534cbc4eeb32b0f64a6b110b5f434878b6a05730ea6e5f317c84a41a3ddbe2d9ef9693c34b5e87515056395444198fba8e9542adf9276cb9147447d79f774b94a40f6ea32377f1da1ea9f40e08a9b678737fab7ee77b764a9ed7b36848ac77d5b60c0f5075fa5f130e215dab20401e944078a6d905fa54cb094bf967f1620105aaeba95d1db2925ea045e83808713f71c60ca5dfe9c20e895eb637e53dfa54629d71670971", "openwall"},
	/* GPG symmetric encryption, "gpg -c", https://id0-rsa.pub/problem/1/ */
	{"$gpg$*0*63*1c890c019b24ce46afd906500094ad1afde4d56b9666dee9568cf2d47315b36e501b340813a62b8b82b72492b00a4595941ebd96de8eab636a00210bc57a13*3*18*2*9*65536*20538c8d69964d96", "password"},
	/* Challenge6_pro_Company2_hard.pgp (without MDC) */
	{"$gpg$*0*100*2cc874cb99956585bdf31bc7122540e21043c42e5be9cdeca20daf0dea294bcd15163d4dddc8ecc62b7eaadff213185601ed7431c92c83c4510c19c906f40f8eb865c33cb4be87a63dad7ed882387781d866bbc2c98604c6ee9411a1f0bc5306301913e4*3*9*2*3*5242880*d80b2eb1fddeeda8", "3Pseuderanthemum"},
	/* Following three hashes were generated from PGP Zip files using gpg2john */
	{"$gpg$*0*168*24d65b6ca7821043f03882a939aaa1f8d5c4ce7d26d7e83386968903582ca809f6cc7ffddfcb31d27e8945a672ec0e36530d6cbd7ac01318d5658a1121234b4987886ee9d6cfd493f5447dc5e40938e23fc2b70be967ab5ceb516052fc3798d2ccaab57b3ffe42870cba93497539a1b16d8eaf87abfaba81cf0787c87335f25290bbef02eabae5f7c090cab2410adc85f7c6e5210bda57f68acad41cb4f03e6cbf71e32f9fada60a*3*18*2*9*4063232*59092e506c1a856a", "12345678"},
	{"$gpg$*0*59*044511b6335c3d392c5cb43b56d9bd6ea9e2ba9818d6d9202bdfe1e83d4540f490bf96e17c790b063ec5c61423f031d535c96602431d8153e62392*3*18*2*9*4063232*ab38a8d3fce03b86", "openwall"},
	{"$gpg$*0*169*33d74e46b0d2c693981a91a30f24af0f6a849a37c61207c03149d5f1a301e247d0bee59476fb604ab622c282bce2b7ef30044ea0e1a9a4167738b2432477cc709f88442111297be0b007567ee56646c245e19524f7a4103abfa35994015ca88b056c62b84c6606d82727d0b24d996efe68e5531652755915115e37e1b60d989c36b9fd09de965ea229740f4c87312d5bb0eb6dc72e68647231831ab3e930fae0ccded0c12166b1b722*3*18*2*9*2097152*4a6b94697208f151", "openwall"},
	/* gpg --gen-key --s2k-digest-algo SHA512 --s2k-cipher-algo AES */
	{"$gpg$*1*668*2048*1de86a75cca20667506b71e729cf77e10ec148a948a94199910506e783eba52bf074f5d1d1f4819adbe28c7b51b464069ba3e44fceb62eef3038d3dfe8f7bc6012c9abc35769439730a8aabe99e4603fd2201303e82b413617d8fbaf95fdaee3d16d38a74df86a814f487e78b5c84093187529ebc54232a945628205b2eaf13ffeb41f94b1482a73f3aeb97f297d2398d94be2782a1f24244430cf251553dce8571c99ccbd6fe46e6863b25fe132420d1f49acdf9bf413c2155a794b5cf45cea8bc4d958fee20b5523cc42343a106fca60068f93aedd6d4f6021bee5a22b70969c1c8369a615de3f46867bc9364d0cdde141672c102ae42cb338c21d0ec6dd4eec923345201b3b3f97e94b7f60defb2a733616cdcd50c4254689441ab25d3ffe8adb56ef6654f35b446f05a56eef24a4bcdd52cc2b4590667f56d31c6182a757ad0ca1d1377cb04ac3a0711b25cb978ce51f19b5affe648153fa96ee3204b4043478ea20903aa7ff7f2f71cfcff802de73d709776d2dcf611d2936366c7a42edd7ab12ce4cf354eef5c27118ee89f3bb6f9de37b8e64e6db3071ea0b6de83ed27568e25672b56eacad2fee9a8872ea17b6a5fef7e14c3fece236842d2cef0c2044dbdcb2a3b317f64aaad1703844e0ebe1a5e0a90f137b62735d65dc51cf0357abe7ffd25d41d0e23fa9fc03b1be7b73f6fb8a9db04aed18cec473b0c93ffd981cc54cfd779e116c46ee621f3aa4b2e16a8ab8017a234cf26ac77f433e4544bd5761c8b263ae1b8023f6d1aca73bae1d2da5bbf7824406f5e2ff976fbf6e4b9484f020e9346648435d341de2e06a9e607059f847c5007a078dec2f08f466fc219ea5c4762d678af9b4737466e6af46edab495305a4d30124cc30d67fd3d38787cf763e362fe4484722e22b5f584e7cf64ec2c05390252a23583da9ca*3*254*10*7*16*5dfa8dd3acc0c05f3b1666f0e9243ef9*65536*75807ba0c8e4917f", "12345678"},
	/* gpg --gen-key --s2k-digest-algo SHA224 --s2k-cipher-algo Twofish */
	{"$gpg$*1*348*1024*d34b480dff5b275826f7e429b8f27c43f94c4db41740df16fcbca68dfa2e73d8f35dc3bdbf0847b71c5c4a5f3b1259cb2f9387026343b302f8dfb0a57d042cfa5d28a4729ae995cd695ab05db0300305df9b4a03f36c1368466eaf6d8a58e193bfaf9d14680732481bb4b6fbf6fbfb4d4731fadc6cb6dd5a13b71d7fe95cc06a2299fb6082742affde071b610beba076b692c2bb214aa8c513c826d80bf6424f86ae9d2c62483b35e7c55959c954040cb40c676abad542c3fc7a9406dcef6e290408fb4c4f64d67185ead007d753c923a12a603b23601f09ee96a3fedf322eca02c29497cc3228018079fe935feffb871261100807d5a000389bf2b9baa18e37dc485bfebfe43b58b53ab0d9d96e1c770ec65085dfecc45538f570afabd823f56bd43af49747b9c6e28951cd43d3f4652f8619064dd9b449e6b7b1887e6c8e329e537664d1ab1538bae0e075aa15901034d844a43e317ab607088f70*3*254*11*10*16*24ff5d0153905789635d463a626f13a0*65536*c5538cead34df464", "123456"},
	/* gpg --gen-key --s2k-digest-algo SHA384 --s2k-cipher-algo Blowfish */
	{"$gpg$*1*668*2048*d875c0d3f173363879b40a3b9566de49ee222a4613648c50886cd39a11291517f6eb5e40fd752524495b07abab266ccaab0b24f50c87f4b91b1638ad62a3ee0387e41f44ab40dfe6fa54d3b589fed9ce65e33ff5bd7df220de91f65cb94c4feb290e0313522a957d32c6304ef6c68b449f1d21482cb90f4033b8993282029901d74f175283a8a950fbfa1a682dad90b147f5ae36791b019ab25994b95087657add312538b382ae86e4a3ff4f1d4b95eba062412f755f525d0ac4f0dbf3a30ab427bcfab6194ef6b10b73bc8752377e53f13d5985c0887774e54b9c857df6adeadda87291c47fdbf8fa7a400bf2e495955d88bb2ed3363b8f6f065059d99af452bef8c234c152d0cf241a14b81346838bbb455ae692b0e5a2905556af215eba3ec1804c28115c933d9264d6282b7c0923d375202485a25ea75b66ce6ee8bed214a1431f2a927f3d7859e96076edd9565ef61578f455b6d25bbcec7e2cfd3b83350168ece7facc65ee49518437cb5161a657773dd9e40946bb2a9609cbb3a07b906f18fcc88f6f9cb344020c32ec2918e7501923f6e6343db3afc7007e3bb5b443828193b073c3dd61657405d0c5532ecf42f745f674d2449c88825076046d75faa892ff7d077c44c1709490680279db7ed90e2676bd3573c2e2ee879054120b870fe1743082e6340f5812c73937d3876ebd9a4ad84913aa7784c7be8ac8410e9ab680e88c47a5c869f837ee224ccc6443f6ac36a92d682fc1a7db2f0bb6cb30e5be1d17bbfc5163471a55cc47eeef2c27ce49f0cec48d1d7a5769b5f42bf93eb6bd61643c49cbf7b75b1d6118653f45a84777bc604144d8ccd6814f32a3ef80e45cb507d91767d1334171041bf3f586ec803000c67baaf57a74c228fa986522129f5cb3aa85a3f44373e5f8c47951f892d58a923cde68e659632c0267*3*254*9*4*8*29b4190538078f46*65536*5f8d833d2266d429", "abcdef"},
	/* gpg --gen-key --s2k-digest-algo SHA512 --s2k-cipher-algo idea */
	{"$gpg$*1*668*2048*a83b3cf2f3662290d890569cd9787828ea71fd946f303db9f8cdc9c4400285af8689605a1a853f0d6850b002e9579fbc91a0702206cbd958dad1ff2aafbcb8db13c5188bf5694e5af98300e6711775bec0a0c882bf84883d96f9ab03a827b2cb719c63ab32b729bd4657d6990403d95fab3e1e53bfccb65c2fe9b4a17d2d779e01612b3d7f4ebdd92a7dbc8c111b68021c4479f8d4b9a12c0b686e66fbfc3d498186f17d8668e53efe233d2b0d01f8315180afe42bfdc4c02c2054a7f2d3063963dd14375a87604bee5eeedea89d5148cf1df108d338f51f6d814188e313b90eb8b65fb55bff87a8b3e86becc7b836a417dce1f32648fc156efe89df46f51f4beed6cf5c1cc449b4651e1b2d1a2eafdcd91987d1dcf06a885ef621699c171b27db2932f7c61cba5aaf320ff694b6c8cc08342ade9e6b53f2e943cf0e1e73de0e891a37992e7b01396c59051b28459532e375d2026af2605e08f6f8aadf3981f52aab3ccd5a727256f997f9c51d3a5b1c48e80fe5398ca7f3c8150ad00389c7d87d705001c5b587edff657c4a9ad16eb8860fcf179a271c913696c3178e3742ca39cd9e85a3a9558f6550a3c10ebc2ab4791f7761cd4e5bd0b0d1cd3becfe3bc94681ba5ead47dd81cedec1a7607b843b9369afd8bac1dcd0efa5e751cb5f5510367ecbf89f72764ff0e513ff76d75e1085ac7cbf2b377ee2d379bf46cb166cf03d06aeeefb8028f4b1a0f0626ffe3a7e0d672538ed55df96406d51073c92317dd6d057b749727a78be1636c3ab1be2586df97f56a20e8df099ffb4542ab34c23e0984bc9a4918230bf5e06d06b3321c7404b87cff50ffa73a959cff0ecebf3407f59055ba6d934e4ae818734f1eef05904bcfa3226a1e008d52974a2fffda74004739b1c75895da34b95ce4b1a1023f878667dd29efac7c6867adf59*3*254*10*1*8*bcd00fecc8fcf1a9*65536*2ef2aa27d53d3b10", "qwerty"},
	/* gpg -o out.gpg --cipher-algo 3DES --no-mdc --symmetric --compress-level 0 --s2k-mode 3 --s2k-count 1 secret.txt */
	{"$gpg$*0*36*c8ebbe8116a24a2c5f7e81c1588c225e39e41bfe1b3bede92e2914443ade5651efe9c949*3*9*2*2*1024*2f4ddf3395af20a6", "qwertyzxcvb12345"},
	/* gpg -o out.gpg --cipher-algo IDEA --no-mdc --symmetric --compress-level 0 --s2k-mode 3 --s2k-count 1 secret.txt */
	{"$gpg$*0*36*73426e4ec660c94430cf8551a3a3d8e2fc710d018b31271d83fd5098ff2e29b6734fdbca*3*9*2*1*1024*c77703dc5a6b398b", "qwertyzxcvb12345"},
	/* gpg -o out.gpg --cipher-algo CAST5 --force-mdc --symmetric --compress-level 0 --s2k-mode 3 --s2k-count 1 secret.txt */
	{"$gpg$*0*58*190111fef479fda732000fe7ead411eb778bfe101cf71c6a8a5fbf96b7d8e99dbbad901c37c88d213e1306a953d9aa9a04244509693f16856061*3*18*2*3*1024*d3e886db68fbfa0f", "qwertyzxcvb12345"},
	/* gpg -o out.gpg --cipher-algo twofish --no-mdc --symmetric --compress-level 0 --s2k-mode 3 --s2k-count 1 secret.txt, has mdc in spite of "--no-mdc" flag */
	{"$gpg$*0*66*c87c9a0e7e7f7299129645f2f352076f8d9c29c830e7d21b28ee45fbfe2a31fcb70900fd8031e896035d672847c9b9c59f1fd802290d3d6992c45eb3d27e95cc0990*3*18*2*10*1024*45216ac170f04fd5", "qwertyzxcvb12345"},
	/* PGP 8.0 for Windows, AES-256 with missing mdc */
	{"$gpg$*0*44*cfa1353f691dfa09e1f2001fe81a50f67b7d38a69d4d909a5ec665f2691304c092b5136e4c691368fb006973*3*9*2*9*65536*f3d4f603c697cf18", "openwall123"},
	/* PGP 8.0 for Windows, Twofish with missing mdc */
	{"$gpg$*0*44*eaf7c0fd70579388927f1c85395e6f76a73234639a792c0a08c8ede8397ac09e105bc6eca51632367d572348*3*9*2*10*65536*048af401a552dca6", "openwall"},
	/* PGP Desktop 9.0.2 */
	{"$gpg$*0*66*c54842eed9b536e1fafad46aa233a6c158bd1fcabeed6b91531d8331a3452466d02446586b9b6837b510efbe95bb9f91c92d258be82f65092483812b896af3d4aa28*3*18*2*9*65536*b2688a012358b7fa", "openwall"},
	{NULL}
};

// mul is at most (PLAINTEXT_LENGTH + SALT_LENGTH)
#define KEYBUFFER_LENGTH ((PLAINTEXT_LENGTH + SALT_LENGTH) * 64)

// Returns the block size (in bytes) of a given cipher
uint32_t gpg_common_blockSize(char algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_BLOCK;
		case CIPHER_BLOWFISH:
			return BF_BLOCK;
		case CIPHER_IDEA:
			return 8;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256:
			return AES_BLOCK_SIZE;
		case CIPHER_CAMELLIA128:
		case CIPHER_CAMELLIA192:
		case CIPHER_CAMELLIA256:
			return CAMELLIA_BLOCK_SIZE;
		case CIPHER_TWOFISH:
			return 16;
		case CIPHER_3DES:
			return 8;
		default:
			break;
	}
	return 0;
}

// Returns the key size (in bytes) of a given cipher
uint32_t gpg_common_keySize(char algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_KEY_LENGTH; // 16
		case CIPHER_BLOWFISH:
			return 16;
		case CIPHER_AES128:
			return 16;
		case CIPHER_AES192:
			return 24;
		case CIPHER_AES256:
			return 32;
		case CIPHER_IDEA:
			return 16;
		case CIPHER_3DES:
			return 24;
		case CIPHER_TWOFISH:
			return 32;
		case CIPHER_CAMELLIA128:
			return 16;
		case CIPHER_CAMELLIA192:
			return 24;
		case CIPHER_CAMELLIA256:
			return 32;
		default: break;
	}
	assert(0);
	return 0;
}

static int gpg_common_valid_cipher_algorithm(int cipher_algorithm)
{
	switch(cipher_algorithm) {
		case CIPHER_CAST5: return 1;
		case CIPHER_BLOWFISH: return 1;
		case CIPHER_AES128: return 1;
		case CIPHER_AES192: return 1;
		case CIPHER_AES256: return 1;
		case CIPHER_IDEA: return 1;
		case CIPHER_3DES: return 1;
		case CIPHER_TWOFISH: return 1;
		case CIPHER_CAMELLIA128: return 1;
		case CIPHER_CAMELLIA192: return 1;
		case CIPHER_CAMELLIA256: return 1;
	}

	return 0;
}

static int gpg_common_valid_hash_algorithm(int hash_algorithm, int spec, int isCPU)
{
	static int warn_once = 1;

	if (spec == SPEC_SIMPLE || spec == SPEC_SALTED) {
		if (!isCPU)
			goto print_warn_once;
		switch (hash_algorithm) {
			case HASH_SHA1: return 1;
			case HASH_MD5: return 1;
			case 0: return 1; // http://www.ietf.org/rfc/rfc1991.txt
		}
	}
	if (spec == SPEC_ITERATED_SALTED) {
		if (!isCPU) {
			if (hash_algorithm == HASH_SHA1 || hash_algorithm == HASH_SHA256 || hash_algorithm == HASH_SHA512)
				return 1;
			goto print_warn_once;
		}
		switch (hash_algorithm) {
			case HASH_SHA1: return 1;
			case HASH_MD5: return 1;
			case HASH_RIPEMD160: return 1;
			case HASH_SHA256: return 1;
			case HASH_SHA384: return 1;
			case HASH_SHA512: return 1;
			case HASH_SHA224: return 1;
		}
	}
	return 0;

print_warn_once:
	if (warn_once) {
		fprintf(stderr,
		        "Error: This GPG OpenCL format does not support the requested S2K type!\n");
		warn_once = 0;
	}
	return 0;
}

int gpg_common_valid(char *ciphertext, struct fmt_main *self, int is_CPU_format)
{
	char *ctcopy, *keeptr, *p;
	int res,j,spec,usage,algorithm,ex_flds=0;
	int symmetric_mode = 0, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$gpg$" marker and '*' */
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* algorithm */
		goto err;
	if (!isdec(p))
		goto err;
	algorithm = atoi(p); // FIXME: which values are valid?
	if (algorithm == 0) { // files using GPG symmetric encryption?
		symmetric_mode = 1;
	}
	if ((p = strtokm(NULL, "*")) == NULL)	/* datalen */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (!symmetric_mode) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* bits */
			goto err;
		if (!isdec(p)) // FIXME: bits == 0 allowed?
			goto err;
	}
	if ((p = strtokm(NULL, "*")) == NULL)	/* data */
		goto err;
	if (hexlenl(p, &extra) != res*2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* spec */
		goto err;
	if (!isdec(p))
		goto err;
	spec = atoi(p);
	if ((p = strtokm(NULL, "*")) == NULL)	/* usage */
		goto err;
	if (!isdec(p))
		goto err;
	usage = atoi(p);
	if (!symmetric_mode) {
		if (usage != 0 && usage != 254 && usage != 255) // && usage != 1)
			goto err;
	} else {
		if (usage != 9 && usage != 18) // https://tools.ietf.org/html/rfc4880
			goto err;
		if (!bench_or_test_running && usage == 9) {
			self->params.flags |= FMT_NOT_EXACT;
		}
	}
	if ((p = strtokm(NULL, "*")) == NULL)	/* hash_algorithm */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (!gpg_common_valid_hash_algorithm(res, spec, is_CPU_format))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* cipher_algorithm */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (!gpg_common_valid_cipher_algorithm(res))
		goto err;
	if (!symmetric_mode) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* ivlen */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res != 8 && res != 16)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
	}
	/* handle "SPEC_SIMPLE" correctly */
	if ((spec != 0 || usage == 255))
		;
	else if (spec == 0) {
		MEM_FREE(keeptr);
		return 1;
	}
	if ((p = strtokm(NULL, "*")) == NULL)	/* count */
		goto err;
	if (!isdec(p)) // FIXME: count == 0 allowed?
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != SALT_LENGTH*2 || extra)
		goto err;
	/*
	 * For some test vectors, there are no more fields,
	 * for others, there are (and need to be checked)
	 * this logic taken from what happens in salt()
	 */
	if (usage == 255 && spec == 1 && algorithm == 17) {
		/* old hashes will crash!, "gpg --s2k-mode 1 --gen-key" */
		ex_flds = 4; /* handle p, q, g, y */
	} else if (usage == 255 && spec == 1 && algorithm == 16) {
		/* ElGamal */
		ex_flds = 3; /* handle p, g, y */
	} else if (usage == 255 && spec == 1) {
		/* RSA */
		ex_flds = 1; /* handle p */
	} else if (usage == 255 && spec == 3 && algorithm == 1) {
		/* gpg --homedir . --s2k-cipher-algo 3des --simple-sk-checksum --gen-key */
		// PKA_RSA_ENCSIGN
		ex_flds = 1; /* handle p */
	} else if (usage == 255 && spec == 3 && algorithm == 17) {
		// NEW stuff
		// PKA_DSA
		ex_flds = 4; /* handle p, q, g, y */
	} else if (usage == 255 && spec == 3 && algorithm == 16) {
		// NEW stuff
		// PKA_ELGAMAL
		ex_flds = 3; /* handle p, g, y */
	} else {
		/* NOT sure what to do here, probably nothing */
	}

	p = strtokm(NULL, "*"); /* NOTE, do not goto err if null, we WANT p nul if there are no fields */

	if (symmetric_mode) {
		goto good;
	}

	for (j = 0; j < ex_flds; ++j) {  /* handle extra p, q, g, y fields */
		if (!p) /* check for null p */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if ((p = strtokm(NULL, "*")) == NULL)
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		p = strtokm(NULL, "*");  /* NOTE, do not goto err if null, we WANT p nul if there are no fields */
	}

	if (p)	/* at this point, there should be NO trailing stuff left from the hash. */
		goto err;

good:
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

// For all generator functions below:
// Max keysize is 32, min hashsize is 16. So numHashes is 1 or 2.
static void S2KSimpleSHA1Generator(char *password, unsigned char *key, int length)
{
	SHA_CTX ctx;
	uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, "\0", 1);
		}
		SHA1_Update(&ctx, password, strlen(password));
		SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
	}
}

static void S2KSimpleMD5Generator(char *password, unsigned char *key, int length)
{
	MD5_CTX ctx;
	uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		MD5_Init(&ctx);
		for (j = 0; j < i; j++) {
			MD5_Update(&ctx, "\0", 1);
		}
		MD5_Update(&ctx, password, strlen(password));
		MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
	}
}


static void S2KSaltedSHA1Generator(char *password, unsigned char *key, int length)
{
	SHA_CTX ctx;
	uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, "\0", 1);
		}
		SHA1_Update(&ctx, gpg_common_cur_salt->salt, SALT_LENGTH);
		SHA1_Update(&ctx, password, strlen(password));
		SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
	}
}

static void S2KSaltedMD5Generator(char *password, unsigned char *key, int length)
{
	MD5_CTX ctx;
	uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		MD5_Init(&ctx);
		for (j = 0; j < i; j++) {
			MD5_Update(&ctx, "\0", 1);
		}
		MD5_Update(&ctx, gpg_common_cur_salt->salt, SALT_LENGTH);
		MD5_Update(&ctx, password, strlen(password));
		MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
	}
}

//#define LEAN

// Note, using this as 'test-bed' for writing the GPU code.
// trying to minimize variables, reusing them if possible.
static void S2KItSaltedSHA1Generator(char *password, unsigned char *key, int key_len)
{
	// vars needed to 'fake' data like we see on GPU
	unsigned char *salt = gpg_common_cur_salt->salt;
	uint32_t _count = gpg_common_cur_salt->count;

	SHA_CTX ctx;
	uint32_t password_length = strlen(password);
	const uint32_t tl = password_length + SALT_LENGTH;
	uint32_t i, j, n, count;
#ifdef LEAN
	uint8_t keybuf[128 + 64+1 + PLAINTEXT_LENGTH + SALT_LENGTH];
#else
	unsigned char keybuf[KEYBUFFER_LENGTH + 256];
	uint32_t bs;
#endif

	for (i = 0;;++i) {
		count = _count;
		SHA1_Init(&ctx);
#ifdef LEAN
		for (j=0;j<i;++j)
			keybuf[j] = 0;
		n = j;
		memcpy(keybuf + j, salt, SALT_LENGTH);
		memcpy(keybuf + j + SALT_LENGTH, password, password_length);
		j += tl;

		while (j < 128 + 64+1) {
			memcpy(keybuf + j, keybuf + n, tl);
			j += tl;
		}

		SHA1_Update(&ctx, keybuf, 64);
		count -= (64-i);
		j = 64;
		while (count >= 64) {
			SHA1_Update(&ctx, &keybuf[j], 64);
			count -= 64;
			j = j % tl + 64;
		}
		if (count) SHA1_Update(&ctx, &keybuf[j], count);
#else
		// Find multiplicator
		n = 1;
		while (n < tl && ((64 * n) % tl)) {
			++n;
		}
		// this is an optimization for oSSL builds (NOT for GPU I think)
		// it does gain us about 10%, more for length 2/4/8/16 passwords
		// which is case 1
#define BIGGER_SMALL_BUFS 1
#if BIGGER_SMALL_BUFS
		if (n < 7) {
			// evenly divisible multiples of each count. We simply want
			// to cut down on the calls to SHA1_Update, I think.
			//const uint32_t incs[] = {0,16,16,15,16,15,18,14,16,18};
			const uint32_t incs[] = {0,8,8,9,8,10,12};
			n = incs[n];
		}
#endif
		bs = n * 64;
		j = 0;
		if (i) {
			for (j = 0; j < i; j++) {
				keybuf[j] = 0;
			}
		}
		n = j;

		memcpy(keybuf + j, salt, SALT_LENGTH);
		memcpy(keybuf + j + SALT_LENGTH, password, password_length);
		j += tl;
		while (j+i <= bs+64) { // bs+64 since we need 1 'pre' block that may be dirty.
			memcpy(keybuf + j, keybuf + n, tl);
			j += tl;
		}
		// first buffer 'may' have appended nulls.  So we may actually
		// be processing LESS than 64 bytes of the count. Thus we have
		// -i in the count expression.
		SHA1_Update(&ctx, keybuf, 64);
		count -= (64-i);
		while (count > bs) {
			SHA1_Update(&ctx, keybuf + 64, bs);
			count -= bs;
		}
		if (count) SHA1_Update(&ctx, keybuf + 64, count);
#endif
		SHA1_Final(keybuf, &ctx);
		j = i * SHA_DIGEST_LENGTH;
		for (n = 0; j < key_len && n < SHA_DIGEST_LENGTH; ++j, ++n)
			key[j] = keybuf[n];
		if (j == key_len)
			return;
	}
}


static void S2KItSaltedSHA256Generator(char *password, unsigned char *key, int length)
{
	unsigned char keybuf[KEYBUFFER_LENGTH];
	SHA256_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + SHA256_DIGEST_LENGTH - 1) / SHA256_DIGEST_LENGTH;
	memcpy(keybuf, gpg_common_cur_salt->salt, SALT_LENGTH);

	// TODO: This is not very efficient with multiple hashes
	// NOTE, with 32 bit hash digest, we should never have numHashes > 1 if
	// all keys being requested are 32 bytes or less.
	for (i = 0; i < numHashes; i++) {
		SHA256_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA256_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + SALT_LENGTH;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + SALT_LENGTH, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = gpg_common_cur_salt->count / bs;
		while (n-- > 0) {
			SHA256_Update(&ctx, keybuf, bs);
		}
		SHA256_Update(&ctx, keybuf, gpg_common_cur_salt->count % bs);
		SHA256_Final(key + (i * SHA256_DIGEST_LENGTH), &ctx);
	}
}

static void S2KItSaltedSHA224Generator(char *password, unsigned char *key, int length)
{
	unsigned char keybuf[KEYBUFFER_LENGTH];
	SHA256_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + SHA224_DIGEST_LENGTH - 1) / SHA224_DIGEST_LENGTH;
	memcpy(keybuf, gpg_common_cur_salt->salt, SALT_LENGTH);

	// TODO: This is not very efficient with multiple hashes
	// NOTE, with 32 bit hash digest, we should never have numHashes > 1 if
	// all keys being requested are 32 bytes or less.
	for (i = 0; i < numHashes; i++) {
		SHA224_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA224_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + SALT_LENGTH;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + SALT_LENGTH, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = gpg_common_cur_salt->count / bs;
		while (n-- > 0) {
			SHA224_Update(&ctx, keybuf, bs);
		}
		SHA224_Update(&ctx, keybuf, gpg_common_cur_salt->count % bs);
		SHA224_Final(key + (i * SHA224_DIGEST_LENGTH), &ctx);
	}
}

static void S2KItSaltedSHA512Generator(char *password, unsigned char *key, int length)
{
	// keybuf needs to be twice as large, since we group to 128 byte blocks.
	unsigned char keybuf[KEYBUFFER_LENGTH*2];
	SHA512_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + SHA512_DIGEST_LENGTH - 1) / SHA512_DIGEST_LENGTH;
	memcpy(keybuf, gpg_common_cur_salt->salt, SALT_LENGTH);

	// TODO: This is not very efficient with multiple hashes
	// NOTE, with 64 bit hash digest, we should never have numHashes > 1 if
	// all keys being requested are 32 bytes or less.
	for (i = 0; i < numHashes; i++) {
		SHA512_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA512_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + SALT_LENGTH;
		mul = 1;
		while (mul < tl && ((128 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 128-byte blocks
		bs = mul * 128;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + SALT_LENGTH, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = gpg_common_cur_salt->count / bs;
		while (n-- > 0) {
			SHA512_Update(&ctx, keybuf, bs);
		}
		SHA512_Update(&ctx, keybuf, gpg_common_cur_salt->count % bs);
		SHA512_Final(key + (i * SHA512_DIGEST_LENGTH), &ctx);
	}
}

static void S2KItSaltedSHA384Generator(char *password, unsigned char *key, int length)
{
	// keybuf needs to be twice as large, since we group to 128 byte blocks.
	unsigned char keybuf[KEYBUFFER_LENGTH*2];
	SHA512_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + SHA384_DIGEST_LENGTH - 1) / SHA384_DIGEST_LENGTH;
	memcpy(keybuf, gpg_common_cur_salt->salt, SALT_LENGTH);

	// TODO: This is not very efficient with multiple hashes
	// NOTE, with 64 bit hash digest, we should never have numHashes > 1 if
	// all keys being requested are 32 bytes or less.
	for (i = 0; i < numHashes; i++) {
		SHA384_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA384_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + SALT_LENGTH;
		mul = 1;
		while (mul < tl && ((128 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 128-byte blocks
		bs = mul * 128;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + SALT_LENGTH, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = gpg_common_cur_salt->count / bs;
		while (n-- > 0) {
			SHA384_Update(&ctx, keybuf, bs);
		}
		SHA384_Update(&ctx, keybuf, gpg_common_cur_salt->count % bs);
		SHA384_Final(key + (i * SHA384_DIGEST_LENGTH), &ctx);
	}
}

static void S2KItSaltedRIPEMD160Generator(char *password, unsigned char *key, int length)
{
	unsigned char keybuf[KEYBUFFER_LENGTH + 256];
	RIPEMD160_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr, *sptr;
	int32_t n, n2, n3;

	uint32_t numHashes = (length + RIPEMD160_DIGEST_LENGTH - 1) / RIPEMD160_DIGEST_LENGTH;

	for (i = 0; i < numHashes; i++) {
		RIPEMD160_Init(&ctx);
		// Find multiplicator
		tl = strlen(password) + SALT_LENGTH;
		mul = 1;
		// +i added for leading nulls
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}
		bptr = keybuf;
		if (i) {
			for (j = 0; j < i; j++) {
				*bptr++ = 0;
			}
		}
		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		n = bs / tl;
		// compute n2. it is the count we 'really' need to completely fill at lease 1 buffer past normal.
		n2 = n;
		n3 = bs;
		while (n3 < bs+64) {
			++n2;
			n3 += tl;
		}
		n3 = n2;
		sptr = bptr;
		memcpy(bptr, gpg_common_cur_salt->salt, SALT_LENGTH);
		bptr += SALT_LENGTH;
		memcpy(bptr, password, strlen(password));
		bptr += strlen(password);
		while (n2-- > 1) {
			memcpy(bptr, sptr, tl);
			bptr += tl;
		}
		// note first 64 byte block is handled specially, SO we have to remove the
		// number of bytes of salt-pw contained within that block, from the count
		// value when computing count/bs and count%bs.  The correct amount of bytes
		// processed is (64 - i)
		n = (gpg_common_cur_salt->count - (64-i)) / bs;
		// first buffer 'may' have appended nulls.  BUT we may actually be processing
		// LESS than 64 bytes of the count.
		RIPEMD160_Update(&ctx, keybuf, 64);
		while (n-- > 0) {
			RIPEMD160_Update(&ctx, &keybuf[64], bs);
		}
		RIPEMD160_Update(&ctx, &keybuf[64], (gpg_common_cur_salt->count - (64-i)) % bs);
		RIPEMD160_Final(key + (i * RIPEMD160_DIGEST_LENGTH), &ctx);
	}
}
static void S2KItSaltedMD5Generator(char *password, unsigned char *key, int length)
{
	MD5_CTX ctx;
	unsigned char keybuf[KEYBUFFER_LENGTH];
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;
	memcpy(keybuf, gpg_common_cur_salt->salt, SALT_LENGTH);
	// TODO: This is not very efficient with multiple hashes
	for (i = 0; i < numHashes; i++) {
		MD5_Init(&ctx);
		for (j = 0; j < i; j++) {
			MD5_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + SALT_LENGTH;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}

		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + SALT_LENGTH, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = gpg_common_cur_salt->count / bs;
		while (n-- > 0) {
			MD5_Update(&ctx, keybuf, bs);
		}
		MD5_Update(&ctx, keybuf, gpg_common_cur_salt->count % bs);
		MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
	}
}

void *gpg_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	struct gpg_common_custom_salt cs, *psalt;
	static unsigned char *ptr;

	memset(&cs, 0, sizeof(cs));
	if (!ptr) ptr = mem_alloc_tiny(sizeof(struct gpg_common_custom_salt*),sizeof(struct gpg_common_custom_salt*));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$gpg$" marker and first '*' */
	p = strtokm(ctcopy, "*");
	cs.pk_algorithm = atoi(p);
	if (cs.pk_algorithm == 0) {
		cs.symmetric_mode = 1;
	}
	p = strtokm(NULL, "*");
	cs.datalen = atoi(p);

	/* Ok, now we 'know' the size of the dyna salt, so we can allocate */
	/* note the +64 is due to certain algo's reading dirty data, up to 64 bytes past end */
	psalt = mem_calloc(sizeof(struct gpg_common_custom_salt) + cs.datalen + 64, 1);
	psalt->pk_algorithm = cs.pk_algorithm;
	psalt->symmetric_mode = cs.symmetric_mode;
	psalt->datalen = cs.datalen;

	/* from now on we use psalt */
	if (!psalt->symmetric_mode) {
		p = strtokm(NULL, "*");
		psalt->bits = atoi(p);
	}
	p = strtokm(NULL, "*");

	for (i = 0; i < psalt->datalen; i++)
		psalt->data[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	psalt->spec = atoi(p);
	p = strtokm(NULL, "*");
	psalt->usage = atoi(p);
	p = strtokm(NULL, "*");
	psalt->hash_algorithm = atoi(p);
	p = strtokm(NULL, "*");
	psalt->cipher_algorithm = atoi(p);
	if (!psalt->symmetric_mode) {
		p = strtokm(NULL, "*");
		psalt->ivlen = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < psalt->ivlen; i++)
			psalt->iv[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	p = strtokm(NULL, "*");
	/* handle "SPEC_SIMPLE" correctly */
	if (psalt->spec != SPEC_SIMPLE || psalt->usage == 255) {
		psalt->count = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < SALT_LENGTH; i++)
			psalt->salt[i] =
			atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if (psalt->usage == 255 && (psalt->spec == SPEC_SALTED || psalt->spec == SPEC_ITERATED_SALTED) && psalt->pk_algorithm == PKA_DSA) {
		/* old hashes will crash!, "gpg --s2k-mode 1 --gen-key" */
		p = strtokm(NULL, "*");
		psalt->pl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			psalt->p[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		psalt->ql = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			psalt->q[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		psalt->gl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			psalt->g[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		psalt->yl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			psalt->y[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if (psalt->usage == 255 && (psalt->spec == SPEC_SALTED || psalt->spec == SPEC_ITERATED_SALTED) && (psalt->pk_algorithm == PKA_ELGAMAL || psalt->pk_algorithm == PKA_EG)) {
		/* ElGamal */
		p = strtokm(NULL, "*");
		psalt->pl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			psalt->p[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		psalt->gl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			psalt->g[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		psalt->yl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			psalt->y[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if (psalt->usage == 255 && psalt->pk_algorithm == PKA_RSA_ENCSIGN) {
		/* RSA */
		p = strtokm(NULL, "*");
		psalt->nl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			psalt->n[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	MEM_FREE(keeptr);

	// Set up the key generator
	switch(psalt->spec) {
		case SPEC_ITERATED_SALTED:
			{
				switch(psalt->hash_algorithm) {
					case HASH_SHA1:
						psalt->s2kfun = S2KItSaltedSHA1Generator;
						break;
					case HASH_MD5:
						psalt->s2kfun = S2KItSaltedMD5Generator;
						break;
					case HASH_SHA256:
						psalt->s2kfun = S2KItSaltedSHA256Generator;
						break;
					case HASH_RIPEMD160:
						psalt->s2kfun = S2KItSaltedRIPEMD160Generator;
						break;
					case HASH_SHA512:
						psalt->s2kfun = S2KItSaltedSHA512Generator;
						break;
					case HASH_SHA384:
						psalt->s2kfun = S2KItSaltedSHA384Generator;
						break;
					case HASH_SHA224:
						psalt->s2kfun = S2KItSaltedSHA224Generator;
						break;
					default: break;
				}
			}
			break;
		case SPEC_SALTED:
			{
				switch(psalt->hash_algorithm) {
					case HASH_SHA1:
						psalt->s2kfun = S2KSaltedSHA1Generator;
						break;
					case HASH_MD5:
						psalt->s2kfun = S2KSaltedMD5Generator;
						break;
					default:
						// WTF? (see gpg_common_valid_hash_algorithm() function)
						psalt->s2kfun = S2KSaltedSHA1Generator;
						break;
				}
			}
			break;
		case SPEC_SIMPLE:
			{
				switch(psalt->hash_algorithm) {
					case HASH_SHA1:
						psalt->s2kfun = S2KSimpleSHA1Generator;
						break;
					case HASH_MD5:
						psalt->s2kfun = S2KSimpleMD5Generator;
						break;
					default:
						psalt->s2kfun = S2KSimpleSHA1Generator;  // WTF?
						break;
				}
			}
			break;
	}
	assert(psalt->s2kfun != NULL);

	// set the JtR core linkage stuff for this dyna_salt
	psalt->dsalt.salt_alloc_needs_free = 1;  // we used mem_calloc, so JtR CAN free our pointer when done with them.
	psalt->dsalt.salt_cmp_offset = SALT_CMP_OFF(struct gpg_common_custom_salt, datalen);
	psalt->dsalt.salt_cmp_size = SALT_CMP_SIZE(struct gpg_common_custom_salt, datalen, data, psalt->datalen);

	memcpy(ptr, &psalt, sizeof(struct gpg_common_custom_salt*));
	return (void*)ptr;
}
static int give_multi_precision_integer(unsigned char *buf, int len, int *key_bytes, unsigned char *out)
{
	int bytes;
	int i;
	int bits = buf[len] * 256;
	len++;
	bits += buf[len];
	len++;
	bytes = (bits + 7) / 8;
	*key_bytes = bytes;

	for (i = 0; i < bytes; i++)
		out[i] = buf[len++];

	return bytes + 2;
}

// borrowed from "passe-partout" project
static int check_dsa_secret_key(DSA *dsa)
{
	int error;
	int rc = -1;
#if HAVE_DSA_GET0_PQG
	const BIGNUM *p, *q, *g, *pub_key, *priv_key;
#endif
	BIGNUM *res = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	if (!res) {
		fprintf(stderr, "failed to allocate result BN in check_dsa_secret_key()\n");
		error();
	}
	if (!ctx) {
		fprintf(stderr, "failed to allocate BN_CTX ctx in check_dsa_secret_key()\n");
		error();
	}

#if HAVE_DSA_GET0_PQG
	DSA_get0_pqg(dsa, &p, &q, &g);
	DSA_get0_key(dsa, &pub_key, &priv_key);
	error = BN_mod_exp(res, g, priv_key, p, ctx);
#else
	error = BN_mod_exp(res, dsa->g, dsa->priv_key, dsa->p, ctx);
#endif

	if ( error == 0 ) {
		goto freestuff;
	}

#if HAVE_DSA_GET0_PQG
	rc = BN_cmp(res, pub_key);
#else
	rc = BN_cmp(res, dsa->pub_key);
#endif

freestuff:

	BN_CTX_free(ctx);
	BN_free(res);
#if !HAVE_DSA_GET0_PQG
	BN_free(dsa->g);
	BN_free(dsa->q);
	BN_free(dsa->p);
	BN_free(dsa->pub_key);
	BN_free(dsa->priv_key);
#endif
	return rc;
}

typedef struct {
	BIGNUM *p;          /* prime */
	BIGNUM *g;          /* group generator */
	BIGNUM *y;          /* g^x mod p */
	BIGNUM *x;          /* secret exponent */
} ElGamal_secret_key;

// borrowed from GnuPG
static int check_elg_secret_key(ElGamal_secret_key *elg)
{
	int error;
	int rc = -1;
	BIGNUM *res = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (!res) {
		fprintf(stderr, "failed to allocate result BN in check_elg_secret_key()\n");
		error();
	}
	if (!ctx) {
		fprintf(stderr, "failed to allocate BN_CTX ctx in chec_elg_secret_key()\n");
		error();
	}

	error = BN_mod_exp(res, elg->g, elg->x, elg->p, ctx);
	if ( error == 0 ) {
		goto freestuff;
	}

	rc = BN_cmp(res, elg->y);

freestuff:

	BN_CTX_free(ctx);
	BN_free(res);
	BN_free(elg->g);
	BN_free(elg->p);
	BN_free(elg->y);
	BN_free(elg->x);

	return rc;
}

typedef struct {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
} RSA_secret_key;

// borrowed from GnuPG
static int check_rsa_secret_key(RSA_secret_key *rsa)
{
	int error;
	int rc = -1;
	BIGNUM *res = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (!res) {
		fprintf(stderr, "failed to allocate result BN in check_rsa_secret_key()\n");
		error();
	}
	if (!ctx) {
		fprintf(stderr, "failed to allocate BN_CTX ctx in chec_rsa_secret_key()\n");
		error();
	}

	error = BN_mul(res, rsa->p, rsa->q, ctx);
	if ( error == 0 ) {
		goto freestuff;
	}

	rc = BN_cmp(res, rsa->n);  // p * q == n

freestuff:

	BN_CTX_free(ctx);
	BN_free(res);
	BN_free(rsa->p);
	BN_free(rsa->q);
	BN_free(rsa->n);

	return rc;
}

int gpg_common_check(unsigned char *keydata, int ks)
{
	// Decrypt first data block in order to check the first two bits of
	// the MPI. If they are correct, there's a good chance that the
	// password is correct, too.
	unsigned char ivec[32];
	unsigned char *out;
	int tmp = 0;
	uint32_t num_bits = 0;
	int checksumOk;
	int i;
	uint8_t checksum[SHA_DIGEST_LENGTH];
	SHA_CTX ctx;
	int block_size = 8;

	// out is used for more than just data. So if datalen is 'small', but
	// other things (like mpz integer creation) are needed, we know that
	// our sizes will not overflow.
	out = mem_alloc((gpg_common_cur_salt->datalen) + 0x10000);
	// Quick Hack
	if (!gpg_common_cur_salt->symmetric_mode)
		memcpy(ivec, gpg_common_cur_salt->iv, gpg_common_blockSize(gpg_common_cur_salt->cipher_algorithm));
	else
		memset(ivec, 0, gpg_common_blockSize(gpg_common_cur_salt->cipher_algorithm));

	switch (gpg_common_cur_salt->cipher_algorithm) {
		case CIPHER_IDEA: {
					   IDEA_KEY_SCHEDULE iks;
					   JtR_idea_set_encrypt_key(keydata, &iks);
					   JtR_idea_cfb64_encrypt(gpg_common_cur_salt->data, out, SALT_LENGTH, &iks, ivec, &tmp, IDEA_DECRYPT);
				   }
				   break;
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   CAST_cfb64_encrypt(gpg_common_cur_salt->data, out, CAST_BLOCK, &ck, ivec, &tmp, CAST_DECRYPT);
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(gpg_common_cur_salt->data, out, BF_BLOCK, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    AES_cfb128_encrypt(gpg_common_cur_salt->data, out, AES_BLOCK_SIZE, &ck, ivec, &tmp, AES_DECRYPT);
				    }
				    break;
		case CIPHER_3DES: {
					  DES_cblock key1, key2, key3;
					  DES_cblock divec;
					  DES_key_schedule ks1, ks2, ks3;
					  int num = 0;
					  memcpy(key1, keydata + 0, 8);
					  memcpy(key2, keydata + 8, 8);
					  memcpy(key3, keydata + 16, 8);
					  memcpy(divec, ivec, 8);
					  DES_set_key_unchecked((DES_cblock *)key1, &ks1);
					  DES_set_key_unchecked((DES_cblock *)key2, &ks2);
					  DES_set_key_unchecked((DES_cblock *)key3, &ks3);
					  DES_ede3_cfb64_encrypt(gpg_common_cur_salt->data, out, SALT_LENGTH, &ks1, &ks2, &ks3, &divec, &num, DES_DECRYPT);
				    }
				    break;
		case CIPHER_CAMELLIA128:
		case CIPHER_CAMELLIA192:
		case CIPHER_CAMELLIA256: {
					    CAMELLIA_KEY ck;
					    Camellia_set_key(keydata, ks * 8, &ck);
					    Camellia_cfb128_encrypt(gpg_common_cur_salt->data, out, CAMELLIA_BLOCK_SIZE, &ck, ivec, &tmp, CAMELLIA_DECRYPT);
				    }
				    break;
		case CIPHER_TWOFISH: {
					      Twofish_key ck;
					      Twofish_prepare_key(keydata, ks, &ck);
					      Twofish_Decrypt_cfb128(&ck, gpg_common_cur_salt->data, out, 16, ivec);
				      }
				      break;
		default:
				    printf("(check) Unknown Cipher Algorithm %d ;(\n", gpg_common_cur_salt->cipher_algorithm);
				    break;
	}

	if (!gpg_common_cur_salt->symmetric_mode) {
		num_bits = ((out[0] << 8) | out[1]);
		if (num_bits < MIN_BN_BITS || num_bits > gpg_common_cur_salt->bits) {
			MEM_FREE(out);
			return 0;
		}
	}
	// Decrypt all data
	if (!gpg_common_cur_salt->symmetric_mode)
		memcpy(ivec, gpg_common_cur_salt->iv, gpg_common_blockSize(gpg_common_cur_salt->cipher_algorithm));
	else
		memset(ivec, 0, gpg_common_blockSize(gpg_common_cur_salt->cipher_algorithm));
	tmp = 0;
	switch (gpg_common_cur_salt->cipher_algorithm) {
		case CIPHER_IDEA: {
					   IDEA_KEY_SCHEDULE iks;
					   JtR_idea_set_encrypt_key(keydata, &iks);
					   if (gpg_common_cur_salt->symmetric_mode && gpg_common_cur_salt->usage == 9) {
						   JtR_idea_cfb64_encrypt(gpg_common_cur_salt->data, out, block_size + 2, &iks, ivec, &tmp, IDEA_DECRYPT);
						   tmp = 0;
						   memcpy(ivec, gpg_common_cur_salt->data + 2, block_size); // GCRY_CIPHER_ENABLE_SYNC, cipher_sync from libgcrypt
						   JtR_idea_cfb64_encrypt(gpg_common_cur_salt->data + block_size + 2, out + block_size + 2, gpg_common_cur_salt->datalen - block_size - 2, &iks, ivec, &tmp, IDEA_DECRYPT);
					   } else {
						   JtR_idea_cfb64_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &iks, ivec, &tmp, IDEA_DECRYPT);
					   }
				   }
				   break;
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   if (gpg_common_cur_salt->symmetric_mode && gpg_common_cur_salt->usage == 9) {
						   // handle PGP's weird CFB mode, do this for each cipher with block-size <= 8, take care of block-size!
						   CAST_cfb64_encrypt(gpg_common_cur_salt->data, out, block_size + 2, &ck, ivec, &tmp, CAST_DECRYPT);
						   tmp = 0;
						   memcpy(ivec, gpg_common_cur_salt->data + 2, block_size); // GCRY_CIPHER_ENABLE_SYNC, cipher_sync from libgcrypt
						   CAST_cfb64_encrypt(gpg_common_cur_salt->data + block_size + 2, out + block_size + 2, gpg_common_cur_salt->datalen - block_size - 2, &ck, ivec, &tmp, CAST_DECRYPT);
					   } else {
						   CAST_cfb64_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &ck, ivec, &tmp, CAST_DECRYPT);
					   }
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    block_size = 16;
					    if (gpg_common_cur_salt->symmetric_mode && gpg_common_cur_salt->usage == 9) {
						    AES_cfb128_encrypt(gpg_common_cur_salt->data, out, block_size + 2, &ck, ivec, &tmp, AES_DECRYPT);
						    tmp = 0;
						    memcpy(ivec, gpg_common_cur_salt->data + 2, block_size);
						    AES_cfb128_encrypt(gpg_common_cur_salt->data + block_size + 2, out + block_size + 2, gpg_common_cur_salt->datalen - block_size - 2, &ck, ivec, &tmp, AES_DECRYPT);
					    } else {
						    AES_cfb128_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &ck, ivec, &tmp, AES_DECRYPT);
					    }
				    }
				    break;
		case CIPHER_3DES: {
					  DES_cblock key1, key2, key3;
					  DES_cblock divec;
					  DES_key_schedule ks1, ks2, ks3;
					  int num = 0;
					  memcpy(key1, keydata + 0, 8);
					  memcpy(key2, keydata + 8, 8);
					  memcpy(key3, keydata + 16, 8);
					  memcpy(divec, ivec, 8);
					  DES_set_key_unchecked((DES_cblock *) key1, &ks1);
					  DES_set_key_unchecked((DES_cblock *) key2, &ks2);
					  DES_set_key_unchecked((DES_cblock *) key3, &ks3);
					  if (gpg_common_cur_salt->symmetric_mode && gpg_common_cur_salt->usage == 9) {
						  DES_ede3_cfb64_encrypt(gpg_common_cur_salt->data, out, block_size + 2, &ks1, &ks2, &ks3, &divec, &num, DES_DECRYPT);
						  num = 0;
						  memcpy(divec, gpg_common_cur_salt->data + 2, block_size); // GCRY_CIPHER_ENABLE_SYNC, cipher_sync from libgcrypt
						  DES_ede3_cfb64_encrypt(gpg_common_cur_salt->data + block_size + 2, out + block_size + 2, gpg_common_cur_salt->datalen - block_size - 2, &ks1, &ks2, &ks3, &divec, &num, DES_DECRYPT);
					  } else {
						  DES_ede3_cfb64_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &ks1, &ks2, &ks3, &divec, &num, DES_DECRYPT);
					  }
				    }
				    break;
		case CIPHER_CAMELLIA128:
		case CIPHER_CAMELLIA192:
		case CIPHER_CAMELLIA256: {
					    CAMELLIA_KEY ck;
					    Camellia_set_key(keydata, ks * 8, &ck);
					    Camellia_cfb128_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &ck, ivec, &tmp, CAMELLIA_DECRYPT);
				    }
				    break;
		case CIPHER_TWOFISH: {
					      Twofish_key ck;
					      Twofish_prepare_key(keydata, ks, &ck);

					      block_size = 16;
					      if (gpg_common_cur_salt->symmetric_mode && gpg_common_cur_salt->usage == 9) {
						      Twofish_Decrypt_cfb128(&ck, gpg_common_cur_salt->data, out, block_size + 2, ivec);
						      tmp = 0;
						      memcpy(ivec, gpg_common_cur_salt->data + 2, block_size);
						      Twofish_Decrypt_cfb128(&ck, gpg_common_cur_salt->data + block_size + 2, out + block_size + 2, gpg_common_cur_salt->datalen - block_size - 2, ivec);
					      } else {
						      Twofish_Decrypt_cfb128(&ck, gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, ivec);
					      }
				      }
				      break;
		default:
				    break;
	}

	if (gpg_common_cur_salt->symmetric_mode && gpg_common_cur_salt->usage == 18) { // uses zero IV (see g10/encrypt.c)!
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, out, gpg_common_cur_salt->datalen - SHA_DIGEST_LENGTH);
		SHA1_Final(checksum, &ctx);
		if (memcmp(checksum, out + gpg_common_cur_salt->datalen - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0) {
			MEM_FREE(out);
			return 1;  /* we have a 20 byte verifier ;) */
		}
		MEM_FREE(out);
		return 0;
	} else if (gpg_common_cur_salt->symmetric_mode && gpg_common_cur_salt->usage == 9) {
		int ctb, new_ctb, pkttype, c, partial, lenbytes = 0;
		unsigned long pktlen;
		unsigned long idx = 0; // pointer in the "decrypted data + block_size + 2" stream
		unsigned char *p;

		(void) pktlen;
		(void) partial;

		// https://www.ietf.org/rfc/rfc2440.txt, http://www.ietf.org/rfc/rfc1991.txt,
		// and parse() from g10/parse-packet.c. This block contains code from GnuPG
		// which is copyrighted by FSF, Werner Koch, and g10 Code GmbH.
		if ((out[block_size + 1] != out[block_size - 1]) || (out[block_size] != out[block_size - 2]))
			goto bad;
		// The first byte of a packet is the so-called tag. The
		// highest bit must be set.
		p = &out[block_size + 2];
		ctb = p[0];
		if (!(ctb & 0x80)) {
			goto bad;
		}

		// Immediately following the header is the length. There are
		// two formats: the old format and the new format. If bit 6
		// (where the least significant bit is bit 0) is set in the
		// tag, then we are dealing with a new format packet.
		// Otherwise, it is an old format packet.
		pktlen = 0;
		new_ctb = !!(ctb & 0x40);
		if (new_ctb) {  // Used by PGP 8.0 from year 2002
			// Get the packet's type. This is encoded in the 6 least
			// significant bits of the tag.
			pkttype = ctb & 0x3f;

			// Extract the packet's length.  New format packets
			// have 4 ways to encode the packet length. The value
			// of the first byte determines the encoding and
			// partially determines the length. See section 4.2.2
			// of RFC 4880 for details.
			c = p[1];
			idx = 2;
			if (c < 192) {
				pktlen = c;
			}  else if (c < 224) {
				pktlen = (c - 192) * 256;
				c = p[2];
				pktlen += c + 192;
				idx++;
			}
			else if (c == 255) {
				int i;
				char value[4];
				(void) value;

				for (i = 0; i < 4; i ++) {
					c = p[2 + i];
					idx++;
				}
				// pktlen = buf32_to_ulong (value); // XXX
			} else {
				// Partial body length
			}
		} else {  // This is an old format packet.
			// Extract the packet's type. This is encoded in bits 2-5.
			int i;
			pkttype = (ctb >> 2) & 0xf;

			// The type of length encoding is encoded in bits 0-1 of the tag
			lenbytes = ((ctb & 3) == 3) ? 0 : (1 << (ctb & 3));
			if (!lenbytes) {
				pktlen = 0;  // Don't know the value.
				// This isn't really partial, but we can treat it the same
				// in a "read until the end" sort of way.
				partial = 1;
				if (pkttype != 8 && pkttype != 11)
					goto bad;
				idx = 1;
			}
			else {
				for (i= 0; i < lenbytes; i++) {
					pktlen <<= 8;
					c = p[1 + i];
					pktlen |= c;
				}
				idx = 1 + lenbytes;
			}
		}

		// Check packet type (double-check this)
		if (pkttype != 8 && pkttype != 11)  // PKT_COMPRESSED, PKT_PLAINTEXT
			goto bad;

		if (pkttype == 8) {  // PKT_COMPRESSED, check for known compression algorithms
			c = p[idx];
			if (c != 0 && c != 1 && c != 2 && c != 3)
				goto bad;
		}

		// Random note: MDC is only missing for ciphers with block size
		// <= 64 bits? No! PGP 8.0 can use AES-256, and still generate
		// output files with no MDC.

		// This is the major source of false positives now!
		if (pkttype == 11) {  // PKT_PLAINTEXT, there is not much we can do here? perhaps offer known-plaintext-attack feature to the user?
			// gpg -o sample_new_fp_qwertyzxcvb12345.gpg.txt --cipher-algo CAST5 --no-mdc --symmetric --compress-level 0 --s2k-mode 3 --s2k-count 1 secret.txt
			// printf("[DEBUG] lenbytes = %d, pktlen = %lu\n", lenbytes, pktlen);
			if (lenbytes == 0 && pktlen == 0)  // heuristic, always safe?
				goto bad;
			if (pktlen > gpg_common_cur_salt->datalen) {  // always safe?
				goto bad;
			}
		}

		MEM_FREE(out);
		return 1;
bad:
		MEM_FREE(out);
		return 0;
	}

	// Verify
	checksumOk = 0;
	switch (gpg_common_cur_salt->usage) {
		case 254: {
				  SHA1_Init(&ctx);
				  SHA1_Update(&ctx, out, gpg_common_cur_salt->datalen - SHA_DIGEST_LENGTH);
				  SHA1_Final(checksum, &ctx);
				  if (memcmp(checksum, out + gpg_common_cur_salt->datalen - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0) {
					  MEM_FREE(out);
					  return 1;  /* we have a 20 byte verifier ;) */
				  }
				  MEM_FREE(out);
				  return 0;
			  } break;
		case 0:
		case 255: {
				  // https://tools.ietf.org/html/rfc4880#section-3.7.2
				  uint16_t sum = 0;
				  for (i = 0; i < gpg_common_cur_salt->datalen - 2; i++) {
					  sum += out[i];
				  }
				  if (sum == ((out[gpg_common_cur_salt->datalen - 2] << 8) | out[gpg_common_cur_salt->datalen - 1])) {
					  checksumOk = 1;
				  }
				  checksumOk = 1; // We ignore the checksum now (as per TODO comment below!!)
			  } break;
		default:
			  break;
	}
	// If the checksum is ok, try to parse the first MPI of the private key
	// Stop relying on checksum altogether, GnuPG ignores it (after
	// documenting why though!)
	if (checksumOk) {
		BIGNUM *b = NULL;
		uint32_t blen = (num_bits + 7) / 8;
		int ret;
		if (gpg_common_cur_salt->datalen == 24 && blen != 20) { /* verifier 1 */
			MEM_FREE(out);
			return 0;
		}
		if (blen < gpg_common_cur_salt->datalen && ((b = BN_bin2bn(out + 2, blen, NULL)) != NULL)) {
			char *str = BN_bn2hex(b);

			if (strlen(str) != blen * 2) { /* verifier 2 */
				OPENSSL_free(str);
				BN_free(b);
				MEM_FREE(out);
				return 0;
			}
			OPENSSL_free(str);

			if (gpg_common_cur_salt->pk_algorithm == PKA_DSA) { /* DSA check */
#if HAVE_DSA_GET0_PQG
				DSA *dsa = DSA_new();
				BIGNUM *p, *q, *g, *pub_key, *priv_key;

				p = BN_bin2bn(gpg_common_cur_salt->p, gpg_common_cur_salt->pl, NULL);
				// puts(BN_bn2hex(dsa.p));
				q = BN_bin2bn(gpg_common_cur_salt->q, gpg_common_cur_salt->ql, NULL);
				// puts(BN_bn2hex(dsa.q));
				g = BN_bin2bn(gpg_common_cur_salt->g, gpg_common_cur_salt->gl, NULL);
				// puts(BN_bn2hex(dsa.g));
				priv_key = b;
				pub_key = BN_bin2bn(gpg_common_cur_salt->y, gpg_common_cur_salt->yl, NULL);

				DSA_set0_pqg(dsa, p, q, g);
				DSA_set0_key(dsa, pub_key, priv_key);

				// puts(BN_bn2hex(dsa.pub_key));
				ret = check_dsa_secret_key(dsa); /* verifier 3 */
				DSA_free(dsa);
#else
				DSA dsa;

				dsa.p = BN_bin2bn(gpg_common_cur_salt->p, gpg_common_cur_salt->pl, NULL);
				// puts(BN_bn2hex(dsa.p));
				dsa.q = BN_bin2bn(gpg_common_cur_salt->q, gpg_common_cur_salt->ql, NULL);
				// puts(BN_bn2hex(dsa.q));
				dsa.g = BN_bin2bn(gpg_common_cur_salt->g, gpg_common_cur_salt->gl, NULL);
				// puts(BN_bn2hex(dsa.g));
				dsa.priv_key = b;
				dsa.pub_key = BN_bin2bn(gpg_common_cur_salt->y, gpg_common_cur_salt->yl, NULL);
				// puts(BN_bn2hex(dsa.pub_key));
				ret = check_dsa_secret_key(&dsa); /* verifier 3 */
#endif
				if (ret != 0) {
					MEM_FREE(out);
					return 0;
				}
			}
			if (gpg_common_cur_salt->pk_algorithm == PKA_ELGAMAL || gpg_common_cur_salt->pk_algorithm == PKA_EG) { /* ElGamal check */
				ElGamal_secret_key elg;

				elg.p = BN_bin2bn(gpg_common_cur_salt->p, gpg_common_cur_salt->pl, NULL);
				// puts(BN_bn2hex(elg.p));
				elg.g = BN_bin2bn(gpg_common_cur_salt->g, gpg_common_cur_salt->gl, NULL);
				// puts(BN_bn2hex(elg.g));
				elg.x = b;
				// puts(BN_bn2hex(elg.x));
				elg.y = BN_bin2bn(gpg_common_cur_salt->y, gpg_common_cur_salt->yl, NULL);
				// puts(BN_bn2hex(elg.y));
				ret = check_elg_secret_key(&elg); /* verifier 3 */
				if (ret != 0) {
					MEM_FREE(out);
					return 0;
				}
			}
			if (gpg_common_cur_salt->pk_algorithm == PKA_RSA_ENCSIGN) { /* RSA check */
				RSA_secret_key rsa;
				// http://www.ietf.org/rfc/rfc4880.txt
				int length = 0;

				length += give_multi_precision_integer(out, length, &gpg_common_cur_salt->dl, gpg_common_cur_salt->d);
				length += give_multi_precision_integer(out, length, &gpg_common_cur_salt->pl, gpg_common_cur_salt->p);
				length += give_multi_precision_integer(out, length, &gpg_common_cur_salt->ql, gpg_common_cur_salt->q);

				rsa.n = BN_bin2bn(gpg_common_cur_salt->n, gpg_common_cur_salt->nl, NULL);
				rsa.p = BN_bin2bn(gpg_common_cur_salt->p, gpg_common_cur_salt->pl, NULL);
				rsa.q = BN_bin2bn(gpg_common_cur_salt->q, gpg_common_cur_salt->ql, NULL);

				// b is not used.  So we must free it, or we have a leak.
				BN_free(b);
				ret = check_rsa_secret_key(&rsa);
				if (ret != 0) {
					MEM_FREE(out);
					return 0;
				}
			}
			MEM_FREE(out);
			return 1;
		}
	}
	MEM_FREE(out);
	return 0;
}

/*
 * Report gpg --s2k-count n as 1st tunable cost,
 * hash algorithm as 2nd tunable cost,
 * cipher algorithm as 3rd tunable cost.
 */

unsigned int gpg_common_gpg_s2k_count(void *salt)
{
	struct gpg_common_custom_salt *my_salt;

	my_salt = *(struct gpg_common_custom_salt **)salt;
	if (my_salt->spec == SPEC_ITERATED_SALTED)
		/*
		 * gpg --s2k-count is only meaningful
		 * if --s2k-mode is 3, see man gpg
		 */
		return (unsigned int) my_salt->count;
	else if (my_salt->spec == SPEC_SALTED)
		return 1; /* --s2k-mode 1 */
	else
		return 0; /* --s2k-mode 0 */
}

unsigned int gpg_common_gpg_hash_algorithm(void *salt)
{
	struct gpg_common_custom_salt *my_salt;

	my_salt = *(struct gpg_common_custom_salt **)salt;
	return (unsigned int) my_salt->hash_algorithm;
}
unsigned int gpg_common_gpg_cipher_algorithm(void *salt)
{
	struct gpg_common_custom_salt *my_salt;

	my_salt = *(struct gpg_common_custom_salt **)salt;
	return (unsigned int) my_salt->cipher_algorithm;
}

#endif /* HAVE_LIBCRYPTO */

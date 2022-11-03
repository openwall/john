/*
 * Common code for the PEM format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#include <openssl/des.h>

#include "arch.h"
#include "pem_common.h"
#include "jumbo.h"
#include "aes.h"
#include "asn1.h"

// $PEM$type$cipher$$salt$iterations$iv$blob_length$blob  // type, and cipher should be enough for all possible combinations
struct fmt_tests pem_tests[] = {
	/* https://github.com/bwall/pemcracker/blob/master/test.pem */
	{FORMAT_TAG "1$1$0c71e1c801194282$2048$87120f8c098437d0$640$c4bc6bc5447bed58e6f945cd1fde56d52aa794bd64b3c509fead910b1e7c1be9b6a89666c572c8ba5e469c5732ff105ecb97875efc2490ea9659082bdf0f3a2fd263ceb86bde4807bb85b01ca25efe25655fcdb9d54db94f7f48bb9b04af2bad5c2aaed87dc289da8b3fb891a9797f73adacb05b21717fe11d4ebdf8f1d39ecfcb8791447263572f487b087484c02e40a13a89c0613ebc4958a0853781eb1382c1f9ac1f1f97dd06e1a26d98088c5f262680a33dbf2e7742a436847cead5af15c538a5eb21b99e0c4ca30d08f5e805678bdbae6a3ee53623b7cebaeac6c7dd54834f6806112909d2d74da35ea907d35cfbd9cfcca4c302e9dc19b3017957747b4525e7832067d462f15451ca47be771add080da835dc177c26df3dd3fbf4b44d0ac7aea30a44469fe542abaf9bb2787b5694c7fdc1b9765167bf9ea5bf695e927bb98217491d7f1843a1e39e2a1a6a178b03e391031a80943f08b6dd7fa5104e38c4a4bad773775a71f5d076641a52a1100e701c14e5a15ac3dbaefad5f2ceb3ccded6689aef2bc9060c36599580f34324ecfa8cf2628da6475934bb53a8f7ef4a07fc1d0a4d41bfc9bac91859ce98f3f8876bbfba01bbe4491fa2d511b2f6eb5ae7ad4213a24c21fef676c8713de9c674d7a88d8844765732dbab43ee9faa5245ddb6fd6d66ab301b82dca829aeacaa5f178cd12aa0565c8a2d6c00b8c7f611ceedeee8ea68d99582fe9ba701c46d1ea78c88bb942ee3e30e83d9843cbda720bd2dcc07f2b4497e781cd54156e5e1022c4fb5827ab4e0469bb40500a6978eed0f27e0258e7304b0745e90eb36bb8d8e1c15c458313c547c3bfe54d75ac26405c40cfa0fecbf2a95e312870c08b13e6b36494c09c8a8ef12057e090a24e05fd3", "komodia"},
	/* https://github.com/chipx0r/crackpkcs8/blob/master/AAA010101AAA.key (DER format) */
	{"$PEM$1$1$0201000282010100$2048$308204bd02010030$1224$7810797b68d48268c0c0d55951a17099e54526a84ac06ee71104028d4171fcb7518d7cb0c841e8ed728712dfd56f5a7a4d5e364978283ae58db0237e941a7efc82f9d4d0d3a6c9491792c3d5ae4cfb86a36d015a233d4b4deb997e31502c211543e8e2c978a6766cbc79cfbf33af1e93a75cc2193fcda712fe0894b2e6263a4caa9b25c2bff75f7c9e83af4f6a7caca56a514177c0b46f0fa47f6f7042e700a89ff7b1a770544d97a2589a8645181a5b8ae7e3d65b24f5487039943bc9a88cf7ac1478c90d29c0d2706759a52f4d85e2d2cad3f9d2d939ec2c051f1de467525a1f5990cdbdc096e360708cb1790e6d98da6a9dd833c7d4dbdcd1c99f0a02a6829c11c27d88db89be7a9be2e69e4f9272a324410f92ffeda9ce7d8bcdabaf048e29fce8d08010de6e5a36d97eec5fd380f586aa077aba0828d0e6d90336bcf71ce8139be6a687f908f13127f6b70a7f846eee60b54fb54c685801aa9212f1824d6dc81e805d08175169092d39c23754e4292d6009cf9ef0be3e3f8c143787fb5f389081c15aa3cd1ba740cc02f1460b4a4e519d2759790e8fb811623ed26bcaa234449caa037331670de0859cce75bb723d55c7b7ae47f4763450285a263d55273c3ab1951e650c0b2c60060d70408092f1b129c0436e35a2ffa3479708d2d6bdbcfb4261bdfc63c7d3ba862e005bcd90dbf9011393ff78ec259ff8ca49b2e08bb2328a6d45147c64407d4563991c2a103315c22af39ac6165cc745f3c5f4e2104a638d23d91c5900b1924f1a1b5bb5cf06e365160b4f1970999bf29ce81a591a5337c63845e043206d64961bdaee7aaaa0ce35ea85c11bbd4829a0ad8c0c11944ea981aaa7233fd64006f6151e78d69ab29d7e9d07a0c1d672169dab6c59925996ef819e17fd0c1954b0ef594807fd15af67240cf0142cda288b2f18921e29267f87ebc89e48da3bfaf1b3012b5513937d9cb594ed8227fc67020cc51aba43c4d24f962bf731c3bd4c6c18cbfcc7844e8f768f17bba36c322b0d53a4c1f01736eae2cdbffee45a1366367040d6ab796a4967ea1387acf0571818933542f42281553cd7426d2d3cdf8cc06177e0b592c3cd5a5e2ea99e329a976c860ad3f3577bd7adc6e39c378d0ef81fdf4c71e63bb74c801678bc002955050fafb8a5ba6547b1648c44fff4a7947dab8aabd5b0e6f52e5808f7af7726164d271e192ad71e68d8cc92c1b6973fb3bee6ca736a6446238672a4d9744da7a929fc5611bbe41db17f6f68325b2ca476127482e1f53a50e4ced37219535e63df03ac837d10ad7a0a9ed489fdb785f7d72f147b8fad03d6c42b70b3494bc249073553a6e9734ef78f0ca32d70d692f88baf02c2671e619698ad88661c674bb9eb1c150ad941a50b0d68692b64adcacf15b3f5f0c31362f4c1c01525e9772fdbf80ae8e67f3bc3ed0c1d1725945f1929bb50ff29b8a06eda444ba8ee8ef52572503e364a4ceb55335110c7f14b33fe5bae70d2a32bcbb6862dbfdfed4e7202fbc811e9e12b9336869a7f297ed3e118dbb3eb2cf1f0978b168303ed559b19379f8f8e8a4bec8cc1e1499e945e1c4ab09ee917a4462ad7d11657241afd26fb9dabed2adf34cbfbd1b3468d669de22f6dc03acd2ed64435085358db2d761a8af5928687d8551de630109da48a9a06ab2f2d07fd056f47683c077f85878f5084a62b77c37a2efbc8f347306c4a2a6169f90d60", "12345678a"},
	// openssl pkcs8 -in test-rsa.pem -topk8 -v2 des3 -iter 2049 -out new.pem
	{"$PEM$1$1$671f19f01d9d0275$2049$50524fb9fd8b147d$1224$cae9d4d53583f50d4c468eca9061458ff1316732d6f28a70f0a1740021f594c8738ca58bfa0e4eb97a826776c3dce6ab89dd71ad30bf7630ec2f1fb18d895954f42a61ce2529e26b7d868267c44b21c03fac11387ce1d5e5b88a75f2038737820ccc768c72e0cdd3d78ba912fa6255eb4e3738cdae60109be2450d053aa91fb62a312263f484eae6f1fb757cf7d92e63f066498e4ed809e5318143f48afde4398a695bbe6804148b319c4f54633f91a08fdcc373a4a66b6f14a2b659e149a25053ff5bc0035b58aa462c8558ab3aefdc2770bad36b5fde810d6fbf07c29ea8e3a72fbfaa1b977663f8b61129b50658866d4a39bb4e9da24b4ef226170a3d9ded7f99a4e6265ca65ba94078da5f2ade1567bc93812205e8ff085cb07479af22e261d1255e29b02aca3278ac29232a49d2656b217f4822d72c7dcd24d2fde44aab525f2bcf970627597b26cc540c9cf8112002fdb35c2fbf97d7532648fa2c3b0508d974b35713a1ff81ff44f8414867e4d8f6b4027ecfd47fd4992b3a3e6e29b43c6ae76c2d503bb5bb260655960b659e55af66254bbfb248a247df3294518fab8295640c4f317ab25adf345f8693dd89514472938da1801d405c3b75419d39d6fe9a554d798da2b26566eef4f7e360dfb2802f68f33d6d4fb756d2e2140f5fef476048fdd923371d6dd494b3aed07fd7733d03783921296ec39ab392ff13bfed5e2c52c1642d999c57635230a4fb7673c5a003bd6b407179a49b2967dd39b1668c35ed75f4517c08d8ee21186a15076fe289733eb4a9a6b90bc61c4ace009ffa40e7319e54006214297f2f219b9fc3c6931fac9568d2d5e457954a6a4999959cbee476e6142b5cc6a373fe7504fe41ac09b5d4f6af9e02357076556f787dc47c6ab9783fea53d1c87c65718a554c5fff242c15118c90f6f6a61e8a0427b98f5244b0f43138493393834f8991da9411b53e394615ebb3303018a905b41baa4be084b0c9008d257018add9278a676d53d812b6c494ebaff36509c9e82626a1c81ecba85ccd569fbebd7d6d546b45439315dc2a37fdffcb356e79122211ad295a2819b9ac30aa7344bc26b2bd618c15d6bd52c90741ef8c3baba7e54daee004c3ecadcda4fc2e63c769a98a540e12b1c37bb47935a5bbd82762e3be995244a766755c3007477b22392998694de7be8f695048870d78d4e57cc222cfae9251bc21ad4f6b3303473b0da554464862a24da4334701389730eae91b70c5ecdad201e7174ef7ec09928a84f4f64d5b8e7398bad1d25a4a9b17e0f58da58377ec796273f5bc48cdda81e9cf02434ee06f10f8330b54e0f102fd79105c2a4d85e4c5d275fe47107bd76d66b88b59489d7ca36c2e8a104426c6f34c48425ea33d610655178b13af409ff807cc196e48d4036e3d01e485ee0420f6ffbadfb142fd08459b0ff1c1c2d424aaa553bb73a90c19fa454b6f4ee9732f13d666b8fb8a86fe08b394ce94a0d68d091dfd124e386d19882782afaa9b97ce626123962e784c41398499ec1b8848be2b2c62597dfaf91d7e4cfef0a5b8bd4d9afa5824c3bb595029deb8b67c55d9eb976215a10e1846b1b82f0e1ad6968fbe2b98b3f50e0ec641dcbee8ed4c078ba09b2fea93800172fc0ae64f9ad510d59925f50a214168b431f1e88a26e77c4d507503f483bb1955b4cbc4571111dbbf1c78a1e4915ffba4be4fafcb22410032d86df1aa7e", "password"},
	// openssl pkcs8 -in test-rsa.pem -topk8 -v2 des3 -iter 2047 -out new.pem
	{"$PEM$1$1$029375ebb44d8c3f$2047$3c7dbbee4df5863e$1224$b97ff356c7687abcd4ea17527b45eaf84d69ac127ddc4b05383331a56e9a0c26661735f9fc5298fcef7fe4280ccafed909ef8494e8dcdc75ebf23daeb3eb28ce5e1e6181c050e6c9416b41176eb87a12ec6898b90a75b0deece18eb7d4c13372eedf1060ceac9230d77843a21dbfa24edd1e41d6aada961f205295198bec11e2d87ae5d2d07daf1b5f5a21455d68003ba40291c20b91114d9339b69a4564c749b64668b209f8a7cef029c8d7f6369c17ddc6bee527576c3da794aeb6125ce9f7d41fc8d5690fc2447a594721390d7803bc600e2c67801636072047f51ca1a9fff2d629e987aa18aa4b08d0f7dce547132d8073718ab2b1fb9ce7ce46551e82749f72ef228b6e8e4420395efb3e90ebe9cc15719f3a0afd71f387a2d432783804efdccf2b554fa4d60c1a5ff385ed784f1cb4b8fe013a08c08e1f9457897457f7e342a5071e471ad261708fd0cb9c75040a85ed27ac1079379557c4dcb74384701f6e30514e80788a543adb036135d94cbdf1feef5c0d287cc081fe75eddb29e37b462c4077bf07da74bb16ee96df3d7f1bcf616198e11d4c489eb33712b29e26c0d32df878074d7e145684cfec9d4f26e53d1cb10d45b13b55195ae9f6afa5c93b67e423558aa73cc4c6d83bb6ff80559076201b352e60f3bc0f018f79e6282fa6ce322f51703860f2da59606d8ab3433ced6359f3dee0d5b046929f1068903460cb84c5c2b2e2c478cc8547d88227aec9b2cf099d3a897778410a0e43138dc30f30768d3e90b675265f725e6b9cd7ca4a7db912c3e67ab2d680e8bf7e3f1ef9b9815b15873ee6a739972117dc4736cfe256be12b70ca1661cb9d32d69a396de5a0ceb81de37c1c395146f479b6e2b24017ee487b68e0b77bb4890533a50275caa68ffdc54cff2652fe94956d0b2c0463104a1b8e04f01f0c125e1125ce598a75d61152eabf97a58e6e789f60e240958b7e75ac208e48465150f389b9a5ff7ae5636cc29e72a573e8faf0ee80bd1a2a2e846a897019d75cad79b16a59be3da46a823baf9a04104d2d009e2780d21c3439c7e791f3ec63a296fbf4dc15e955e00e1be652cc70e930a08db2797694aeec3c20722b65e0cbaa8e3b753b3a51f3b16f32fbe55876f48615937e4ce9da7d985c8772923fce3cd6c463b422ce61fdfff8ba28df7a3cdc7253ad4ce0a35218962a45edc5dd3e24a2248e407d6106dab81cea41b453ac509c4f0ec03d220ff84c842755f4f8673c0975cac13f84f7176cc9c4cd27eb74b42065ea9a4853ef0d2940596f112f3c766db0b6c7e5d5d91bb0aad5e44e34abbc871dbfdb7824e014fa7d2ae62bd253f422482538c4c35dcb7f4a20c915b698262737df04bf7e6806d5bbfff7c54d6ba4c5892dcd122bc0fe80c7399228029cc4c29f388d9787c46d609abb2554a010984db73e8605272a1bd7570aca1ccc04edee3d704b7387bd9866423a015a88e4efced478c00210e213c3d2b2bebdf1584d9a8fb2a31397a12a2d07ecf6247c70d2950f0db3f64aad13647e7db47ca51d7c95f50fc016d9731c992f2463f794ea915b7b5307db6de25fbd3ba7a7b4b15f7a011ab399a2b8c73cd5a7a1b00743928499effb5ab1a402e8600c52f8d1204d8923c2d8e41cdd941d591b554f79dfee3c3eb33a427ab360f90a8820c2957e2b5afd06ea3f02df3563eec9a06f64a6e019e33ed0a112d53382d071cbf835907094158", "alonglongpassword"},
	{"$PEM$1$1$74ae53fd1cf3e5e8$2048$33c1919f1cd1e8b8$336$6e59f6d3fbb084e224da89d23bfe0aec18f1491f58e334119ad83edd10d81b636622736e8a712a34959d78da79af603ec33d1a57bfaef2081e0ff8eccab31a0ad9cc18a60c20c1a2e15790c89972c5abb642a76ddeadf6fe8423c1b1737286a177b931352c5c78d105f828e9dc30fba659147f920aeaabb006988a020845faa985b948de42cc46b23406fffd2f05756c9e13e2fbc049c4be4736f9ec770c8da288a908e8abbbe1fe5c75cc65b7721d4eb338e67fe1bba937830cb9e857f3236a2894059bead0266e6ff78c7a52cab687b5e256bf1393674cdd857062d860434c530647d21edaa7f79b0e134de5cd536117ee5cbc49065c6142b30c1d3e5b0de8c55dd2748ba8bb5915498d5ed3c4abaedba13f4b10a8ff10d3383bce98dd3d52a6393ff1e791d9410bc90b34e115ed7ce10cdc75e6df29c31714983af39f1513395ef89cf2d57f68fc134996ef1afa0b", "dsa"},
	{"$PEM$1$1$cbb6cdcfc1b27cc8$2048$9b9e633ba83d48c2$144$54f2ab743656618ae51062fd6f2ff07a5078dcf3a1fa52075f50f4508e0c342b1f3e29703f4932c689e29f385f7ad73bf96ec7bb536ea8dafd40b9e5aee6f3e27dc21ee538d9e146a9361fc34ae5dd818b23c106688a451a5e180362954698a35111cef9315ffcd6cb4d440a6899177ff0384a9533923c05f97a5bbd3f94415688ca5c3af97f9edab771dc84807a6bcc", "ecdsa"},
	// AES test vectors
	{"$PEM$1$2$c5a93f2b9c89f049$2048$eb981bb835ce523e611ceea4e30e02f6$1232$99f07cc77bf8d11562e3d74fa6adb2527fcbc3ab5c7ea53dae7e744ec5d4f5542bdbc78869ab94e2d51e39b6d664ac7d9d532e302ad981ef59e350752e247b78e0576b8c174d94ffb6e608bfd6bc312e17ca2f4ad9845c4adf9e9fe7f09f9b4a3425263db4b7320a819de50e5b422c6f92d2b03057f092a7240a3120190e5c58e20f86cb66ee5402a5afd2ca42781517106896bb5e33d9714db53d803de44ca08231fd0e3c7415d4bf9ee9d92d7fdc381e62ed51fb233ac1d69b65e493c929eb00816b23f42289776b5db77165ec5bcd6b3c28cc4155a44920ee0db9b41adb4939ea7d3661253a89a3df9d88eb88c76aab7958ccf532c60df42e372fc80b97ec1d22ee40c85db1a7bdd9a827153b88f4b4f24985fbd1a513fe0ed7d6cda0744262c1ba9ce21605704d82164a1544d449fb71192969e063c7b5911cf811689b97f5b6339d6d53a54ea6236d925f531879687ac426a838017f932b51fb9d33560adb1aa80dd5c077dd87a79ea57ab18fc72e72d34b7ea662142f39297b9a9ab01f8c0c029358c16463b2648603bf7e1fec925257c8d2dd1eb14b76e27087d5f8aca35f556d36fd9f41cef114dc68da3d286fc12e260a79465367353680a1413d70ab2d49d1d20e2c7e6e436a34dab518dc0a925c0f9c9513740ee3c1c4f34cfa95972569fc04c4b3daaca1fca113f0328e893b5d38435274e0d954d51bc68d31dbd2088c3077e78fa7062ddaf2b14c6f0ec7dd7d68f9e34e1724fd806fae1e76ed5ef9fb3c498a891e43ebbe9520de7288ee5f66c5be076b7f399e93a4df6fad68bcb784a1346b1035b67949791e2e79845a3e0af41bb2c8acbba548c6b8043f0c444bd32f3d49f0b5aeff651142bf05edfbf438cc50b42f9ee1548cc223bf8cdd80bf2afd57dceb8a377df349fa72cbf3be96a60ef5678b1836544da54ef61b90b0efc87138520c777ae7707dd73a7ae9be8504de68fbe154722dd6cef25c3242641941bd022c409ca7ff9d7f4ac58c8907e350863ba121d39eb77d04b53f839d05da6437cf80888ac506a985e601852b6b18bddff0e4aeaab2fae5caa8f750b84af1e7975945137c45f459bd32ab80f0be8267644c3c89b1fa70f06e8f1086bae9830fa124048dcbdce5a8edde8ec547592a8560e00c6a97cff49bb7041feb03bbb83f1f39442fe4091692ecc0e227506ac18bbb22b5ac851c9a52cbf0c2a741655863980ab95e77d6f70abb0c06000d955d0ee932d256adde74282e04dd88cf6c931417ed3ea0d0e4542e1618ed9ebd35d348c2c358ca33a6ce7db3444dd474bd7769c5bc12b211ab59537a8ef4b33a2ec918a9cdd490459c747d8ffae35f1b1f99bac614d4b0eb0ffda3d76df606a466fea5e3e5f35ce2acfb38ec041ade97941dd90993491f4ca3092d58321d6e6cb4c814a41e306894f972710627eed4f91519efa0dbcbd18cf84d3b6fe9152355bbd0d0a44d6b701628598984dab1f99f4fa185fdc3393d5db768a61a68925a3f337fa95bbdf7ce211b6fc7525180264885641b6a935bed11fee043b5686a3334594829ba5effe66404bb0608dd8edd108634f877676dc8fb3fa845b425c8446941d0da600b1578dfb20a2c401d4f6d634de28a54208e64b2fb3ec520906ddf45b2c34e67db8270d301e90e67382082b2739339a4373a3ec2720ee38d5490a7694ebe55a1d99bb4a4a1ccfca0ab544c6be54498697582dbe9a9bbc4438ffd8030", "test"},
	{"$PEM$1$4$f9485289c3439d60$2048$abb7527cb22b08dea6312d85e29c0015$1232$aea7e5373582b08247a4347f1d96352bc76a91ee54aff310776b788ada4307a13e257bc3332a76ecfbbf578f76b512531183cf37a190ef214f7e9c5a3f9914f288f150ea84959e2dd242c4c4a9803602054238987bcf6aeb9290d95fcaafa099a8258329a1fd5d20d7ac9e0ceaf64a27b89696afa98636da278ec71dae5316fe53fa2ab1f3a7bd4a343507f260bab03aa2bf7d8f2e78ed8b2a0039c08fd0c1c38a9f65085e925ae2c89fc47b6bea5fb64a6108252982aa847bf4d6243158488f2db1bdf2e2daceaca7045ea3dce1749fe80af00dd37ecd5b8b0a2ed56a3f0ec2987dcaf50ce0c15f0fd1454deae708b5cfc3676307d99fb4dd29cd512f6b6789d969a4ce72e126aa6af7213304b6dbe16e7397e7a7f15eab2b4b89caaa15ffb0ce14244e721d90616c8376dca5b8601aa624f980ce6ebcb0800fed04ff568d423061c6f41a78ddced0b26222c7ec472f463c151dfeb9510e3ce3e6119571a1181f9aa1401c18c294fe611addb26f056e39c23d320a882c6155dc04b7cbf531c49b8cc0dd3744dfa6a246d1ed3bf7fe985f5aa0713f143947a42993804f33a58df50a3abf0d2037107224b02d4e77feb8fdecc49d9cc875d352209b6d0a05d3c7aaf44a6557ca80a75960b1f199966b73f162ca795bc31da991e287b7f38b6ddf4ef15e4231d870bb3f4cadb5a6c6e7dc79a93969ef17f7743c8d75426802ed78fc8976d4b388d4ba4026184166c59e5c978ac1654231c43a490aba5e629caec3502593e05227688a81cce102f6131b1825e2ec374fa852554e08a80feaa8f60383013c9f2f5a9a3439b29c6ddb19ad423143a30fb5a8eddafec76d4611a80788ccc48269f0c3a3d2540dee710d1d173ab208ccbd11c880102cca3fb41444eed4bbcd9ce8fb31071f5a4007c0326eb5b30e19e40605e62459b49745a7a08ac8b81c60ecda39be4e1b66975085ca73b0d785de99bcbd5dc3a30a58de547387bce058eedf864b04ffeb1aeb5447a5584dbb2a04e177effe30982403a9d73bb0ebee504f074fb946fdce4f4a1c45873db9751dcd98cc7290098afbbcfc6c368f85db7c65d0c9292ca05f8f40a15811519b66379cd92a2cba0d1cea9d36cb8de5078a1fbd2cf38be6fb4ece7997886f9a5ff4258984e68026984f802a8e6b0a09d93940fc09214436b83e2bc0222d7999df1a5f896d89341eb029629b40e70e1543a207c9c44658865773544ac3f8fb6506f9fb90ecb1131a2d62952801fe5a9d4980d8149353d9c9679bf3a1e6bccfb2ca24f0e019bccd13c991678c12de59e3693bc08c94ff376d7bb00829ead3f4757096c13fa0207be2e676dc28ee7812b067851c8030a695e77c1a6f72ee8fb5e5060b15057c6d38a2ed85a8a9c4a37f17b27d590c0a83b8010c2419bd46090713d18b10191f88769665e27a62858bdb52da0d21b7803417243a6a52b30ab15893fd65e0ba06b73567064d242d1e0230056d18b266a4f4e17c831539905eee1a3f4ae6a0a8f1a2881f9b50a1d89e43ba8707731c3b93c211af2c4ad4981b053b8c8f629207de4828442cd5e56e291c3a740a3b1ffa3d956075142ad80f393f2a7e478171bde2743fdc0eb9edfd52aa1f4633c0aacbe11b541efe4b4980dcf6d66b0180fc1d9f3ef43bf0a30a3690e1d4dcf41c9e5a8f3cd49a872e275170c8ce0e352f7d6731e36895529907199e419820078d9aabe30f0bf5bfd3979f8c5a0dcd6940", "test"},
	{NULL}
};

int pem_valid(char *ciphertext, struct fmt_main *self)
{
	static int kdf_warned, prf_warned;
	char *ctcopy, *keeptr, *p;
	int len, value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // type
		goto err;
	if (strcmp(p, "1") != 0) {
		if ((p = strtokm(NULL, "$")) == NULL)
			goto err;
		if (strcmp(p, "pbkdf2") != 0) {
			if (!self_test_running && !kdf_warned) {
				fprintf(stderr, "Warning: %s kdf algorithm <%s> is not supported currently!\n", self->params.label, p);
				kdf_warned = 1;
			}
			goto err;
		}
		if ((p = strtokm(NULL, "$")) == NULL)
			goto err;
		if (!self_test_running && !prf_warned) {
			fprintf(stderr, "Warning: %s prf algorithm <%s> is not supported currently!\n", self->params.label, p);
			prf_warned = 1;
		}
		goto err;
	}
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // cipher
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1 && value != 2 && value != 3 && value != 4)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iv
		goto err;
	len = hexlenl(p, &extra);
	if ((len != 16 && len != 32) || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // ciphertext length
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > CTLEN)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
		goto err;
	if (hexlenl(p, &extra) != len*2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *pem_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	int len;
	static struct custom_salt *cur_salt;
	int cid;

	cur_salt = mem_calloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // type
	p = strtokm(NULL, "$");
	cid = cur_salt->cid = atoi(p);
	p = strtokm(NULL, "$");   // salt

	for (i = 0; i < SALTLEN; i++)
		cur_salt->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cur_salt->iterations = atoi(p);
	p = strtokm(NULL, "$");
	if (cur_salt->cid == 1)
		len = 8;
	else
		len = 16;
	for (i = 0; i < len; i++)
		cur_salt->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cur_salt->ciphertext_length = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cur_salt->ciphertext_length; i++)
		cur_salt->ciphertext[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	if (cid == 1 || cid == 3)
		cur_salt->key_length = 24;
	else if (cid == 2)
		cur_salt->key_length = 16;
	else if (cid == 4)
		cur_salt->key_length = 32;

	MEM_FREE(keeptr);
	return (void *)cur_salt;
}

/* The decrypted data should have a structure which is similar to,
 *
 * SEQUENCE(3 elem)
 *    INTEGER0
 *    SEQUENCE(2 elem)
 *      OBJECT IDENTIFIER1.2.840.113549.1.1.1
 *      NULL
 *    OCTET STRING(1 elem)
 *      SEQUENCE(9 elem)
 *      INTEGER0
 *      INTEGER(1024 bit) 163583298361518096026606050608205849417059808304583036000248988384009…
 *      INTEGER65537
 *      INTEGER(1024 bit) 117735944587247616941254265546766890629007951201899342739151083099399…
 *      INTEGER(512 bit) 1326824977515584662273167545044211564211924552512566340747744113458170…
 *      INTEGER(512 bit) 1232892816562888937701591901363879998543675433056414341240275826895052…
 *      INTEGER(512 bit) 1232481257247299197174170630936058522583110776863565636597653514732029…
 *      INTEGER(511 bit) 6306589984658176106246573218383922527912198486012975018041565347945398…
 *      INTEGER(512 bit) 1228874097888952320
 */
int pem_decrypt(unsigned char *key, unsigned char *iv, unsigned char *data, struct custom_salt *cur_salt)
{
	unsigned char out[CTLEN];
	DES_cblock key1, key2, key3;
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;
	int length = cur_salt->ciphertext_length;
	int block_size = 16;  // AES
	AES_KEY akey;
	unsigned char aiv[16];

	memset(out, 0, sizeof(out));
	if (cur_salt->cid == 1) {  // 3DES
		block_size = 8;
		memcpy(key1, key, 8);
		memcpy(key2, key + 8, 8);
		memcpy(key3, key + 16, 8);
		DES_set_key_unchecked((DES_cblock *) key1, &ks1);
		DES_set_key_unchecked((DES_cblock *) key2, &ks2);
		DES_set_key_unchecked((DES_cblock *) key3, &ks3);
		memcpy(ivec, iv, 8);
		DES_ede3_cbc_encrypt(data, out, cur_salt->ciphertext_length, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);
	} else if (cur_salt->cid == 2) {  // AES-128
		AES_set_decrypt_key(key, 128, &akey);
		memcpy(aiv, iv, 16);
		AES_cbc_encrypt(data, out, cur_salt->ciphertext_length, &akey, aiv, AES_DECRYPT);
	} else if (cur_salt->cid == 3) {  // AES-192
		AES_set_decrypt_key(key, 192, &akey);
		memcpy(aiv, iv, 16);
		AES_cbc_encrypt(data, out, cur_salt->ciphertext_length, &akey, aiv, AES_DECRYPT);
	} else if (cur_salt->cid == 4) {  // AES-256
		AES_set_decrypt_key(key, 256, &akey);
		memcpy(aiv, iv, 16);
		AES_cbc_encrypt(data, out, cur_salt->ciphertext_length, &akey, aiv, AES_DECRYPT);
	}

	// padding byte can be 4 / 6 or so on!
	if (check_pkcs_pad(out, cur_salt->ciphertext_length, block_size) < 0)
		return -1;

	/* check message structure, http://lapo.it/asn1js/ is the best tool for learning this stuff */

	// SEQUENCE
	if (asn1_get_next(out, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_SEQUENCE) {
		goto bad;
	}
	pos = hdr.payload;
	end = pos + hdr.length;

	// version Version (Version ::= INTEGER)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		goto bad;
	}
	if (*(pos + 2) != 0) // *(pos + 1) == header length
		goto bad;
	if (hdr.length != 1)
		goto bad;
	pos = hdr.payload + hdr.length;
	if (hdr.payload[0] != 0)
		goto bad;

	// SEQUENCE
	if (asn1_get_next(pos, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_SEQUENCE) {
		goto bad;
	}
	pos = hdr.payload; /* go inside this sequence */

	// OBJECT IDENTIFIER (with value 1.2.840.113549.1.1.1, 1.2.840.10040.4.1 for DSA)
	if (asn1_get_next(pos, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_OID) {
		goto bad;
	}
	if ((memcmp(hdr.payload, "\x2a\x86\x48\x86", 4) != 0) && (memcmp(hdr.payload, "\x2a\x86\x48\xce", 4) != 0))
		goto bad;

	return 0;
bad:
	return -1;
}

unsigned int pem_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return cs->iterations * (cs->key_length > 20 ? 2 : 1);
}

unsigned int pem_cipher(void *salt)
{
	struct custom_salt *cs = salt;

	return cs->cid;
}

#endif /* HAVE_LIBCRYPTO */

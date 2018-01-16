/*
 * Fast cracker for SSH RSA / DSA key files. Hacked together during October
 * of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * Support for cracking new openssh key format (bcrypt pbkdf) was added by
 * m3g9tr0n (Spiros Fraganastasis) and Dhiru Kholia in September of 2014. This
 * is dedicated to Raquel :-)
 *
 * Ideas borrowed from SSH2 protocol library, http://pypi.python.org/pypi/ssh
 * Copyright (C) 2011  Jeff Forcier <jeff@bitprophet.org>
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sshng;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sshng);
#else

#include <string.h>
#include <stdint.h>
#include <openssl/des.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "aes.h"
#include "jumbo.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "md5.h"
#include "bcrypt_pbkdf.h"
#include "asn1.h"
#include "memdbg.h"

#define FORMAT_LABEL        "SSH-ng"
#define FORMAT_NAME         ""
#define FORMAT_TAG          "$sshng$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME      "RSA/DSA/EC/OPENSSH (SSH private keys) 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1001
#define PLAINTEXT_LENGTH    32 // XXX
#define BINARY_SIZE         0
#define SALT_SIZE           sizeof(struct custom_salt)
#define BINARY_ALIGN        1
#define SALT_ALIGN          sizeof(int)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  8

/*
 * For cost 1 using core i7, MKPC=8 and OMP_SCALE 128 works fine but that
 * is far too slow for cost 2, which needs them at 1/1. Let's always auto-tune.
 */
#ifndef OMP_SCALE
#define OMP_SCALE           0
#endif

// openssl asn1parse -in test_dsa.key; openssl asn1parse -in test_rsa.key
#define SAFETY_FACTOR       16  // enough to verify the initial ASN.1 structure (SEQUENCE, INTEGER, Big INTEGER) of RSA, and DSA keys?
#define N                   8192

static struct fmt_tests sshng_tests[] = {
	{"$sshng$1$16$570F498F6FF732775EE38648130F600D$1200$1777f12047d4ebab06d052d52946e5e0e73b41d5077b20e1ffe1c97ef9459b8c6844fecc24fdf63314c8889398fa140026339c85336278600e299c0f4c236648ca684f0c122e66d3e860e19eab8b46a564eb101def1c6a38f2f1800040c6b59a66e7b86e145e180f8a126e46544be1e17dd32e4e72f735c9e6b0ca4bbbb32ccf34ba0a7827858b0be32f9e53f13466e2ac78c3fecdf2a51cd7871286a3a91f9c71ae9e857a74bcc06071af6f60d827f7e13ccf6c1be722246c0796f509744c2b1b1452315ea6f86a1c8765d1f0c1d795349b4ea1ba229318b392fe505292cd0c6b4e3e9b2acc13b96943d92fa5635e05b7795989906274b0fb1894102d07facdd8f2122299960e1490823d62bbd5bf6d6c92ed26e68cc2edc93fbffec557a5d187fffe085ded9408ac63293851a684ca10d6e9a4ee9b5c552c827caee1f1c41870fe2d0e79bc4a0b85478fa82a58f947d345122c8ac7c80ba2ae8452b093dda70e2a4329fce70af9cf98e19477a622083664d1e62393a01b20371fc5be9390059f1c4af75d5448a2fbe1aaa46701c696afec927c67d15c046036531d9252faa08bbf9ea0e019ea574e6af94edd7ec17c83c0f87e34c7456e19bc53b2de04dafa83267694c1f61d038e0fc5f8f1b8ce573da470e6db6d38c0e8f7141ad9e9609ea408e3823271e987766039d484bc88f23f2f2a1175636ece950c7d82f43726287fef37da945ec6ad6adc04cb59f66087f68a3e84e8cc39c578bcbce3aaf67f1325d3d20dbd5872cc88ab72fc0bda05bf969eca08f8cafb306424a1597ba5d612e155b4723c2c1bee9a8e3d195be3b798ea417008a2340a919e23ac899ea4dbc4ef05af2cf6b12293eeb293584b37d3f8465e36a62d65b21f68725603e11dc14acf4e3855e25980387a34a34919fdd49844ed888e37199bb26df1bbbc303e895615fcbb0aa9ddc8a2aa685da942a1e68dc3a355d27236f74220d404d25e0ac64ae9203bb04296b4d67481a4f516fd22e47092073c9c44fa098670d736c5c509e55d6b40d3bf346ea5bb0007e32e9d8290c2633621fd84c2f5f428a5649ff3a16d00fec21381543202f2ee12078ddea8a371935f2ffa15aafa644e111a29c1c4703bf8e9cf1397356e296c5484558b96639b9cf3703aabff0cf42864dab91b1e09c6439159bc95374da7a5d416402286390e76cb766cd94e7a002596e8862b8d7e46c1fc6f7bdd0b93c73d2dc3cf58ea31bc549086209f450bb7460d5e9ba0d0f7b80337651f45bf83bef1783c3a15631c82428bfe167dc0692402d7f15144fff01ad8596970439ce8a2df0107c85a23ef93edd19f62de499ab58ada581886494c3e52dd5ec53c191f6d62729729a252c2c0d8024950d1637cfd7c61a4fe64ce41cde76fe00fa2607af66a44d3b4b8836820f40c03669f08b4e986f4d03c09e3c026a910f83be623d7f68ff80d81662f020f433f7a896e10134a278cd9a8517d3bcd77c5287f7d41bc52d2f8db79b5f8f9ed6d6f45a482b13cb91ecdef43ebe38f5ad71836185ae6faf1dd11c50cc1759e4834fcab2b3523d4224a32d2eaba224a2c950dac7524afc74f02f17b511f3b22d577a6928d40909bed64f6ed27096dff591a8fbee3f32733fd2b36c0c4708a5224f165af000d93832e211ae52465f680e7a4fd66bb5eb210c4402eb58f6ebfde", "strongpassword"},
	{"$sshng$0$8$DAA422E8A5A8EFB7$608$fa7b2c1c699697dd487261a213a0dd088a86bc03f4e2db8b87ad302e3581bdd8ed17d0a3ced3e7179ef17beea9064ee862017f472de293d655f6b1cd7115e27c328cf5caf1b5896952590cd82d123fcf6c5da3b43f5435c829ebb595300c828e04d57c7ade57efe006305b32fe79afd0d14cadba681b4dc3a69b25a1e71ddbd353465217c311d11721f1cba05d1226ff0e7d261156f0837753bcaaddfec383591f61470a4318cf679046d43490a1eef33014a90865917ccaa16f986724b8ee421d990327a46410362b4992406af41a88e3c5e5bbb7707ba08517e7ac8295ad0b934c38968f05fd372f1ee29e24eddcbbacba5b3e1b7150e51ba4e17b4f54319630e2d5372adc46e4de437f64b3d11670eb25fc94c7e9bd0579806bbf16c6cfe529a4bc0d3918ca4777f8418e789163660d9bbe0aa297857ee4922dffe310e6967fba2ee2e06707d9bbd9c8601bad7ccfdcb8a948074de511be7d588b7b71d4b5f0b1e19020b54efc4d626b2e4d85c0a40682517128b9ecc29f882996f4f6b655bb1986e293cb5271fe98c61d8b2e6e8338fee42f22674fc8b2da475663ba19644e7de76927cd9e333b533ad7617cc7a9f19dc7c00c240ed92c2fb1aaf6495bd16ab9fae4650567ad8b175d02f9e6a9737362168035670017fd9ad87cf4e916f47baa5efe0d04939295fba608f83fa811b946d12afe77836dc6d0d398824a355926ce5848dace776c7a7ab7109be495894bc98a2cf04107368d5d8777a1d0ef19782ebb1527b564ac0f5d4ac91e81f435cc21f5905b9753ee1a79913306957589943da161a6f5dc3082b80930553769ce11d82d9cb12d8a12bb4e56eb3f1200eb", "television"},
	{"$sshng$1$16$A0B8FCAB2B655BA3D04B2020B89A142E$1200$a4dbb4c526a6bea3aeca26e6d89f0c19ebdfb9154ce4cdb4bbfc3420ffce58dd6ae1077dba9753a001b22b07e4248bb2d4a3c4bf2cbae43f8c29f55c3c36c656aa7262fd2f429a8f7fbc443c175687b20c78ed3e409a03fb7b0afa22ef2fad63d580ce00e31948171787a8861e34d4c966d0c54d299585df757a76a278c28e899b7b16fe74d38ad9f6220a2ebbd2b427a3f29436feb2e000a3f1b26a3906eb84314a8f8dc211aeab0e5d5c776b54a59c3630a96de506fdfcf7a6991bae4e90ef2f6f99d5a92c78eddc1f7bd75a94bc472c32ef82b56261889a60fbaeee0b145c4aa785bff8b854b8c61fde3f018e10e9b4de6fbf5aa7ff30d985a8b8da1e55459855cd96076d0de5ff31a593ca7ff4badb07886808c624ceaf955569138c57fd9006877d8a174bce3347b72490d5181d83a20500dc49e8160d075659b568820ac2788a50aba0488a598c6d90821026c9a6213f279b8773eb3c5b60a73e48199ed7cba66595e7f219c4d0f5e231219619ffbd3d7bd1dad4ada8bf8d9ddbd5319ff47922e6858946778daf0e6b47973db77f56dcc356691ccc652ccd53d9f9895c896d99cf0c498e5a8d712f2e8a159a80e8a3e68b812650f0ddb0e1300438b914f4c28d232c443768bccaeb204212494782003343a5cf6d455b95efc94c8d95544db32c0539d0e1fc0288b5ecfcbc4bb7b6278a54093a56ec0ad5928c113aa96a114d7fd3aec173759f5c081f1d0a2f0922433ff17911901c0f0f940b1f345d161d91ecd4456e9b8458a14e0fcbaf2b750201c10cff3c8f387004b99be515f45c00200efea4e36d83524a760c20518d902e38d6121bef29b479edbf44be4c51730c3bbc86dd6abc40b67470e12b8235cb1317b6dae34d99248f3a8f98a77d848360c01a645f76c3abc3f66af0d1f0f7bbb77930b3f85430062fb1a82c5aff1350bdba049a8bc7bcc33e61fd3e8484b9e6d51ea121337b7553284cd1222a2469e1c7158f13ff63307530243af25b4b36d19ba0604212ebcb42b450c475e238c2b9f021088b16aacfb6e564eef86860fd077f90de471fc26621360609e526444e7556bb8d6de703271a4ba8dec254305cd1163f90a32d8966f599903de0e4b62e3a8db15753fb099d164d9bd44c05f163fd96ef73382c779214c8ec93498f2f5fa31a74ad6ac3136a37c6f6c27b1dd7b93c1e292f2ef0d569581f45cb0747ee5a2fcba5781cdc96b9b2f07bdbaf7ff4e0432873072112fd17792c91548393cd58a7eb8b126f17ee107f9670567c0ab6e6b9a2997054d968feb29f479fb8b7888138971a14228bad1854d9804f1bea77014b7f0d1037444178d66d2db19b660cf5e84726b2f730662a1df93abc54ae521d3d1691fb4fa48b087ead9dfccf4e6367d9a25f48a019a6affbec84c20ae7b10c2a169cfa07a4d26c5035c02d3b7d01681bf56bf568ab1f740c86ee6f43b8b440eea1f1139a89fa5bc653164426856e3a5e22ff5fed05ba7a054f6d4609eb142ef113a24f05b92ba72c40cd9bde09d8125d462fd30bab15cb47130fa30730b26c0d399d14b9cb42ec56df024bb9bbcd18ab4d279ccf82b2c1fee8fdbade8bd506791a6fd51349b24cdc36ec4d88e6dd43a85b92a71458908271d298681f54aa567262fc70260cc15d7f5559abd7e7ee4d2c7c727bf5036c469b690ece969480240c", "Olympics"},
	{"$sshng$1$16$ABF86CF7849BBC5C661A69F1F7B4C87A$1200$4941cb1e3d19fd7173e7b97faf6484d803fe6737628241e7e848b4d02ef63c91a99aba940c116157f96e7c8e91550df51df80324a5630244ae83fcc04304ca9f7a4d9621cab45a6d513afc06b2364c222a7907729e3562f676fb94d7a3cfb2551de2766e9d67c035fecde455fd741a67521d0f71673d7c364ac314850314b31b6899198544c0f2ab788ebd435cd291ae8c12576837f784ab7cd8a9bc24bea3823034154df1b3d9b6a064131a9eb81b3fd298f128458cfce450305602e087ea9957e29117942ee7a2fd8a980da55c364f781feeb1bf355ee0de54ce946d85930f786d6f6175254d5a4370ddc5c88ef13e23429b0d9d01f413f08ce5253141d84c8368308890c69b65be93a415923f98bc898f9cb4abafcbcddf2785f698e091d75eea0a90216ca47d0459cb2b8d95a8989f604a0c7bc8dc690791c0c73e6f7a2628ea7ebd8e1a39ae583c91668dca7806f226ab361f07bfd35f7130aefc83071b865cc004f963ef80a750008e920f1854321949d6143ffc33b60b58015d5f32c820006b0a91aa08755fd859c845d3a75d89350d9c12e7df32b9bcd188681b0981ac4713505c4b516ee4d1073ea715b68d0c10ce3f562f0b5b5383a6bd53008ec0e8927d78d8fd21d760e67da700db638f3835cfd523046ee0f2fffed05c3bd902b66765629f428bc2808e300fbe2064af9ab125ac4195f3b5756e09059cc391127c8efba8e50eaeb7e0a4d98561ce9540fa6b9b6333beb1efed5751e7acc1aaf4f0ff975e548a21b08a2ab49d4e6bf2336e60eb8684debe5d611769cee17c38e02d2057284d7948fdbe459092a0e4471107f55562aceb1045f0f1cefb3d89e549422f27618137c48dce1f149f6c8748d4a1eff89eed9140ec598def8d38457a239ee167af6d60ae995261d9cb47ce2d4d25b1520f8b75408b45265cf14d3892dcb53732fa4151312f4f6c8d46a54d07c23b4b253003489a28d544fa903eb0a72a3ae914dafed5218ce8d745b23bde33c9e346db79051e763866fba38f123b32c110b4168c3baf2ace735d0fcf5ccf7c2a29d67d4831c0cf3472ab8b197ed953056c42d7cc91646ca12a7bebb23fa4fb063217b7b7c9fec7688788798424acc32b3c704a91bee6a63ca5a2186df80e225f96679568c936c9a47b5615858211c72441a9ff4dc265ba98f346984bf92969af9bd035f93a47ddf8beef9ba84eacc1f76ee4bd1eb242dc9fb2949d287f685369d1122865926270f8bc83d7118801e77e48fd2dd4b996231564d1649c4636b734e483067c1181d1edc6dd424f517cd3ea3fe1ab904cda78b7b7d6c856a82c7e1c6ba3e9fb93da1dfeaf4e3eff86b4541ab38f526f509b915f787d6abd4a4c7174dfcb18f36ba72fa69b61a060b2785b3d3e8d28e9f6aa1a32aca3948ee48188a7ee24b160f3a6bc98297bd852d0759080cecd85dbc91bf4404705948c6a169e140a2479cdf5b840c3d6f99ea4e09b76730b4d33300f6a963c90cb0e07833a4bf314d72d81ae8ed5cf5ca4bcb6f35acb0c7d8298b70a5b61f87b13c3b1d02b56fe42c5465ad57dd4041b9b36943188acb8742052669b95fd98f3d18351f8748e9eb0f47d11a4d6ca2ec0348ef7d24e9f80c1dc239b513ed7867f25903875a1e9a983c5c8475b8de1f7f70423f1f472fca1e99a52b14105c4a47edb657eb87d0353", "extuitive"},
	{"$sshng$1$16$925FA0A2EF7283A2F69C6CE69121D43C$1200$0498402851fd405114a860a1fdc760752bc8b7f44c77b2ef6a6d46ed3cee48d963bf34b905124c18823bc69819bbec29edebf4e697afffec2c35e79b993ff28b92d0355758b9c4ea00fb1f4bd48732059643ca2144b9c35de734d8db395076cb7c0468f6cfbabb1646345f907af82bf1598733d7aaa5496c55e662075d6bdb47cb941160fd1106570303d009bdc89fa3ecc07c84c3f91238a51db8ecc09f8e6b6c1395ce57970cbf2a3ef1341ddcb404e95832f0535a30b17048554b3341502619c48685db4706855ce62a86b3953f1219d4dae10243265d01264fa6408006188a40683e5de4952cb6796cd2593e9365065f51ff21b23b8bc075445226092b988114962ed5f4b97128cc69eca7a3d1169d2d83a632a5cc51290527bc848c7dd3d76554b28bb2bea0626f4fd27f3b9610e827e8211c60879d77ea1593d80908618b55081048bc2baef6848c410372b9a69358feb95c23d747f81b59577c601d55337b7c737d77bd742a115681a778c3d8e513a3ccd25cf833a32c73bf04476131b2bb498fac9496597163766b5f466b2478a564736c245cf0a0bf4b33be13eb2360dacbf8573b342f336d0341229654cd140674b18e35c04f917a9668306b4c93285825bdc8494c209d103212ea1deac7839db28acfb50fabc5c2b5057333ecbcb685adef5e962a526a02fd44f40a5af9c27d4211af129ad47b5fbc1d5f9f01e5ad1c53f728ead66a45cb8e6a9c1237aeb02374225ef2b63bc3ea6b2b1ab6136f90236ed5de5f88c6edde8ea75db8cf9aed8030537731dfe3ee855ab501f0235aeb05c8b2e3f4668ca0ab230cc8764863bf3ea71bbce2763556a14cdc5e09b0fa8e9ce6948d377b087fe04d1a5ae2ca61350514376cf447119fad0ea158b16b86be8f43742fb9934d3c1e8cc46497c191d1703a85e0b8b102b27595471687c5d1335a2290214fd46d9568d4b2845b88f116d5c2b3e3766030beb3d71157ff0c4fabd13aa173795db5b88d059ec79bf50c22f3119411b4279d1c7c0e88a7b01fa47e52553913b0ceee272500fedfa28483a849c186ce31b2134945dcaa84c13f7e474d59b0a0f5f768a8ec4cd58c8499b3ba3e1880fa7764ea9e424b29e5f6ea93671bce2985ea0d51efc2774f023c65e99be3db57c4a83e3c2f59fee62f60fa8c7eb66ff870f05cffd7ea208520a0640fe86f619944b389cfe695567ebc82829407273ac67130d3b09c8ff172a77a8ef56b18aac65d5607ef9f6ee791c0ec5b6447bd847b5d6a5411142a110700d5bb04424111ddfee27139ebad931da60de1e8bfc87f2b53b8720435d3dbb358445fc3493ada42192783741f72b5934d6a399e1ea16291fad9f38e49f23e3ad7303d4d1e5677b9a81aff8dfca7abb33455e4e7858a9de656e4239c22ac2e91b558bcc25b356be583487ffc24459873febd2becae6056544d56fe670342347048a8abca019d2203794fd8652d31899f094d67aa304d1e607460efbdf05b3b407de54fc9e33d1879fe577091036b77e43e382f1acbbc12cb3bc83f25a4791265741e018b4825beb0a6901db19ee58a3c378df4ffeb4c9def7e730a08546d3f698f5ca4f98c81deb2982729ab95167ecaa1d6320b12d48f4de2fc9891b8e117c88a6f5bff046b1ea8cab4b0af8a488dfa6353ccaa3125e959322bd0ad4662ad15cffb86f3", "C0Ld.FUS10N"},
	/* DSA test vectors */
	{"$sshng$0$8$78DAEB836ED0A646$448$95d5a4abd38c957a969a322aa6936798d3c8523e6e553d762e4068b130294db89b4e67b790825bd6e0de1b60528557d8faf0ce4d413d92818f0cbb315b5b7902df845722032bc6883b4b87b5e5cce406c15f6d0b2d45916d156a661b0cc6a421dc7dd794788df9085a59c6f87c5baed7c6bc4a48a64c5a439d9b9f7e808397fce1fc1ed789e0114cb03cd392bf660541041c1f964476044d39dd71eb240231f4111494b3fbe85a35f2bbe32d93927aedecf959e786a51be450ade61e746b8eae6174016e8dabf59a358a518c3445c93b4824e61c065664f24b3e773643c0e47996b7c348cefe63407303cbb37e672905bb0a4fd51e4cfd920563863987f96f9fa2098d0ed5c9244f21ba4df28d9826fd8e0f525af349f7b54f0c83bee8de8e1d3702a6edc0a396af85b8805d3ac4a0b01f053d0454856fa3a450f199637ae0333670483a454769b5bcbb5a6329d07c0ad6ac847f11e32ccb835650fb9404880c1ad19548cfb57107d43cc8610b9869165a8b116867b118f97ef74f09ab285114512f599d066d46dae846a1b04787f3e30410b234e5fc098e8a39419a2dbdb5a25c709b13fd31eb2d0e6994e11df0e32ff45b1a3c95c153ce606912a8dc966daf", "television"},
#ifdef DEBUG
	/* this key is SUPER slow. */
	/* it would be nice to get one of these with rounds set to 2,     */
	/* instead of the rounds=64 of this hash  (pass_gen.pl update)    */
	/* new ssh key format */
	{"$sshng$2$16$cc2c3c68c39e0ba6289ed36cb92c3a73$1334$6f70656e7373682d6b65792d7631000000000a6165733235362d636263000000066263727970740000001800000010cc2c3c68c39e0ba6289ed36cb92c3a73000000400000000100000117000000077373682d727361000000030100010000010100af9bf6a900464f154916fac3d80476e0ee739ff7f25a96b562ff9f4262db1972992947dfa89da47f9fa5f4d9e54a2d103ce63779746888c298693663310f054af1c1dc90f62b22f630703726631c03ff217c29a32fd9f9bc178aabe9666c37c2c2bf4a2b4c528efe51e755053216d41e860ef996b549184cd15bd17641128690d2946a76261954edfee942bbefbb182df320d3da7f46a5fcddc15b5ecbf9b1b822cbc9ef978e8b639e8eab2e3b1229d429da4f6bdc27af2f2aab0e187a6cce91b95a8ac6f5602773d0014f1e8124a89e43e502bebb4d21f6a148e208e2d591391d1aede6a0a6d499a3de9996474310dd9d3233e3f05e9d0e85aba44715e838bd000003d08168da8d056f904faf9d80b22c08141e8b068a3af64ace3b5ffbad24b884cd37ae7ad89546031ab834d612b44266b95263a5c38f0d628d704caf70944629ad66d3cef974ec4faaaeb7d7df67f1321bb606ec6e14060c0de1a63a5732ca89b94ae765cb0671a4a1a76b42c06c220546bbf0f8a88471c0bf4200a0cbe0d346be67f688dcf76a3666f7c4447b3ced2d0c9a2fa50abc6ca222ddd70aeb82d65f8fefa313b3db76c5a03478bebc9e0942e17c07ae11d1fbe1b0b380ca2506a26aaf5cdb8668af186d1bc293844bd9c2cc8bb40530387f9a5e11770484593af69384fc003beb82beffa00c1b23f7d6a9bd8f6153cb7abd9531008df384a3455d7cdd7020df4dc507f34e697ad437f01989271b17b93045265f20e6fd02f63ac1e13ec85f8224bc60dd91e15dcfa2ec4f6986e3b37ea6bd571ca18089402f80c121323eb774708cc6ab470e05a53428b65dede47ded97c4f5941be44f6290d5ccdd9bea95b06190efee6c64d874798b6045c5d553a1f68c95f143d0a6893877796fff452851d64ac73c007b91dd6058a5c31165003d9d66b4a1a40c2f82e5c3be6820b109addc0f088c84576e30c7202da3304636de4035f3ca8b032885aa2bedb4d1e134c1615139fb6ed7fa924c2e8abdfcd75da029e910ee8a9d4af594e2a9732115237b6ba3c24f8dfd4bed0a7cb4d96e114bff30e9c68226ae04de6fee2340b41c49cd08982a3f21169853366882a4af43e256cb0d09c88856c46f2ad8a7bcc3896efe5f4f104ef9b595cd08b4b76d6ac074f4fa4a488f508c6106603cb4ca65af819d2222a086ddd16a63021627f337ab9d86b33150808313bfe7368737bf38e7dee410cf08f2effef780d161e2cb734135bba36fe2ee3319cda95242b89b50673c88eb3dfa331e987e3fbde92cec7e019990d97b11c71d5b04b8ec451549abc9ed195a080aefb1d77eff476f9de4315fca5bf6386438869a8d59a5f0badda70b337bb9bdcff966229d631286d3c5b97c41f3ef5daa6ef4416577815214733e8602ef7f8abc3a19ee58f48b10c8ab1d5c76f01febdb29b36910d615d4022849ec117f02b6ae898cc0ff67e61df43284d3ff739ab4c34fe2854797ae0b66e0ba234e236daba6eb9172e9e1f4a0f5283ae9b336059d2ab2c7145e0a4de4b5bed3baf87c90ad4d47b94eb1c01b07510191f06b9eaf014e225b2bce46d5a7080c6d1daf64460836d7630c157e44afc9483a777d76fcafbfc2c4f299211c0465f0151f13707f815700944ad6a17e23e63dd0eecb5cdb5284ad92dd853e0ce136bc77633fef514e6aadeb61e7fe885fe399076cbd5464a6d17efa1e116853e80cf08adea7e550b0d27e6a96d835069674fd7bcc$64$358", "12345"},
#endif
	// EC private key
	{"$sshng$3$16$00B535FBA963402F20C12648A59D7258$128$dfa09369ff38f33c9789d33760d16fdd47730311b41b51a0c7b1dd1dec850c5c2ff523710af12839f25a709f0076cdd3e3643fab2ea1d17c6fae52a797b55e752b71a1fdd46d5bd889b51ddc2a01922340e5be914a67dabf666aff1c88275bd8ec3529e26386279adeb480446ab869dc27c160bd8fe469d5f993b90aaffef8ce", "password123"},
	// RSA key encrypted with 3DES, this caught the incorrect padding check bug
	{"$sshng$0$8$F1621D1A561534C3$616$ab1925ec002675445db989f2591a5bf7a31a80e10131b6eebb20bc2d2b70e2a21f431bfc70228f3873b4e0bb902156a1cf829d50fa09bc035d5ddf04f2a403f4fd7bfe32b5219d6c74dd594d0babd07e28075be4eef6f015d1ce5be91fcd81a55f886d867995d4719bd8e0890e8fe4c8abc171d272442e1c6805b29e1cb996a2b2cd3e82e70df0270d98d88c8cd32a1164ebe6e1390e64ce15cc166054281619a125bf4776c7433cf653a87d40d3ae6b494d536c2d2974e697d34b8965239d976e9e1d8a3f1503c7bb6ebacd8f852f65b96e58e5a280411ea7737ba1410ec273722b1b3b91c83eba4c3a0c187be3bdb05d3fe9be55cfbde501adc8ff6ff257ecbd4efceb8d8e7a859af411565b3f3fb0fc3d9df056a265836ec18b234f7b6956a4202ae75e5ed2890d33e9abb355763cc56438509a199c4fe3e48e12fa3f6cc2e55f8f3b134ba2dec87b4d37d6209bbf84826d74cac0d96cf4303654c36476edc38f750d4d7d0a495aac5f6ec8ffc6fcceb482985b81636fb66f05502d00c00e5e8b39a17afe46faf18ac590cb4fd59cf88b62209378c47be74b902956b555bdeaba14f447a8b0e4522ea6d0f492045f3b14a49c3d7d9f6cd3f8782cb1fce3bacd57e71e918726a514a39a474661c6989796a9fab1d8f6cc684b4963ced9982a01ee50e076937dfccc4a1d00870b238f30fc4fa258dd6a62d3c7a79bb9f23b0be25261bf222681859058fc56660d59124d114d7528e98b8c2eb8d465514894a6796b07f244bb8334bb4a440245d5a942a05fd401634cbc6f32ee223b4ec49446fd0fc2b30ed05324837ba8a2415c23bc4fc526ee15766c6a29047ba5bb05f38a122160ed91c769ae", "albert"},
	// /ssh-keygen -o -N test12345 -t ecdsa -f test
	{"$sshng$2$16$6931efeeafd9d3fefc5d3f220d6e32f3$375$6f70656e7373682d6b65792d7631000000000a6165733235362d6362630000000662637279707400000018000000106931efeeafd9d3fefc5d3f220d6e32f30000001000000001000000680000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041043da6ae45fd7e65967e3434e5af68d1f92c08b2dbc837ba50f14f58c3fe9f715062f61d3485d0426dec2b021b69f4a8272bdeaf90d9be5b3bd101f2381e9a1758000000c0d876c4b88fc4b76a43b95813d68e37000e6bea260da8cde01144a8ea052e66e5e42bb488b1c39822541147bc21a16cc6be613fa76d6e524073a68e94d944723abb34cec635dc4e3ffa0411695452467c294b95c78f34466c2154bb97f54d5712b7cc08d2902a0f874543eb6660c4c4adccbf1528cfb5348451d93a70d8318a3716819a624299aa5e9c21ec6526377c7bbc3f30173dd9a9b3bc0ef0193a9a21210db076c93c228fd23eaa83796d4f6a4848760db010054f1b9aed7445061a3512$16$183", "test12345"},
	// /ssh-keygen -o -N test12345 -t ed25519 -f test
	{"$sshng$2$16$a439509f8aefc40a17a504ac81c46601$290$6f70656e7373682d6b65792d7631000000000a6165733235362d636263000000066263727970740000001800000010a439509f8aefc40a17a504ac81c466010000001000000001000000330000000b7373682d65643235353139000000200b31c6439dc6b42c9de146c70c752e33877baa7a5875c37ce092e5689dadadee000000a013bbe4b8cd8e0880a7c5dba953fdc5b0e4380b1904c631cb10c9f19ddadd52341160120f459ea1325681bc8f5c40f45a5ef055bc79ea9a05bc94bf668e2808ea6cf88a5ff3f418c4b13664c02456086671776969ce9cb21699818d16b4deae2dd30f03f0f85fc8dd54901a7ad884c35a2b28bd08b418d15ee7d8ec0332649eeff4fab6299eca59f096c2b56f753de0dcc226c0d8404bf44a73a608de2589545c$16$130", "test12345"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned char salt[16];
	unsigned char ct[N];
	int cipher;
	int ctl;
	int sl;
	int rounds;
	int ciphertext_begin_offset;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	cracked   = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char buf[sizeof(struct custom_salt)+100];

	if (strstr(ciphertext, "$SOURCE_HASH$"))
		return ciphertext;

	strnzcpy(buf, ciphertext, sizeof(buf));
	strlwr(buf);
	return buf;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, cipher, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* cipher */
		goto err;
	if (!isdec(p))
		goto err;
	cipher = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt len */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > 16)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (hexlen(p, &extra) != len * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* ciphertext length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)	/* ciphertext */
		goto err;
	if (hexlen(p, &extra) / 2 != len || extra)
		goto err;
	if (cipher == 2) {
		if ((p = strtokm(NULL, "$")) == NULL)	/* rounds */
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)	/* ciphertext_begin_offset */
			goto err;
		if (!isdec(p))
			goto err;
		if (atoi(p) + 16 > len)
		       goto err;
	}

	if (cipher != 0 && cipher != 1 && cipher != 2 && cipher != 3) {
		fprintf(stderr, "[ssh-ng] cipher value of %d is not supported!\n", cipher);
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
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(struct custom_salt));
	cs.rounds = 1;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$sshng$" */
	p = strtokm(ctcopy, "$");
	cs.cipher = atoi(p);
	p = strtokm(NULL, "$");
	cs.sl = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.sl; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.ctl = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.ctl; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	if (cs.cipher == 2) {
		p = strtokm(NULL, "$");
		cs.rounds = atoi(p);
		p = strtokm(NULL, "$");
		cs.ciphertext_begin_offset = atoi(p);
	}
	MEM_FREE(keeptr);

	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#if 0
static void generate_key_bytes(int nbytes, unsigned char *password, unsigned char *key)
{
	unsigned char digest[16] = {0};
	int keyidx = 0;
	int digest_inited = 0;
	int size = 0;
	int i = 0;

	while (nbytes > 0) {
		MD5_CTX ctx;
		MD5_Init(&ctx);
		if (digest_inited) {
			MD5_Update(&ctx, digest, 16);
		}
		MD5_Update(&ctx, password, strlen((const char*)password));
		/* use first 8 bytes of salt */
		MD5_Update(&ctx, cur_salt->salt, 8);
		MD5_Final(digest, &ctx);
		digest_inited = 1;
		if (nbytes > 16)
			size = 16;
		else
			size = nbytes;
		/* copy part of digest to keydata */
		for (i = 0; i < size; i++)
			key[keyidx++] = digest[i];
		nbytes -= size;
	}
}
#endif

inline static void generate16key_bytes(unsigned char *password,
                                       unsigned char *key)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, password, strlen((const char*)password));

	/* use first 8 bytes of salt */
	MD5_Update(&ctx, cur_salt->salt, 8);

	/* digest is keydata */
	MD5_Final(key, &ctx);
}

inline static void generate24key_bytes(unsigned char *password,
                                       unsigned char *key)
{
	unsigned char digest[16];
	int len = strlen((const char*)password);
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, password, len);

	/* use first 8 bytes of salt */
	MD5_Update(&ctx, cur_salt->salt, 8);

	/* digest is keydata */
	MD5_Final(key, &ctx);

	MD5_Init(&ctx);
	MD5_Update(&ctx, key, 16);
	MD5_Update(&ctx, password, len);

	/* use first 8 bytes of salt */
	MD5_Update(&ctx, cur_salt->salt, 8);
	MD5_Final(digest, &ctx);

	/* 8 more bytes of keydata */
	memcpy(&key[16], digest, 8);
}

inline static int check_padding_and_structure_EC(unsigned char *out, int length, int strict_mode)
{
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;

	// First check padding
	if (check_pkcs_pad(out, length, 16) < 0)
		return -1;

	/* check BER decoding, EC private key file contains:
	 *
	 * SEQUENCE, INTEGER (length 1), OCTET STRING, cont, OBJECT, cont, BIT STRING
	 *
	 * $ ssh-keygen -t ecdsa -f unencrypted_ecdsa_sample.key  # don't use a password for testing
	 * $ openssl asn1parse -in unencrypted_ecdsa_sample.key  # see the underlying structure
	*/

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
	pos = hdr.payload + hdr.length;
	if (hdr.length != 1)
		goto bad;

	// OCTET STRING
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_OCTETSTRING) {
		goto bad;
	}
	pos = hdr.payload + hdr.length;
	if (hdr.length < 8) // "secp112r1" curve uses 112 bit prime field, rest are bigger
		goto bad;

	// XXX add more structure checks!

	return 0;
bad:
	return -1;
}

inline static int check_padding_and_structure(unsigned char *out, int length, int strict_mode, int blocksize)
{
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;

	// First check padding
	if (check_pkcs_pad(out, length, blocksize) < 0)
		return -1;

	/* check BER decoding, private key file contains:
	 *
	 * RSAPrivateKey = { version = 0, n, e, d, p, q, d mod p-1, d mod q-1, q**-1 mod p }
	 * DSAPrivateKey = { version = 0, p, q, g, y, x }
	 *
	 * openssl asn1parse -in test_rsa.key # this shows the structure nicely!
	 */

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
	pos = hdr.payload + hdr.length;

	// INTEGER (big one)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		goto bad;
	}
	pos = hdr.payload + hdr.length;
	/* NOTE: now this integer has to be big, is this always true?
	 * RSA (as used in ssh) uses big prime numbers, so this check should be OK */
	if (hdr.length < 64) {
		goto bad;
	}

	if (strict_mode) {
		// INTEGER (small one)
		if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
				hdr.class != ASN1_CLASS_UNIVERSAL ||
				hdr.tag != ASN1_TAG_INTEGER) {
			goto bad;
		}
		pos = hdr.payload + hdr.length;

		// INTEGER (big one again)
		if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
				hdr.class != ASN1_CLASS_UNIVERSAL ||
				hdr.tag != ASN1_TAG_INTEGER) {
			goto bad;
		}
		pos = hdr.payload + hdr.length;
		if (hdr.length < 32) {
			goto bad;
		}
	}

	return 0;
bad:
	return -1;
}

static void common_crypt_code(char *password, unsigned char *out, int full_decrypt)
{
	if (cur_salt->cipher == 0) {
		unsigned char key[24] = {0};
		DES_cblock key1, key2, key3;
		DES_cblock ivec;
		DES_key_schedule ks1, ks2, ks3;
		generate24key_bytes((unsigned char*)password, key);
		memset(out, 0, SAFETY_FACTOR);
		memcpy(key1, key, 8);
		memcpy(key2, key + 8, 8);
		memcpy(key3, key + 16, 8);
		DES_set_key((DES_cblock *) key1, &ks1);
		DES_set_key((DES_cblock *) key2, &ks2);
		DES_set_key((DES_cblock *) key3, &ks3);
		memcpy(ivec, cur_salt->salt, 8);
		if (full_decrypt) {
			DES_ede3_cbc_encrypt(cur_salt->ct, out, cur_salt->ctl, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);
		} else {
			DES_ede3_cbc_encrypt(cur_salt->ct, out, SAFETY_FACTOR, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);
			DES_ede3_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 32, out + cur_salt->ctl - 32, 32, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);
		}
	} else if (cur_salt->cipher == 1) {
		unsigned char key[16] = {0};
		AES_KEY akey;
		unsigned char iv[16];
		memcpy(iv, cur_salt->salt, 16);
		memset(out, 0, SAFETY_FACTOR);
		memset(out + cur_salt->ctl - 32, 0, 32);
		generate16key_bytes((unsigned char*)password, key);
		AES_set_decrypt_key(key, 128, &akey);
		if (full_decrypt) {
			AES_cbc_encrypt(cur_salt->ct, out, cur_salt->ctl, &akey, iv, AES_DECRYPT);
		} else {
			AES_cbc_encrypt(cur_salt->ct, out, SAFETY_FACTOR, &akey, iv, AES_DECRYPT); // are starting SAFETY_FACTOR bytes enough?
			// decrypting 1 blocks (16 bytes) is enough for correct padding check
		}
		memcpy(iv, cur_salt->ct + cur_salt->ctl - 32, 16);
		AES_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 16, out + cur_salt->ctl - 16, 16, &akey, iv, AES_DECRYPT);
	} else if (cur_salt->cipher == 2) {  /* new ssh key format handling */
		unsigned char key[32+16] = {0};
		AES_KEY akey;
		unsigned char iv[16];
		// derive (key length + iv length) bytes
		bcrypt_pbkdf(password, strlen((const char*)password), cur_salt->salt, 16, key, 32 + 16, cur_salt->rounds);
		AES_set_decrypt_key(key, 256, &akey);
		memcpy(iv, key + 32, 16);
		AES_cbc_encrypt(cur_salt->ct + cur_salt->ciphertext_begin_offset, out, 16, &akey, iv, AES_DECRYPT); // decrypt 1 block for "check bytes" check
		// AES_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 32, out, 32, &akey, iv, AES_DECRYPT); // decrypt 2 blocks for padding check, iv doesn't matter
	} else if (cur_salt->cipher == 3) { // EC keys with AES-128
		unsigned char key[16] = {0};
		AES_KEY akey;
		unsigned char iv[16];
		memcpy(iv, cur_salt->salt, 16);
		memset(out, 0, N);
		generate16key_bytes((unsigned char*)password, key);
		AES_set_decrypt_key(key, 128, &akey);
		AES_cbc_encrypt(cur_salt->ct, out, cur_salt->ctl, &akey, iv, AES_DECRYPT); // full decrypt
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char out[N];
		common_crypt_code(saved_key[index], out, 0); // don't do full decryption (except for EC keys)

		if (cur_salt->cipher == 0) { // 3DES
			if (check_padding_and_structure(out, cur_salt->ctl, 0, 8) == 0)
				cracked[index] = 1;
			else
				cracked[index] = 0;
		} else if (cur_salt->cipher == 1) {
			if (check_padding_and_structure(out, cur_salt->ctl, 0, 16) == 0)
				cracked[index] = 1;
			else
				cracked[index] = 0;
		} else if (cur_salt->cipher == 2) {  // new ssh key format handling
			// if (check_padding_only(out + 16, 16) == 0 && out[31] >= 8)  // this padding check is quite unreliable in practice!

			// all keys don't have a non-zero length padding, so we use the "check bytes" check instead
			if (memcmp(out, out + 4, 4) == 0)
				cracked[index] = 1;
			else
				cracked[index] = 0;
		} else if (cur_salt->cipher == 3) { // EC keys
			if (check_padding_and_structure_EC(out, cur_salt->ctl, 0) == 0)
				cracked[index] = 1;
			else
				cracked[index] = 0;
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
	unsigned char out[N];

	common_crypt_code(saved_key[index], out, 1); // do full decryption!

	if (cur_salt->cipher == 0) { // 3DES
		if (check_padding_and_structure(out, cur_salt->ctl, 1, 8) == 0)
			return 1;
	} else if (cur_salt->cipher == 1) {
		if (check_padding_and_structure(out, cur_salt->ctl, 1, 16) == 0)
			return 1;
	} else if (cur_salt->cipher == 2) {  /* new ssh key format handling */
		return 1; // XXX add more checks!
	} else if (cur_salt->cipher == 3) { // EC keys
		return 1;
	}

	return 0;
}

static void sshng_set_key(char *key, int index)
{
	strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int sshng_kdf(void *salt)
{
	struct custom_salt *cur_salt = salt;

	if (cur_salt->cipher == 2)
		return 2; // bcrypt-pbkdf
	else
		return 1; // regular "ssh kdf"
}

static unsigned int sshng_iteration_count(void *salt)
{
	struct custom_salt *cur_salt = salt;

	return cur_salt->rounds;
}

struct fmt_main fmt_sshng = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT | FMT_SPLIT_UNIFIES_CASE | FMT_HUGE_INPUT,
		{
			"kdf",
			"iteration count",
		},
		{ FORMAT_TAG },
		sshng_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		fmt_default_binary,
		get_salt,
		{
			sshng_kdf,
			sshng_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		sshng_set_key,
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

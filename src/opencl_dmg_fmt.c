/* DMG cracker patch for JtR. Hacked together during August of 2012
 * by Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "common-opencl.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL		"dmg-opencl"
#define FORMAT_NAME         "Apple DMG PBKDF2-HMAC-SHA-1 3DES / AES"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define	KEYS_PER_CRYPT		1024*9
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define BINARY_SIZE		16
#define PLAINTEXT_LENGTH	15
#define SALT_SIZE		sizeof(struct custom_salt)

#undef HTONL
#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
		((((unsigned long)(n) & 0xFF00)) << 8) | \
		((((unsigned long)(n) & 0xFF0000)) >> 8) | \
		((((unsigned long)(n) & 0xFF000000)) >> 24))

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

typedef struct {
	uint8_t length;
	uint8_t v[15];
} dmg_password;

typedef struct {
	uint32_t v[8];
} dmg_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[20];
	int iterations;
} dmg_salt;

static int *cracked;
static struct custom_salt {
	unsigned int saltlen;
	unsigned char salt[20];
	unsigned int ivlen;
	unsigned char iv[32];
	int headerver;
	unsigned char chunk[8192];
	uint32_t encrypted_keyblob_size;
	uint8_t encrypted_keyblob[0x30];
	unsigned int len_wrapped_aes_key;
	unsigned char wrapped_aes_key[296];
	unsigned int len_hmac_sha1_key;
	unsigned char wrapped_hmac_sha1_key[300];
	char scp; /* start chunk present */
	unsigned char zchunk[4096]; /* chunk #0 */
	int cno;
	int data_size;
} *cur_salt;

static struct fmt_tests dmg_tests[] = {
	// testimage.AES-256.64k.header_v2.dmg
	{"$dmg$2*20*fd70ac1e078f01fce55a2e56145a2494446db32a*32*9110b1778f09b1a7000000000000000000000000000000000000000000000000*64*68a32866b0e67515f35dc67c4d6747a8561a9f4f6a6718a894b0a77a47c452471e04ecef9bf56f0d83d1201a509a374e00000000000000000000000000000000*14*8192*70ebe6f1d387e33e3d1093cca2e94c9a32e2c9ba47d461d737d49a7dc1b1f69407b7dbc16f7671689ea4a4641652b3f976b6f1c73c551a0a407d5a335caa169db4a6a25bbd27fbbc38fc71b29ee9b1eae349b0d8a21d57959ecca6bf74bc26ccaee69cfee4999b55374605491af6d0b9066c26995209cd1b71925bcb45a8ef5727a6c20338f08de4357d4cb42cb65ecdc2344a5d7387633c913258ba40699ea5f88804b5e562bf973096337b17b4fc1236d3c8a80b9b48aed63c5a0eae3ae924a883e948f374771bba46923658f225fd2795ce0e795269f589e0ffc81615585e1224cddde654d689a3260e69683c6198bdfcd87507c23cefe36d72f8878cb27bbe5dce868752a7cce067f5a3110f20ebd31ecd53840103e0b2d44385656398edc487bf6d1a5ec3a56af54f9d4254fd20988df41eb85e366f13da1270a3f42c6672ad5faf00fa21e9ba3691bde78ab2c267a142f275467d5b853a107dbf1d75839f0e87b3b4f1d2cec88cc02a26bc4a63aa6836b0c43c5dbb44a832050385a48d46968361ebb053c2416c02458b76c95e50970922556d40b100967340a32824e6b6e44c0c1e0da7ce989d9d5ad91560156"
	 "ed39666cbfbea71f28797a5a7a40e77665612e977ecb8b7fe71d500eafc29d9a0ec1d0ff1723fea7c405bc181ea93c0df42f5bf886eace3cfeee8b0dba52ba8cd2ae009e75d8845264d12dd632ca3236bc1b643437881b270183d2e2bd20808ae73d32bfe88347e33bef4921fcfac9646b74f116be1f04fc353d2222499d5247fa842d0d0f00fc9642ea7524adb65c18fff87b6efd060ec850d7de6f59869387b3d4cc8e38014d52d94ead07d16b8d94327fe5533941497c9be2dd6c04142ba57e29daaeef96d0f2d109522651d797715f4bc5f4cc3fb69fa92623b5ea3e08ff78dc59913993c877f4e2c8964dffd2c8cde6c6b6738da2883505486df5b633aaa8c66acbc2886107f3dd61b1df29f54a13ef27a7d2785c02153375240885e5c54297d88827403320799e05213761549eedc1c159c922087983410d2abadf9ef8ae460d018c278a9ea724f52b866e3d7ff2374496103b5137297100c970d195fca8c1286a8f9d3859ee12c84bdaa4b56ca91e307580b61dbe435ce4021007e4a2a8085976549cf1d195f439bb6e642567f91a0224e98796614d9ea6bfab8f6d13f91b7a80a54e538a1a785cd07b5d7ed2b7e45a0658b5722b5f8844f5139cff3b33ce244946757c020c54c8b5e43324023ed11001201213ffe4829e37135686a8bec1837b35fb234049570868dc5ba9c84cef6890d9ec400a794b1723eb209a60758ba9ae9abd23a7ea9f94fc6b73d29a560e24973c9160f195fbe82376c81dfeec1a7f912a8c22c067a26786a22f0b7db298"
	 "3631400f120010706c78acc36ddcc29c7055fe82105f770e2dadf131ab49af93539fb5186d32dbe4a4df6cb0fdf6840c0609c8769fe242cc60d87e04e6e3be1a7884a05d9fb96c3bc1bbc769d96bbcc0413492eefc5502e9c1ac7c3f237b9851dc453b5bfa899b7b68e5e3b92711e7c92945feb6f6e452d6216e154a952cc28a3740925554d9fd44acedc8a44b0c25bbb6aa637fe9560437c08b17992c74de38fe1fb8fd5f66c2933c2d573ddc914f68f42d6cb350f126a51f607a2dd23b63e6382ec1e6ae434f47cfcd1e7d96c8293ef2994f850a27ef2d8210a0df0c219eadd2376ce36a22db56827d92a90d5e2fa55a4154c39061bd5490ba29f8309cf3e2056f761762dff56803bbe0607faef510d023b249663368977fede0577944f2ff05ead4b432bbb07a7d90148ebd1e30bf1204cd9069725d9fdbb850d3d6fde5044da1b9ffa222d99061c8ae217bc5b249960db545e6fece3ea2faeefa7702f065764b326ae0e62f3b8745cb73f35bea1bb9f6ed4fcda591f4d84da0415a0552306f6691a64a1d0efc8ac93559a79e57e357b63df48506c12dde74f6ea8fc5eeb1846c394fb8fd0fd40df26a42e53692db51bb36403305c1aff797e20adb6f8f1721e316705dcf8fe6e6989a5c3da253fdc6cb5de426f1c018161d72e34e6791d73023c5df69c0f83d3ea1d097f3a7ff37720a66868f40d3b87755bdaf508086c7e478ac1efc0dc421987af6db9b2f096a7270de91f5b3b84ee6d1d268d581718d3c534eeffbe2889388e9930cb051b5752c1a"
	 "b1faf1e367866af7d4b37ba25c15a030d9a5f32bb8912ce853fe7988dc62aa61264e3c5a29d18c5121a605558b15004c817cb0ab1646138cbf6375f1a179852bc22d80b83891edfd38e25efcc0dbb78062f479a9dc792e5822e09ba3e0b8ef71c62ad7747dba8cc97707f31383baa93108d5c7253dce2395fa24d77c42cbf3559b5dc0235c0ce49ef9e3cc816598698c8f8c5b32abfaeb44f3c35a01a4f47421a166d5aa893aaba80e57eb576b838c95ed6f9d5b3d389a8f86b97fe629408ec7c7ba7fd95d7625e950c7324fdd35989570b24f2e1e24d52b65ed6116e728dc3a1004d3d8fbfeeaea1c7dc5d3dc7a029f97f8dc7f740e2386eb27e9793680d959821031fda08c7146f46e8ee47ec28c7d25574eb690de09849725e490c39e524b74aecfc68ff0d760d115b4d0a126609cef83b6c80731dd17f4a307331464953c6b41875b6e5fea328fd59f275e2fabd25717781cf9d5cc52286246ebc92527eeac7acc6e2652c6fcff405e7b4a78b8f9475f46bb82a68a6e44037d61de0df58a8b7a81f407aaa260f3a49c4a2641776404fc15bfb77573dc8728573a1872e7e093663842d9368e74cbe3ae547355fa101daeaa0f97dc0a63927e54ae59fe13aac4f488e938fa67a12876d103b4a56b6eb88ff0104330e5cdc7c6886b46545d523bfbfc88f40f9654fcd0f8c4f443a225b50b44af9674166d3de36b6ac63a150fbcda2e2511ae2a42fbe51c08f7238366aada5c6be8eeb41963c6a5374a94b332012e860d6cfbc1b8a4d5a9825b88a90c9a5f"
	 "5615ca503698ad00df2cd93467b66d9b15876bc49895a081959132bad2e63757aa4e5ff77c6f25dd2581a3e9bb8e213c9313ceca0fcf5f8416882849fbee576d8ffb9dc057eb96bf6b81db60a82b0e6f315a13dd31706c0e36f4f21b9ce977ff6700cd77db603120d59ad8088e121cc3c502e37774b098eee7c8244f9bbe0d4a9d0deba3ec22e5abfea69ab72cdb75a001bb53672fe12b4fdbdf7e82c0bb2608de5d8e1961fb4524dd1acc890361923fb691bc5ea436246428a70b5021f9eee2c637eeab574babde4c0d55f57925e511ff623af5c4224d3ccb9c8572179e2610b4b79817ca18ddcb5302151f9facffca96269ff5fbb11e48209e20145bdd70d72bae54f6fbb89a3396bdaaa3d45413e3c5bc672ab98dfbeb3274156096f641494c1c946baab7c388a16c71ce5009b32f45dbbe37998906570045027950bd758b7ab2f72c243eccf9551d539946a99779848b16cddf9f163fcefe1e1ebee3ba7d5240b92698ad56a036274ca798eae19b0dbcf39a1c0ea1a58b29dc0e3de89def08e6c5800c94db47b7eaef5514c002d687b4d99b00fbd44137f56557830d63156f43bf73db8b330bca0ebb4ea5d50941b758929722aaa5452cd4a4e00640165dfc35fd35daaf929997adeb4c4f7611d66befb80809dc7bc6c763879c3bcd8dd0fe6b621898717fd095fb7eb403b07591b931a8e16ab488b01acd636bf4f1e71d5460532b8a3b00d7353e84c071de5cfa25de685cb85b569e08d2f177727cda11f196b040d25c97ccb83e355db98c2bc14844"
	 "1ca95b5f612020bc53a81184ccd0c5f14bf6d9fd6318ec28bafe8d668cb3c98c56ad416007bef4a3ed9e12eafe8f9e7d87fbb02d1f557b497db1a2c0fe40ec3f23ea88332513c68f724cc8a8af6636c9f332a8e55c2d41fd81a23e92e9ffacd3ef14cda669e7dbe31ca08a5238c7fbfe7020933087bf2ce0a7489fd5a3becce5de09628234f60c833002aa8e9c9ec51f57c8e4ba095c1d054750d46d64041bb1f567a82d63bb5e88fb70bdddad0ed7572229e56b90e74dd88ca829f1ce8424bd24a0bbfe3dc3f77d244ee59f364b36a4b05fb511b5b0d7f876c65ab4233803543b0a68b9d2d6d45d292f91eb4700c2dbf431e40c77a4fcc3ac3fdf3a2bae3df35b6417b8f1eedfe84cc65a07c426780871d16ec5ed3201ea4eaa778b71f04cc1999587bb4645bbc43e365395e9188c85bd024f758304aee979f8e67d07636fea251423e920e2b7258580d1918fce772bf02ee66926fc5f9a3dd6a8c89e6ce7e4fc03d4784296df1a9152a1fc66050983a287e3520bf3e04d900d25316c8bd5ab489bf97a2f31f4061f895111caff9968ecb22d75cb9e5400ca1d0fb044acb4fb9cccaa4766cf6c63ae5a7a3f9af90d1b225067f671d85cdb4e2e21d2850f351d995d54520fdcbb8cb30bfa82190ab2071eb8bf350f984408b206597371736110114d12d79da4027f9a58c8fede63cf16fa552d2a956ae2a49c83b0afca3056f87f1e27bdeb9d14a7e5cf30550017a3233c4f386769021a853b971746aa28aa69ca980bb02979779c5bd29259c84911e2b252"
	 "61b92be669e8a731dd74edce66b6f3ab5944695efd57c0004ff637eabfbc02ae346528fedbf2ae80d420580adc4d571a37fa1397fc2b85ec458d5262c15620c88f2dca0eb1bae4ec39d67fef56ecbdf89703919e5a6767d0f77bf6f0f60ba21003d033c9dc3057df18d855a5801110fa9a29a42ce10a44a39ed883df249ccddef8aaf832387e70048d9ad6014cc17f9a2bf7146696ee4eed388d06a45f7bd7696e57500ecfada9e9eb17926b16bbd90146e406e281141f0a918c320cacc9d1f045ac1bba87ce8d1d45cb6303988d5228da6ad33df6d2a5bd7f265b8f610078e9db5fa3db0e08286e500063f0fd6860a11d9985226ad382a95bc3c3941d43378ea1bf28fc85749f616092d77e7c292e311337168b52eba08ffc0f76582710a1a7d33c55162b3c7fbf227a324e1f4579e035ae0fa17fafb1ea964aa977490b5a3fc16c75e1fc50a6d17e193345b71369df804c61a71bf60be4281c3d1f945c690368c23caab006f9dfc913dbe6119d6fe8349cdd424db7074726e8bdd0ae99e2bfb9b800ddb965c06e0587cd10108c9b431cad4fd10d3654a22ceac73553a6b2b2218ed6526c362df46cfa776e2caea0de61b9d5c0c74e03e299ceb2221ed0f30ffc5876354d5607c3eafc77f78e4fce5e0c7f6ba7d417ac5f0511e2635b41b28dfb4f2fbb73d351a69fff920b76f5687386114b3d5ab9cad056c88840a023b7e2df73f007852763570d38a966c8258365b014a12a3497f506dbe55c073244333547223785438372884ecd8b66aa0a794ab5fb"
	 "94b0a519bb3cbf01b43463c0c7fc6ebc67754ca25686002e13edad54c817b0aef64698637d18a4a8bba382add892f4918b720aa99b09ed2a6e02b7140f89e3e00680f37343d3e47412d04ef78005b8b9a23b92d145a8da9c5efafce374955727367a7f1a179b990868550cf960c6df6baf2cddda5fe3e689de8dfcf1474db419ecf88cbce9de7a58e9d8a15991fdf5361846273d195a2892fbc95ad079ca8153910984c4694edb4c790f430043c4019fbd96fe49d8afa5e7d1f6674e4a125bfbdc916b0d3819566898599443ebf2a87b1fdaf41378227d396d2d320dc5b860705bc87f45eba2b6473234fe054267698dba0913ab1234b46697c54e2b19526d1ad4b7e3eab40a413f86170fe9f2a71eae2fb959a021b0b43516f1c8a3e674f37ee235ade79ca296364b0cad5ebe8449e09b63a34e8711587f7f2fe6e181a787b1d3a8f30012ce9549abb834fb80c673c575a25d3c33bb6d846ac231f411dd6422c59215e0a267424c0c57e6c9bd5486e8b6327e9dd16b7065eb74ef91ec9204360b03d08654a4e418346ec2d4d21edd5608a76903494791546d430eac38178d158d61951de3c61fbe5d56c22cbda4a3d40297f7abd83913e8b483d9a80cf000810d90a921f453bcf9e35732d2579c1aaef4a6980c666e3b273a9f91d9918f850bd6e4475d8aa5cb616cec58d6ab6d70dbe2b0f7ad85618b6e60dd4ff5d0faf19dfdf27a9ee48cd7b2d6613e76f04ab6ef5f0af12966a90875816c27c4297a2bf622ddf66fbe7c211670d0c46c7295b93bd2f1"
	 "22568df3dc46e9294c7258a0b7e81b2d45979680edbb7ab323e4857d84306ccc16ca79c711144eab7b37e3437245d7b78ced1cfebfc45892791b9ac6cc1211f83e328ce3f57af3d89b5be89dd2efeac9d738330bd0d8d4a059bfac06d1ad73bf6d427541e559c3d16eb5adc4380c1b25c1b8a9097ce7eeeed1c5d6884dd1a32ee2bfaab8371593a0eef65f80e705b9b56adfc0db4c272024a71947755032a5ebc1bb346ee8a99b01b408cc0b1658a319ffa5ab2eb87e9aa8b3dd9d9d92ce3bc04e4ebcc011a280143927676360f249ccdaf7949bb23770a06ff5861661d36d761508f7e9ba149310d1347c3165e07997853d415abdacfae9579d1dc0b5990a05ae9e6dce8931ac2db9414546dc64f8161a64cf30b9ce8c50ef2a99775f03dfc2c611e780a5cbcc27cab920a87d940acd8b3fd42897ab6f51b29214275bd564c50eb7aab3ad19a2c903c84d2ed5a23c49c81d87cf3244505424332c917d7b671d4a90765b8953c26bb7ed5dfe3e93632610ab44296afee2b5c631fe643a0a78eb9af94d700250f5a82bc57d24825423f1ecfd8cc2bb0daa229670d0d9a4fb342ee8c9b7b16d86d29abc2a57633303b918ac78ea8d2672dfdd4a06ea0bbd756fbadfb0c09e2426a65e90ca829ea00ad66ca8c9e79b9aa5ddd02d435cb23014b1033da00381ddf2dcf408660d1eebd1f6c7bf5ae9fc3fe47e75ff7ca482716534a9f3365f5cdb48f3d59fb19d11bb8782ef96e394296594812e8a7da23a953f6117ce577e55f3d6cb1d3a4007dc7d252c7123a8"
	 "37be12884e54ad10757af405beffb5cff189133bb7df5fc009544b2d62ec44fdc0c1c8240d4413af5b36e031510b1f1537a690ba7049cce9df4bf4dd63f6987c513992fca78a1cb7e8d670fb43a52ea2ca2f49724e35397041e5c75a365b510f40fa9bd076377274d6a95af801981d71972da0a08b536b024f439c43d13902878798153ed825ddd7dee8937181823076f036caecec170edf1b5fbdd84e530bc50a7acc257bb9679d72de3f115602d18d2d12e6ecf4d3242ccbe9a71a1483e7fe40d2447ba028a76aa92c13516ebde90dc4d204095a554cbfad79d6efe4ec540c7b51593413465b929742b729ca688f67ee9d9fe76431fa81217fb135d0dd6ebc91904efcb0cb6dee22867e5ddd7453f530d04935f41575de9ca457da55b67791d2e8b83890b5be543366b92ba6579a6f19f8e82a0bd87e379967766e5b0a58305b984778c562ea03a8b8392e3160ea4532b6ce5de74bc8fa0e8ebe88fbd62a73d7106a309f5a5f5d7617664b015e166fcd87906caa80ab4eb3e62f73e527b5d951a0ed0340fe17bb7b2692e4a31d14798879788fed12413bac50e490ab93ed66311599a6c1362fc60da5319ad907c7ef7852985ce86246276a138379d2004772d4d9a989b83b3e780bdda9825ad06a4b3dcc9a9d4d8025cbdee7cb2e02ea1f77bc90bf4ae56903859025b7283ba6410aa91933466623b996e9ad07e3095e376b11a27ca451c246d5561501e69c6747013ecda44f8d1fa50a75572453c9ddecc07b1aaeebc04cc7e976915f5e68d1236ae2ff"
	 "dea4b9fc4f8e91b03982801e2ba604b46ad80f966838ae09d2734c6482dd16d7738cadc1276593a336e2ce8cf7ce48d1535c7865f7b90445ff3ab9e56f58e254115bc07710de50d7953238d7ca419013d104d90fe79794995c28f219c963d716bf8942e0cc5cb432aafce4afb42f74596b847fde5d87fba9adce5c17fe590fe58e60379393e521ee194fe063211d72c29d58f7dde89addb6b0e20515ca7aa270df2ef2d77f92219781502c49292c6c4a985242b9447521cdef5a52b53b5eefcc43e8036ebe90b51a3565cbb180ea1b3e3d20f63b8f420c2a7f01c475428d5f63c66f122654af4edcbafebe34970c152767cf623eb4f1ee33931a79622cafc70cdd2bc7ccd55ecc1e0aafde3f66f5414315048d3c5c51638c35fa920cfcf7a18ada48a589c12e4da2c801cb8bf3b182463707a17891cf296ae8aae6a8a88ee3d602cc1bb7647861f65ec1a278433ae08d8c8e63727633425fda0b86d78378ac80b1bc1a48abf270dc2b5ea71691eeeb979950cbe0ddfdc451dcf8e3dc657060f4c3f96512b21bcb228a966381efa94bbf5ff4bbf38a803b6aafc719a545e4d0582a62e81e6468aa04eaf131f8d2f545c060651e115032f5b3579fdfb95a2328f5c9a0308874630e840ae1dcec1b9543c36267a9651c94c91cea42a93a91ba3a054ded4a8343864b449e46abec49474e218c8c541b00eb0f8997e710025631ac28be3f08126446dee0cf61bc69b85e4fc021f203c796cbd2ca16ebc8fa15f55510a08ed334155233c6459d2d428df31a3f376c"
	 "d81a530700b3ef08631dc5b50f787d4efe2bf219bd17f0431803d9d946255716e8543bf77fc44a48abc70a97feae8398c2059938d39fb4ac5f7214d92bb89fb9c45b6d117fd51f6207935beb1a89963fb9d1aa020669bf809c21154c20e720aa1178ed2bc13fd548e0d7d01eb1d028aa48318a02dc7aa412e2ae01ff59a86dae40771ad3f48f0fa54b6e679854be00deb9938e37ab3a4c9a96f3b7849ac75b82619cbc806c42f4bc4feb1141f6a8391bf9335f643ce5cd2791590b28b19d03cca7b5cf702f10ffa0317327e828deb4791f71500f243be77a451e5759c6c711b38f8f62757c54d7fc6dc586a90df7777d8cf1c72f9c0947af005d770f4a74b6c9413738c3b5ab32306ff5b41a6446c2de3f59a27b79d877d3f05fe22d11afd69e49e59f35b3725a0ad126642f388602b7816abe397a9c9233cf7d1e12a00362306d2d9b81fddb279544f35e23a8c198930f75986f26e6f292ae8debe5da0a7a5b8add2be71efc78179eff7fa2a2dad35863b69e85e8172073f434f48fb03f7bd1bc78fc2badbda261a68f7bfa171c898897b3b0d4852920674b8d9ffdb37ce66c1b6aaf9b375253a0d74eba4d359737f7fddb42471969d81605e41f615399c5fd6cce1808e9b511ac54f75f774e84b00970474f5136447af04b4866ab6c54aabf7a247c6caf3ee891fecb14073f3cfdc7368ac00f6b1c9b23e301e49257840f949a57c28a95c5c490bca91bf979d40403f7b9458bd255df757e6eea0bf41d5175548aa46243d98f2f0f6c754d6e7e58fbea97"
	 "7d7e0af8b7d0a6bce07d0c483293868a914a50aaedfb9b239b4c3c472381535b287a4146fd52e7bf882c9c3eff7bb2fae15d5b96bb1222d81d26dba563ac550e716b6c08b062cad6702a33a9db4274fa2e81af815e8325101d5a9ce9b345e29619da9e45dcbcd7b0935d7dde07644edc6b049eee9371511bb2cac50ec1170c7aad835c54fa52c8e0a0e8446356488e09c2f07b17413a7ddb872d05016aba129cc36de609831863747310f0fa443480a47524dfc5e1f34eef3ba2fefa29e596e7fff86a924462781930fab55e71fc2f06271e62878e51e0db08ee5dea31f1d2afe9a4f548ad6a4f4763c9d0eecbcdc32323aba1c9c12554a5cfedb5310b4a03caf426a80d725fabd557493c46f2a174aac851d3d39529d5ad919fdb7fb0dc1e5b0ffdf706a9f5af36fcd2bdde28d68c5af4a1da4e67cd44f97b555b62b39cee1274b7c3dd3971ace3da6101c87f9b8f28c5e13d4066a3e63543825dd8bddc3e90b6dc75bac78931da98929a337817f68deec6065f6f7883d5bb10cab909c9945f71a672eb2cda9fadf4a8d9da906e2a5d1f589193b4e791772663f1bbe751498bda065f90244391169d80490208083de39bec984af73dc99b10d85958f372004a03962c45c531b347851dc5e26bf7bcdd68c9b129524d6734282bdd431f991170d6a5c67138a5405d8005b355ec7ce95496a8e98782f6d978c42c30a17db9c12671d82f2d3e257f66980f20bb6380303f1e89b10035ae7bdb3e55d31f2d1574784aed5c95aa09aaa9614989d957a65d893dbd"
	 "abbfaaf30cae0cad575e39f5311aa00a6979fa52ec12dfb2f731a3ce5f8b6097a612c2ce98f5898eb2d1780d0cf9ad30ce5395ae871ba7ca6a0884a13c09732cefc5aed9d7a28c09041cdd62e75d7396432545f0c16496b7f5f516fb2cc603c0ec10a51ee952b7cd0593ec00dddf67e27dfe3f0cdc5bf737170243a8ed3c1f59733fb47bde4b6578d7ef11f95790d4c678d95ab2cbdb1673d2d516c189af00f996371077276e672f1223926fdcd6627ff86816906edad3aa97e3a9e7346562add05ec1a94c2dbb7f3b28ef537715a1d69761bfb8c2092e608311af2f79a4f8188665a48539944374437bcff6e59bdff4e4b9e4dce11307d892915071157698460b9e9fd68ee0d1acd21434810fc8ae702fb8dc794ad5364c79fdd74c8a70f390556930fc2a23064f36411c626179d1d745d4875f5c2b37292cb8ba37bb78d419f05e9a5d2245a38da20b6b14eba2d5ca3d58d23bb5ade1322cf337eb75a97ce98c167b6305907c3fe18038bee1e2450c3095480f99c9f12d2b543b33866e5546a39d539c6e2d639356bdbcbdb3b4e0935ac76e0fdaf54cfdf241d2c5ce135324885f8cd69e6562f48979352bbab357c6861c66b4ff7d9dd5d32a8ab8b6e759a2f5ddcee847fa439a5f9e3989039aa60751019eca6c7dfcc2464ca4a1ae12f079d200961797cb0e52cb046d1f0cb1d97c4699e07f019b48edd6f4a71b99ba26c2e5e72745cd9bb9a7e89d8eaba646461bb76818fcc447de2820196e32cdcf4a57c527c52f64d316b513f6a611c929890be5b0"
	 "3b3d3352cef23bf86d0e058b1cd9c4a10a9a01060aa9c9cc4bf42c7c6cbb677724db3f0c3736461c1828e67c9916e953057024371bb4ad8995672f760c47574bde9df9e73af90773cd46c9df8cb655f8c37eed8cbda40da06304471e32bc828a7dd9457fbe4d63a15633009c1a9f003f3db7f5b2b5e3b22c60f747d5627bce3eb4398a543cf24b18cf0a56728adcc253d7f5343245c1426b5bcd9daff94394499cb6d7ac2b4e63ec424c66f5dbceaf877fc13f47e744aca7d8b5d89c8d5621f4e13488b141062ee04c2312528a0a987a5d32ebc6ffae45657f4b2d1420890970e363a124b75374594dea0560320b36133e31d6a978f90ef079b81484503c7fc3edbceadfc9fcea06f271a60ea6c5d434b694ace1b506eaf013aca2c6103acfe6c565a5a24cdf638f8ee282ac812e32cc2662a8e2d4a31239952836c4896870d973bb65b280f0370f4c3a54c7f4723b2bef522ca4c233d7646da3fdb9743e273afa1e3bfcb947eea9f323ca908bb4961b214aa906cca1d2d56eff25d60952cc5897ee6390f9af4efd5d48b2aee8734cf6b8042f2de75b107f8d135d9a63148e88e43df815fe7871a354741f8863af4e114ed0369515bca104f8d3b24a2d740b8617de3e96a23*0", "vilefault"},
	{NULL}
};

static dmg_password *inbuffer;
static dmg_hash *outbuffer;
static dmg_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static size_t insize = sizeof(dmg_password) * KEYS_PER_CRYPT;
static size_t outsize = sizeof(dmg_hash) * KEYS_PER_CRYPT;
static size_t settingsize = sizeof(dmg_salt);

/* borrowed from http://dsss.be/w/c:memmem */
static unsigned char *_memmem(unsigned char *haystack, int hlen, char *needle, int nlen)
{
	int i, j = 0;
	if (nlen > hlen)
		return 0;
	switch (nlen) {		// we have a few specialized compares for certain needle sizes
	case 0:		// no needle? just give the haystack
		return haystack;
	case 1:		// just use memchr for 1-byte needle
		return memchr(haystack, needle[0], hlen);
	case 2:		// use 16-bit compares for 2-byte needles
		for (i = 0; i < hlen - nlen + 1; i++) {
			if (*(uint16_t *) (haystack + i) == *(uint16_t *) needle) {
				return haystack + i;
			}
		}
		break;
	case 4:		// use 32-bit compares for 4-byte needles
		for (i = 0; i < hlen - nlen + 1; i++) {
			if (*(uint32_t *) (haystack + i) == *(uint32_t *) needle) {
				return haystack + i;
			}
		}
		break;
		/* actually slower on my 32-bit machine
		   case 8: // use 64-bit compares for 8-byte needles
		   for (i=0; i<hlen-nlen+1; i++) {
		   if (*(uint64_t*)(haystack+i)==*(uint64_t*)needle) {
		   return haystack+i;
		   }
		   }
		   break;
		 */
	default:		// generic compare for any other needle size
		// walk i through the haystack, matching j as long as needle[j] matches haystack[i]
		for (i = 0; i < hlen - nlen + 1; i++) {
			if (haystack[i] == needle[j]) {
				if (j == nlen - 1) {	// end of needle and it all matched?  win.
					return haystack + i - j;
				} else {	// keep advancing j (and i, implicitly)
					j++;
				}
			} else {	// no match, rewind i the length of the failed match (j), and reset j
				i -= j;
				j = 0;
			}
		}
	}
	return NULL;
}

static void release_all(void)
{
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release Kernel");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");
}
static void init(struct fmt_main *self)
{
	cl_int cl_error;

	global_work_size = MAX_KEYS_PER_CRYPT;

	inbuffer =
	    (dmg_password *) malloc(sizeof(dmg_password) *
	    MAX_KEYS_PER_CRYPT);
	outbuffer =
	    (dmg_hash *) malloc(sizeof(dmg_hash) * MAX_KEYS_PER_CRYPT);

	/* Zeroize the lengths in case crypt_all() is called with some keys still
	 * not set.  This may happen during self-tests. */
	{
		int i;
		for (i = 0; i < MAX_KEYS_PER_CRYPT; i++)
			inbuffer[i].length = 0;
	}

	cracked = mem_calloc_tiny(sizeof(*cracked) *
			KEYS_PER_CRYPT, MEM_ALIGN_WORD);

	//listOpenCLdevices();
	opencl_init("$JOHN/keychain_kernel.cl", ocl_gpu_id, platform_id);
	/// Alocate memory
	mem_in =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem in");
	mem_setting =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem setting");
	mem_out =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem out");

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "keychain", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
	opencl_find_best_workgroup(self);

	atexit(release_all);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$dmg$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 5;
	p = strtok(ctcopy, "*");
	cs.headerver = atoi(p);
	if(cs.headerver == 2) {
		p = strtok(NULL, "*");
		cs.saltlen = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < cs.saltlen; i++)
			cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.ivlen = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < cs.ivlen; i++)
			cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.encrypted_keyblob_size = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < cs.encrypted_keyblob_size; i++)
			cs.encrypted_keyblob[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.cno = atoi(p);
		p = strtok(NULL, "*");
		cs.data_size = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < cs.data_size; i++)
			cs.chunk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.scp = atoi(p);
		if(cs.scp == 1) {
			p = strtok(NULL, "*");
			for (i = 0; i < 4096; i++)
				cs.zchunk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
					+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
	}
	else {
		p = strtok(NULL, "*");
		cs.saltlen = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < cs.saltlen; i++)
			cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.len_wrapped_aes_key = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < cs.len_wrapped_aes_key; i++)
			cs.wrapped_aes_key[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtok(NULL, "*");
		cs.len_hmac_sha1_key = atoi(p);
		p = strtok(NULL, "*");
		for (i = 0; i < cs.len_hmac_sha1_key; i++)
			cs.wrapped_hmac_sha1_key[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	MEM_FREE(keeptr);
	return (void *)&cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, 20);
	currentsalt.length = 20;;
	currentsalt.iterations = 1000;
}

#undef set_key
static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}


static int hash_plugin_check_hash(const unsigned char *derived_key)
{
	unsigned char hmacsha1_key_[20];
	unsigned char aes_key_[32];
	int cno = 0;
	unsigned char *r;
	EVP_CIPHER_CTX ctx;
	unsigned char *TEMP1;
	int outlen, tmplen;
	AES_KEY aes_decrypt_key;
	unsigned char outbuf[8192];
	unsigned char iv[20];
	HMAC_CTX hmacsha1_ctx;
	int mdlen;

	EVP_CIPHER_CTX_init(&ctx);
	TEMP1 = alloca(cur_salt->encrypted_keyblob_size);

	EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, derived_key, cur_salt->iv);
	if(!EVP_DecryptUpdate(&ctx, TEMP1, &outlen,
	    cur_salt->encrypted_keyblob, cur_salt->encrypted_keyblob_size)) {
		/* BUG: should we fail here? */
		return 0;
	}
	EVP_DecryptFinal_ex(&ctx, TEMP1 + outlen, &tmplen);
	EVP_CIPHER_CTX_cleanup(&ctx);
	outlen += tmplen;
	memcpy(aes_key_, TEMP1, 32);
	memcpy(hmacsha1_key_, TEMP1, 20);
	HMAC_CTX_init(&hmacsha1_ctx);
	HMAC_Init_ex(&hmacsha1_ctx, hmacsha1_key_, 20, EVP_sha1(), NULL);
	HMAC_Update(&hmacsha1_ctx, (void *) &cur_salt->cno, 4);
	HMAC_Final(&hmacsha1_ctx, iv, (unsigned int *) &mdlen);
	HMAC_CTX_cleanup(&hmacsha1_ctx);
	if (cur_salt->encrypted_keyblob_size == 48)
		AES_set_decrypt_key(aes_key_, 128, &aes_decrypt_key);
	else
		AES_set_decrypt_key(aes_key_, 128 * 2, &aes_decrypt_key);
	AES_cbc_encrypt(cur_salt->chunk, outbuf, cur_salt->data_size, &aes_decrypt_key, iv, AES_DECRYPT);
	r = _memmem(outbuf, cur_salt->data_size, (void*)"koly", 4);
	if(r) {
		unsigned int *u32Version = (unsigned int *)(r + 4);
		/* handle compressed DMG files, CMIYC 2012 and self-made samples */
#ifdef DEBUG
		fprintf(stderr, "koly found!\n");
#endif
		if(HTONL(*u32Version) == 4)
			return 1;
	}
	if(_memmem(outbuf, cur_salt->data_size, (void*)"EFI PART", 8)) {
		/* handle VileFault sample images */
#ifdef DEBUG
		fprintf(stderr, "EFI PART found!\n");
#endif
		return 1;
	}
	if(cur_salt->scp == 1) {
		HMAC_CTX_init(&hmacsha1_ctx);
		HMAC_Init_ex(&hmacsha1_ctx, hmacsha1_key_, 20, EVP_sha1(), NULL);
		HMAC_Update(&hmacsha1_ctx, (void *) &cno, 4);
		HMAC_Final(&hmacsha1_ctx, iv, (unsigned int *) &mdlen);
		HMAC_CTX_cleanup(&hmacsha1_ctx);
		if (cur_salt->encrypted_keyblob_size == 48)
			AES_set_decrypt_key(aes_key_, 128, &aes_decrypt_key);
		else
			AES_set_decrypt_key(aes_key_, 128 * 2, &aes_decrypt_key);

		AES_cbc_encrypt(cur_salt->zchunk, outbuf, 4096, &aes_decrypt_key, iv, AES_DECRYPT);
		if(_memmem(outbuf, cur_salt->data_size, (void*)"Apple", 5)) {
#ifdef DEBUG
			fprintf(stderr, "Apple found!\n");
#endif
			return 1;
		}
		if(_memmem(outbuf, cur_salt->data_size, (void*)"Press any key to reboot", 23)) {
#ifdef DEBUG
			fprintf(stderr, "MS-DOS UDRW signature found!\n");
#endif
			return 1;
		}

	}
	return 0;
}


static void crypt_all(int count)
{
	int index;
	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy setting to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent),
	    "Run kernel");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], mem_out, CL_FALSE, 0,
		outsize, outbuffer, 0, NULL, NULL), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#else
	for (index = 0; index < count; index++)
#endif
	{
		if(hash_plugin_check_hash((unsigned char*)outbuffer[index].v) == 1)
			cracked[index] = 1;
		else
			cracked[index] = 0;
	}
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

struct fmt_main fmt_opencl_dmg = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		// FMT_CASE | FMT_8_BIT | FMT_OMP,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		dmg_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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

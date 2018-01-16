/*
 * 7-Zip cracker patch for JtR. Hacked together during June of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>. Unicode support and other fixes by magnum.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>
 * and Copyright (c) 2013-2017 magnum, and it is hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sevenzip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sevenzip);
#else

/*
 * We've seen one single sample where we could not trust the padding check
 * (early rejection). To be able to crack such hashes, define this to 0.
 * This hits performance in some cases.
 */
#define TRUST_PADDING 0

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"

#if !ARCH_LITTLE_ENDIAN
#undef SIMD_COEF_32
#undef SIMD_PARA_SHA256
#endif

#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "sha2.h"
#include "crc32.h"
#include "unicode.h"
#include "dyna_salt.h"
#include "lzma/LzmaDec.h"
#include "lzma/Lzma2Dec.h"
#include "simd-intrinsics.h"
#include "memdbg.h"

#define FORMAT_LABEL            "7z"
#define FORMAT_NAME             "7-Zip"
#define FORMAT_TAG              "$7z$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG)-1)
#define BENCHMARK_COMMENT       " (512K iterations)"
#define BENCHMARK_LENGTH        0
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt*)
#define SALT_ALIGN              sizeof(struct custom_salt*)

#ifdef SIMD_COEF_32

#define NBKEYS     (SIMD_COEF_32*SIMD_PARA_SHA256)
#define GETPOS(i,idx) ( (idx&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)idx/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 )
#define HASH_IDX_IN(idx)  (((unsigned int)idx&(SIMD_COEF_32-1))+(unsigned int)idx/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32)
#define HASH_IDX_OUT(idx) (((unsigned int)idx&(SIMD_COEF_32-1))+(unsigned int)idx/SIMD_COEF_32*8*SIMD_COEF_32)

#define ALGORITHM_NAME		"SHA256 " SHA256_ALGORITHM_NAME " AES"
#define PLAINTEXT_LENGTH	28
#define MIN_KEYS_PER_CRYPT	NBKEYS
#define MAX_KEYS_PER_CRYPT	NBKEYS
#else
#define ALGORITHM_NAME		"SHA256 32/" ARCH_BITS_STR " AES"
#define PLAINTEXT_LENGTH	125
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE           1 // tuned w/ MKPC for core i7
#endif

static struct fmt_tests sevenzip_tests[] = {
	/* CRC checks passes for this hash (4 bytes of padding) */
	{"$7z$128$19$0$1122$8$a264c94f2cd72bec0000000000000000$725883103$112$108$64749c0963e20c74602379ca740165b9511204619859d1914819bc427b7e5f0f8fc67f53a0b53c114f6fcf4542a28e4a9d3914b4bc76baaa616d6a7ec9efc3f051cb330b682691193e6fa48159208329460c3025fb273232b82450645f2c12a9ea38b53a2331a1d0858813c8bf25a831", "openwall"},
	/* LZMA before CRC (9 bytes of padding) */
	{"$7z$1$19$0$1122$8$732b59fd26896e410000000000000000$2955316379$192$183$7544a3a7ec3eb99a33d80e57907e28fb8d0e140ec85123cf90740900429136dcc8ba0692b7e356a4d4e30062da546a66b92ec04c64c0e85b22e3c9a823abef0b57e8d7b8564760611442ecceb2ca723033766d9f7c848e5d234ca6c7863a2683f38d4605322320765938049305655f7fb0ad44d8781fec1bf7a2cb3843f269c6aca757e509577b5592b60b8977577c20aef4f990d2cb665de948004f16da9bf5507bf27b60805f16a9fcc4983208297d3affc4455ca44f9947221216f58c337f$232$5d00000100", "password"},
	/* CRC checks passes for this hash (no padding) */
	{"$7z$0$19$0$1122$8$d1f50227759415890000000000000000$1412385885$112$112$5e5b8b734adf52a64c541a5a5369023d7cccb78bd910c0092535dfb013a5df84ac692c5311d2e7bbdc580f5b867f7b5dd43830f7b4f37e41c7277e228fb92a6dd854a31646ad117654182253706dae0c069d3f4ce46121d52b6f20741a0bb39fc61113ce14d22f9184adafd6b5333fb1", "password"},
	/* This requires LZMA (no padding) */
	{"$7z$1$19$0$1122$8$5fdbec1569ff58060000000000000000$2465353234$112$112$58ba7606aafc7918e3db7f6e0920f410f61f01e9c1533c40850992fee4c5e5215bc6b4ea145313d0ac065b8ec5b47d9fb895bb7f97609be46107d71e219544cfd24b52c2ecd65477f72c466915dcd71b80782b1ac46678ab7f437fd9f7b8e9d9fad54281d252de2a7ae386a65fc69eda$176$5d00000100", "password"},
	/* Length checks */
	{"$7z$128$19$0$1122$8$94fb9024fdd3e6c40000000000000000$3965424295$112$99$1127828817ff126bc45ff3c5225d9d0c5d00a52094909674e6ed3dc431546d9a672738f2fa07556340d604d2efd2901b9d2ac2c0686c25af9c520c137b16c50c54df8703fd0b0606fa721ad70aafb9c4e3b288ef49864e6034021969b4ce11e3b8e269a92090ccf593c6a0da06262116", ""},
	{"$7z$128$19$0$1122$8$6fd059d516d5490f0000000000000000$460747259$112$99$af163eb5532c557efca78fbb448aa04f348cd258c94233e6669f4e5025f220274c244d4f2347a7512571d9b6015a1e1a90e281983b743da957437b33092eddb55a5bc76f3ab6c7dbabb001578d1043285f5fa791fd94dd9779b461e44cbfe869f891007335b766774ccee3813ec8cd57", "&"},
	{"$7z$128$19$0$1122$8$6d4a12af68d83bfe0000000000000000$993697592$112$99$7c308faa36b667599ee4418435ab621884c5c115ee3b70be454fe99236422f4f2d5cd9c8fcfbe6b6b0805ee602ce8488a08f7ea14a4f5c0c060fc685bff187720a402b23a5cfe3c9c5a5ae07f91209031b8f9804ac10459e15a0158031f6c58e507401ec6e1e6de8f64d94201159432b", "&'"},
	{"$7z$128$19$0$1122$8$7527d758a59181830000000000000000$3917710544$112$99$61a9ca9e835bd0f2dc474b34d5d89bcf8cd1bb071a984ee1dcf224174a60bcee140fcf2fde8927fe4f3f4eb4a2cc39faff73f1898ae25cc92bd02939f4317ebb173bf3b6f01eef183163ddd533ad5c076f87341bd8b86d8460c68fc390aa8df89fc4076bdfd24e157f6c07e105c07612", "&'("},
	{"$7z$128$19$0$1122$8$68928bade860a2b80000000000000000$3235890186$112$99$4b685a569c3aed78d217bae9ec64fa06b614df55c1cb0d160563d87efe38813accb38dd7037f86cebc91751c2488769c7398dfefaf491c024f2d640dcb388a56404cd5ac475ba16b5f8206fa45d5923b3a0c8dd0f24460ccee0d93bea03ad58b8a8db502a55ba1775560b3d194f342f7", "&'()"},
	{"$7z$128$19$0$1122$8$81931b9ba0b069820000000000000000$3094344848$112$99$fdbb2622143d25b13992b1467ce9edce4e3df8ca07535735b76e8abcb0791e384a1d5547483e19c3bd6e5a0742d29c403cfc8b3a003b285e80b350ea9157600eb91c49b329903de9ec9b17d1c95b0e136b579e165a6e80550464fa99830bfd9ee58fc14516b614ff9f84ec80e6880a36", "&'()*"},
	{"$7z$128$19$0$1122$8$ccf696913989510d0000000000000000$1238556212$112$99$647264fbc665e73ecfe3ef7055fef0d91cb86833d6df08b2f7a3c1c89cf7cdaa09a802c8bfb2e5c6b55143a315df74d841b349fc8b43613d0f87cc90325fd56fc17ee08df7ce76cdc9cda61bd4d5632e20af3db16e921c755174f291c0aa6581844def4547380e2dd4a574435d17e1e8", "&'()*+"},
	{"$7z$128$19$0$1122$8$d618bd3ec8bafd800000000000000000$1349785$112$99$6514e2e7468e6f0ed63796cfc0588ac2d75f024c4a0fa03778bd252d316d03e48a08ffcc0011725ad4f867e9a9666630dff4f352c59bcbadb94b9d0e2c42d653b80f480005ce868a0b1a075b2e00abd743de0867d69cdc8b56c7f9770537d50e6bb11eb0d2d7d8b6af5dd8ecb50ab553", "&'()*+,"},
	{"$7z$128$19$0$1122$8$1c1586d191f190890000000000000000$642253888$112$99$f55cf9ab802b10a83471abe9319711ae79906cd6921365167c389470a3a8a72b0d877379daae2c24ea2258e8586f12d5036aff9ddc8e26861467b0843ffb72e4410c2be76ec111d37f875c81b244ed172f1f4765a220d830a9615787e9d07f8582146556e9c566b64897a47d18a82b36", "&'()*+,-"},
	/* Some older versions of 7z2john.pl could generate hashes with negative CRC values. Explicitly test the support for such hashes. */
	{"$7z$2$19$0$$8$bce330349dd1378f0000000000000000$-647422963$48$36$2c5e6c91d54bfbbbc77b9774544f35fe55fe2483f33296582b8fb5a5aae05b82b0b78ae6ee8b051d5ca4290d2e177051$32$00", "openwall"},
#if DEBUG
	{"$7z$128$19$0$1122$8$0df03cbdbc73e22a0000000000000000$3194757927$112$99$df53e9d8b4e02cf2962ad87912021508a36910c399a7abc4a3a5423fa2184816af7172418eb4763924ec8b099b7ca95abdc6faac9aaa6e181ffa60b7e8bdb2bf576536ca69152e3b6b97302c796bbc9dec78db6ba7a4a58e68f8ee28f27dea26bd4f848dc3a3315e97e1463b5c171ce5", "&'()*+,-."},
	{"$7z$128$19$0$1122$8$7785351cf9fe5dfa0000000000000000$1304801610$112$99$7b35280384726da8521fee0786ef43e0aa621394a6f015b65cbd7f1329f43c4543b8a451a0007c03a3ce3f61e639c54ede3e580600b113777822b6d562390d14ed236e5bac3d3af63ae23015148a95e7ccbc9eea653b52c606ca09ec51fd2b0c4cfc2b760fccc1fe0ccdd9ee3fcb8129", "&'()*+,-./"},
	{"$7z$128$19$0$1122$8$70eb7f4b821cf5310000000000000000$3381356868$112$99$c26db2cb89df1237f323d92044726d03cfc7ba83115e789243c3b2570ae674d8356a23e004b103638b1ea9fe6ff5db844a1ddcaaed8a71a8d8e343f73868b4acafd34d493345439b0e0be87d2cf52eb4cceaafcff0dfaf9cf25080693ede267460320e1282b869a5f0b6c8789e769640", "&'()*+,-./0"},
	{"$7z$128$19$0$1122$8$2ac0f1307794d8e10000000000000000$2871514580$112$99$4783d91fa72c377310654e961120e71ecdd27ec2e67366e83291daefcea03514ca9ecea031fcbd25c0759c1f242219e673cee093ef361664f18dacf85ca0620fd7092477ceeff7c548df0a475ce93278a564fe4ddb4ee2e4695cbe417a792e822204390ca5a530208a8ed51bc01f79e6", "&'()*+,-./01"},
	{"$7z$128$19$0$1122$8$5bc4988c71cba8b70000000000000000$2815498089$112$99$0e4368dde66925e2bfac9a450291f8f817beaa891f08c4d2735d20b3147df581e2f3c53abfe2b0971186ac39280eb354ca5989f9043ad0288302d0ac59a3c8fa99d26c9619b81d22996f24eec1dba361afdd5e50060c2599a40a00c83c4ee0bc4ebe6e3126a64a743af95d9b22ee5867", "&'()*+,-./012"},
	{"$7z$128$19$0$1122$8$33ab0ad513b7d6910000000000000000$107430285$112$99$f9f1195a4210eadc5b23f046f81c8cfaec3b90d8b6b67893f10bd9bedd0d859d0695bca5ce315cecbc2910dce27e4c1a1416675d841901c8d84846360b1919ebcba91143713c6b755758d3db64d39344da18222341818220cc43f3ee3a91cbc288f1aafe377b53def310d3b83d32aee3", "&'()*+,-./0123"},
	{"$7z$128$19$0$1122$8$dd490a165c1b90f90000000000000000$2897354864$112$99$51efe41b67875503acebe2e199cb542a279520b468a61ba67b54612e317a84e95879a34eaad82124798f32c19f9c0786e8faaac768da5f6b2c91e3ba9f97a03a992c18b5b9b21a5f2b67ae9daeef37ec115f44bfb8b10ac3cb7862b6c024413a2ee801aa674df05e8b56bd8654f279f5", "&'()*+,-./01234"},
	{"$7z$128$19$0$1122$8$9077cb191a5969b40000000000000000$3637063426$112$99$1e74746c59bdfe6b3f3d957493c9d5b92ba358f97e19d30e20443cb2fbac0501e07a162344ac7cf7cfa727c70a2bcf52593accc5c2c070c2331863ac76da5ad2f5de374292a87c6af67ab561f9cf71ae472ed1267d481c250f5b4d82d0ec0b2b8531db1fe4637c3f4e3a08de1b9b5418", "&'()*+,-./012345"},
	{"$7z$128$19$0$1122$8$adc090d27b0343d30000000000000000$1147570982$112$99$ac14b9dc3751cfe6c1c719ceef3d73946fff2b0f924e06cd3177883df770e5505551bcf5598277801f46584a4f41530f50007c776d2bb91fd160148042275dfe4e420ff72244409f59c687a5bb2d0fc1bb29138689094fe40bb0f22785c63c631cd05abf4f7f3c9b6832e192e103d2f1", "&'()*+,-./0123456"},
	{"$7z$128$19$0$1122$8$8dee69dc35517a2a0000000000000000$87427823$112$99$ea36cf8b577a0b5f31115f8550987f05f174b347a8a6433a08c013ecd816c8ecaad163c62db9bae6c57ace3c2a6ce0b36f78ad4723328cc022906400eed55e0e3685a5e8e6b369df780ee72f3d25ccd49d7f40d013052e080723dd4c0b1c75302c884ea956e3b6fd27261eb8c49dea51", "&'()*+,-./01234567"},
	{"$7z$128$19$0$1122$8$200ce603d6f355f10000000000000000$3012105149$112$99$0ae42342f52172ad921178a25df3666e34e5a217d0afb3655088806f821d374bf522c197e59b131dbc574d4c936472f59f8892f69e47724ea52ecc5dc7d3ed734c557c9698a6f01519039714c065ad25008003c93cb7f694ee07267d5fcdebab5d149d5404023a0112faec2264d33ff6", "&'()*+,-./012345678"},
	{"$7z$128$19$0$1122$8$a5007fc77fa5cc0b0000000000000000$1082728565$112$99$32c404c9633e9c61b76556e169695248008c51ca8f7f0f79c4a271ac6eb1d905a2622132f2f6988f9f3f5e375c592ec63d92d7b183b5801b149595ed440b23a083633de9f1cb5b6ac3238b7523b23141e686e6cbe9d4d3a28fc6489e902c17aeff6cd4cb516bef5cd5c6def78cb88ad4", "&'()*+,-./0123456789"},
	{"$7z$128$19$0$1122$8$fd531c4e580be9a60000000000000000$1843420503$112$99$704289830b1add1c8ee6fd622ecf5b8da01988580bdb52f6269cc61c21838849d3a04299eaee15e0cae0eff9f6c3c82f71e434b3aa1c0ca824b90438c1c983130218acd128d9186e5dc2d19a8db602a0382cb60dadb4641b46fe532b799d29a4b882beaa9217f48ddccc99578617f8a0", "&'()*+,-./0123456789:"},
	{"$7z$128$19$0$1122$8$7f94a95f71c1b0df0000000000000000$141406606$112$99$1a510a6fda9788b4f4b2274ea929044c00b61b23946bc417ead90ad64dcc9a55378f9ab74f7d693a5dcf455c00f82f6c2a885b664f4ab10c9969026714ce2773030f1c5872ca3948cd612e21b321826c2a561104d57a3ba2055f03aa9cc264821544ec4bccc41f4ac76aab97accb8f9c", "&'()*+,-./0123456789:;"},
	{"$7z$128$19$0$1122$8$e24e93c7a9ebde080000000000000000$718561925$112$99$580bf36388526c932c22e3227b51774b6963a9c5b96fc8e2ac70a4302864fa88f50e7c00d9a79e0bca0f07a236e51200dc23435b7680e6fa99b19d790ac093af615a972f8b232686c21279234a2582f9714c5a1a2d326084158eba3e81b4f8ad40784d84baa8ddbed19f1c6603156d2c", "&'()*+,-./0123456789:;<"},
	{"$7z$128$19$0$1122$8$6fbd519735b131710000000000000000$1248418560$112$99$cc9e3c97073d7fd37f04d4e6983b386e3ac00f6292dedb0f566dccf22cdbbb55fee8669edade383e96aa0a740e2b42aa7fddbe5831cac10828c624ee03a1a256c6e777c3d714c55296cb815c509a252b9426fe8d4566c944efe3fac5ea94910e55a390aef2c729a031e832c406049810", "&'()*+,-./0123456789:;<="},
	{"$7z$128$19$0$1122$8$3ce1b899fc03d9c30000000000000000$1452122600$112$99$d4be60d5ab390713c7189f0dd808227c01f15f71fcf4bbccce6cb9238d6418c115eff59784d96ff8944575710a5799c7bcb761e8f1bfb7646a0e8fac3728ba4cca44fb82e5dd9f87bb26828566af64374b512fa094d35af8d743bded88b6257ec98a99b50dd225d4608b283bf035ac08", "&'()*+,-./0123456789:;<=>"},
	{"$7z$128$19$0$1122$8$656e2285aabed25b0000000000000000$3885982465$112$99$77f2871e556e7f5278a9e896e91cd386ca8935128957d31fdce0603ea0e71c08b908a4c2d9f2d279757ced848be9482067c9d7935c88e5233aaa94a101d29908f7f015646758029d2078d25d0886bb9f0cdc0dd5136d72e90ceeea678564b199866dd8c9e5fe927102ee2dcf1cd4167f", "&'()*+,-./0123456789:;<=>?"},
	{"$7z$128$19$0$1122$8$44ffefa48fa5a5b00000000000000000$1011653568$112$99$5d2504a1eb819218b9ad552e377d37e811ffccb64a554f404d982d209edfafb893b679cc881bbcbc606e67ffa055f712d7f140b554769511bc00321765830ea7c5db810fa2000ae7f4250b74aa61d881db66ae6f30e4c8e71887960c117b268d9934b8b5d52d4abdcb42b0e4ff40b805", "&'()*+,-./0123456789:;<=>?@"},
	{"$7z$128$19$0$1122$8$b6e089dd0c52b6b80000000000000000$1229766981$112$99$49a8334d64d9cc7d710fe3b9c35f5d7cb0ec44d5db8a90966fbee93f85fdeeeca859c55519addb20c4628c9204dd24d1169b34dc53a2a685440fae7ed6748c172a8e9dcc42c8dffe60196818ad17a6f9314fcfd4d97cab3c18cf279df344e00fd04eaff32f29cbfcdb6832cfb69fe351", "&'()*+,-./0123456789:;<=>?@A"},
#endif /* DEBUG */
	{NULL}
};

static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int *cracked;
static int new_keys;
static int max_kpc;
static unsigned char (*master)[32];
#ifdef SIMD_COEF_32
static uint32_t (*vec_in)[2][NBKEYS*16];
static uint32_t (*vec_out)[NBKEYS*8];
static int *indices;
#endif

static struct custom_salt {
	dyna_salt dsalt;
	size_t length;     /* used in decryption */
	size_t unpacksize; /* used in padding check */
	size_t crc_len;    /* used in CRC calculation */
	int NumCyclesPower;
	int SaltSize;
	int ivSize;
	int type;
	unsigned char iv[16];
	unsigned char salt[16];
	unsigned int crc;
	unsigned char props[LZMA_PROPS_SIZE];
	unsigned char data[1];
} *cur_salt;

static void init(struct fmt_main *self)
{
	CRC32_t crc;

	omp_autotune(self, OMP_SCALE);

	// allocate 1 more slot to handle the tail of vector buffer
	max_kpc = self->params.max_keys_per_crypt + 1;

	saved_key = mem_calloc(max_kpc, sizeof(*saved_key));
	saved_len = mem_calloc(max_kpc, sizeof(*saved_len));
	cracked   = mem_calloc(max_kpc, sizeof(*cracked));
#ifdef SIMD_COEF_32
	vec_in  = mem_calloc_align(self->params.max_keys_per_crypt,
	                           sizeof(*vec_in), MEM_ALIGN_CACHE);
	vec_out = mem_calloc_align(self->params.max_keys_per_crypt,
	                           sizeof(*vec_out), MEM_ALIGN_CACHE);
#endif
	CRC32_Init(&crc);

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(master);
#ifdef SIMD_COEF_32
	MEM_FREE(vec_in);
	MEM_FREE(vec_out);
	MEM_FREE(indices);
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int type, len, NumCyclesPower;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto err;
	if (strlen(p) > 3 || !isdec(p))
		goto err;
	type = atoi(p);
	if (strlen(p) == 0 || type < 0 || type > 128) /* Compression type */
		goto err;
	if (type > 2 && type != 128) /* none, LZMA or LZMA2 */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* NumCyclesPower */
		goto err;
	if (strlen(p) > 2)
		goto err;
	if (!isdec(p))
		goto err;
	NumCyclesPower = atoi(p);
	if (NumCyclesPower > 24 || NumCyclesPower < 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > 16) /* salt length */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iv length */
		goto err;
	if (strlen(p) > 2)
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > 16) /* iv length */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iv */
		goto err;
	if (!ishexlc(p))
		goto err;
	if (strlen(p) / 2 > len && strcmp(p+len*2, "0000000000000000"))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* crc */
		goto err;
	if (!isdecu(p) && !isdec_negok(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* data length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* unpacksize */
		goto err;
	if (!isdec(p))	/* no way to validate, other than atoi() works for it */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* data */
		goto err;
	if (strlen(p) / 2 != len)	/* validates data_len atoi() */
		goto err;
	if (!ishexlc(p))
		goto err;
	if (type && type != 128) {
		if ((p = strtokm(NULL, "$")) == NULL) /* CRC len */
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL) /* Coder props */
			goto err;
		if (!ishexlc(p))
			goto err;
		if (type == 1 && strlen(p) != 10)
			goto err;
		else if (type == 2 && strlen(p) != 2)
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
	struct custom_salt cs;
	struct custom_salt *psalt;
	static void *ptr;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;

	if (!ptr)
		ptr = mem_alloc_tiny(sizeof(struct custom_salt*),
		                     sizeof(struct custom_salt*));
	memset(&cs, 0, sizeof(cs));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.type = atoi(p);
	p = strtokm(NULL, "$");
	cs.NumCyclesPower = atoi(p);
	p = strtokm(NULL, "$");
	cs.SaltSize = atoi(p);
	p = strtokm(NULL, "$"); /* salt */
	p = strtokm(NULL, "$");
	cs.ivSize = atoi(p);
	p = strtokm(NULL, "$"); /* iv */
	for (i = 0; i < cs.ivSize; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); /* crc */
	cs.crc = atou(p); /* unsigned function */
	p = strtokm(NULL, "$");
	cs.length = atoll(p);
	psalt = malloc(sizeof(struct custom_salt) + cs.length - 1);
	memcpy(psalt, &cs, sizeof(cs));
	p = strtokm(NULL, "$");
	psalt->unpacksize = atoll(p);
	p = strtokm(NULL, "$"); /* data */
	for (i = 0; i < psalt->length; i++)
		psalt->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	if (cs.type && cs.type != 128) {
		p = strtokm(NULL, "$"); /* CRC length */
		psalt->crc_len = atoi(p);
		p = strtokm(NULL, "$"); /* Coder properties */
		for (i = 0; p[i * 2] ; i++)
			psalt->props[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	MEM_FREE(keeptr);
	psalt->dsalt.salt_cmp_offset = SALT_CMP_OFF(struct custom_salt, length);
	psalt->dsalt.salt_cmp_size = SALT_CMP_SIZE(struct custom_salt, length, data, psalt->length);
	psalt->dsalt.salt_alloc_needs_free = 1;

	memcpy(ptr, &psalt, sizeof(void*));
	return ptr;
}

static void set_salt(void *salt)
{
	static int old_power;

	cur_salt = *((struct custom_salt**)salt);

	if (old_power != cur_salt->NumCyclesPower) {
		new_keys = 1;
		old_power = cur_salt->NumCyclesPower;
	}
}

static int salt_compare(const void *x, const void *y)
{
	int c;
	const struct custom_salt *s1 = *((struct custom_salt**)x);
	const struct custom_salt *s2 = *((struct custom_salt**)y);

	// we had to make the salt order deterministic, so that intersalt-restore works
	if (s1->NumCyclesPower != s2->NumCyclesPower)
		return (s1->NumCyclesPower - s2->NumCyclesPower);
	c = memcmp(s1->salt, s2->salt, 16);
	if (c) return c;
	return memcmp(s1->iv, s2->iv, 16);
}

static void *SzAlloc(void *p, size_t size) { return mem_alloc(size); }
static void SzFree(void *p, void *address) { MEM_FREE(address) };

static int sevenzip_decrypt(unsigned char *derived_key)
{
	unsigned char *out = NULL;
	AES_KEY akey;
	unsigned char iv[16];
	union {
		unsigned char crcc[4];
		unsigned int crci;
	} _crc_out;
	unsigned char *crc_out = _crc_out.crcc;
	unsigned int ccrc;
	CRC32_t crc;
	int i;
	int nbytes, pad_size;
	size_t crc_len = cur_salt->unpacksize;
	size_t aes_len = cur_salt->crc_len ?
		(cur_salt->crc_len * 11 + 150) / 160 * 16 : crc_len;

	pad_size = nbytes = cur_salt->length - cur_salt->unpacksize;

	/*
	 * Early rejection (only decrypt last 16 bytes). We don't seem to
	 * be able to trust this, see #2532, so we only do it for truncated
	 * hashes (it's the only thing we can do!).
	 */
	if ((cur_salt->type == 0x80 || TRUST_PADDING) &&
	    pad_size > 0 && cur_salt->length >= 32) {
		uint8_t buf[16];

		memcpy(iv, cur_salt->data + cur_salt->length - 32, 16);
		AES_set_decrypt_key(derived_key, 256, &akey);
		AES_cbc_encrypt(cur_salt->data + cur_salt->length - 16, buf,
		                16, &akey, iv, AES_DECRYPT);
		i = 15;
		while (nbytes > 0) {
			if (buf[i] != 0)
				return 0;
			nbytes--;
			i--;
		}

		if (cur_salt->type == 0x80) /* We only have truncated data */
			return 1;
	}

	/* Complete decryption, or partial if possible */
	aes_len = nbytes ? cur_salt->length : MIN(aes_len, cur_salt->length);
	out = mem_alloc(aes_len);
	memcpy(iv, cur_salt->iv, 16);
	AES_set_decrypt_key(derived_key, 256, &akey);
	AES_cbc_encrypt(cur_salt->data, out, aes_len, &akey, iv, AES_DECRYPT);

	/* Padding check unless we already did the quick one */
	if (TRUST_PADDING && nbytes) {
		i = cur_salt->length - 1;
		while (nbytes > 0) {
			if (out[i] != 0)
				goto exit_bad;
			nbytes--;
			i--;
		}
	}

	if (cur_salt->type == 0x80) /* We only have truncated data */
		goto exit_good;

	/* Optional decompression before CRC */
	if (cur_salt->type == 1) {
		ISzAlloc st_alloc = {SzAlloc, SzFree};
		ELzmaStatus status;
		size_t in_size = aes_len;
		uint8_t *new_out;
		SRes rc;
		size_t out_size = cur_salt->crc_len;

		new_out = mem_alloc(out_size);
		if ((rc = LzmaDecode(new_out, &out_size, out, &in_size,
		                     cur_salt->props, LZMA_PROPS_SIZE,
		                     LZMA_FINISH_ANY, &status,
		                     &st_alloc)) == SZ_OK &&
		    out_size == cur_salt->crc_len) {
			MEM_FREE(out);
			out = new_out;
			crc_len = cur_salt->crc_len;
		} else {
			MEM_FREE(new_out);
			goto exit_bad;
		}
	}
	else if (cur_salt->type == 2) {
		Byte prop = cur_salt->props[0];
		ISzAlloc st_alloc = {SzAlloc, SzFree};
		ELzmaStatus status;
		size_t in_size = aes_len;
		uint8_t *new_out;
		SRes rc;
		size_t out_size = cur_salt->crc_len;

		new_out = mem_alloc(out_size);
		if ((rc = Lzma2Decode((Byte*)new_out, &out_size, out, &in_size,
		                      prop, LZMA_FINISH_ANY, &status,
		                      &st_alloc)) == SZ_OK &&
		    out_size == cur_salt->crc_len) {
			MEM_FREE(out);
			out = new_out;
			crc_len = cur_salt->crc_len;
		} else {
			MEM_FREE(new_out);
			goto exit_bad;
		}
	}

	/* CRC test */
	CRC32_Init(&crc);
	CRC32_Update(&crc, out, crc_len);
	CRC32_Final(crc_out, crc);
	ccrc =  _crc_out.crci; /* computed CRC */
#if !ARCH_LITTLE_ENDIAN
	ccrc = JOHNSWAP(ccrc);
#endif
	if (ccrc == cur_salt->crc)
		goto exit_good;

exit_bad:
	MEM_FREE(out);
	return 0;

exit_good:
	MEM_FREE(out);
	return 1;
}

#ifdef SIMD_COEF_32
static void sevenzip_kdf(int buf_idx, int *indices, unsigned char *master)
{
	int i, j;
	long long round, rounds = (long long) 1 << cur_salt->NumCyclesPower;
	uint32_t (*buf_in)[NBKEYS*16] = vec_in[buf_idx];
	uint32_t *buf_out = vec_out[buf_idx];
	int pw_len = saved_len[indices[0]];
	int tot_len = (pw_len + 8)*rounds;
	int acc_len = 0;
#if !ARCH_LITTLE_ENDIAN
	unsigned char temp[8] = { 0,0,0,0,0,0,0,0 };
#endif

	int cur_buf = 0;
	int fst_blk = 1;

	// it's assumed rounds is divisible by 64
	for (round = 0; round < rounds; ++round) {
		// copy password to vector buffer
		for (i = 0; i < NBKEYS; ++i) {
			UTF16 *buf = saved_key[indices[i]];
			for (j = 0; j < pw_len; ++j) {
				int len = acc_len + j;
				char *in = (char*)buf_in[(len & 64)>>6];
				in[GETPOS(len%64, i)] = ((char*)buf)[j];
			}

			for (j = 0; j < 8; ++j) {
				int len = acc_len + pw_len + j;
				char *in = (char*)buf_in[(len & 64)>>6];
#if ARCH_LITTLE_ENDIAN
				in[GETPOS(len%64, i)] = ((char*)&round)[j];
#else
				in[GETPOS(len%64, i)] = temp[j];
#endif
			}
		}
#if !ARCH_LITTLE_ENDIAN
		for (j = 0; j < 8; j++)
			if (++(temp[j]) != 0)
				break;
#endif
		acc_len += (pw_len + 8);

		// swap out and compute digest on the filled buffer
		if ((acc_len & 64) != (cur_buf << 6)) {
			if (fst_blk)
				SIMDSHA256body(buf_in[cur_buf], buf_out, NULL, SSEi_MIXED_IN);
			else
				SIMDSHA256body(buf_in[cur_buf], buf_out, buf_out, SSEi_MIXED_IN | SSEi_RELOAD);
			fst_blk = 0;
			cur_buf = 1 - cur_buf;
		}
	}

	// padding
	memset(buf_in[0], 0, sizeof(buf_in[0]));
	for (i = 0; i < NBKEYS; ++i) {
		buf_in[0][HASH_IDX_IN(i)] = (0x80U << 24);
		buf_in[0][HASH_IDX_IN(i) + 15*SIMD_COEF_32] = tot_len*8;
	}
	SIMDSHA256body(buf_in[0], buf_out, buf_out, SSEi_MIXED_IN | SSEi_RELOAD);

	// copy out result
	for (i = 0; i < NBKEYS; ++i) {
		uint32_t *m = (uint32_t*)&master[i*32];
		for (j = 0; j < 32/4; ++j)
			m[j] = JOHNSWAP(buf_out[HASH_IDX_OUT(i) + j*SIMD_COEF_32]);
	}
}
#else
static void sevenzip_kdf(int index, unsigned char *master)
{
	long long rounds = (long long) 1 << cur_salt->NumCyclesPower;
	long long round;
#if !ARCH_LITTLE_ENDIAN
	int i;
	unsigned char temp[8] = { 0,0,0,0,0,0,0,0 };
#endif
	SHA256_CTX sha;

	/* kdf */
	SHA256_Init(&sha);
	for (round = 0; round < rounds; round++) {
		if (cur_salt->SaltSize)
			SHA256_Update(&sha, cur_salt->salt, cur_salt->SaltSize);
		SHA256_Update(&sha, (char*)saved_key[index], saved_len[index]);
#if ARCH_LITTLE_ENDIAN
		SHA256_Update(&sha, (char*)&round, 8);
#else
		SHA256_Update(&sha, temp, 8);
		for (i = 0; i < 8; i++)
			if (++(temp[i]) != 0)
				break;
#endif
	}
	SHA256_Final(master, &sha);
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef SIMD_COEF_32
	static int tot_todo;
	int len;

	/* Tricky formula, see GitHub #1692 :-) */
	if (!indices)
		indices = mem_alloc((max_kpc + MIN(PLAINTEXT_LENGTH + 1, max_kpc) *
		                     (NBKEYS - 1)) * sizeof(int));
	if (!master)
		master =  mem_alloc((max_kpc + MIN(PLAINTEXT_LENGTH + 1, max_kpc) *
		                     (NBKEYS - 1)) * sizeof(*master));
#else
	if (!master)
		master =  mem_alloc(max_kpc * sizeof(*master));
#endif

#ifdef SIMD_COEF_32
	if (new_keys) {
		// sort passwords by length
		tot_todo = 0;
		for (len = 0; len <= PLAINTEXT_LENGTH*2; len += 2) {
			for (index = 0; index < count; ++index) {
				if (saved_len[index] == len)
					indices[tot_todo++] = index;
			}
			while (tot_todo % NBKEYS)
				indices[tot_todo++] = count;
		}
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < tot_todo; index += NBKEYS) {
		int j;

		if (new_keys)
			sevenzip_kdf(index/NBKEYS, indices + index, master[index]);

		/* do decryption and checks */
		for (j = 0; j < NBKEYS; ++j) {
			cracked[indices[index + j]] = sevenzip_decrypt(master[index + j]);
		}
	}
#else
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		/* derive key */
		if (new_keys)
			sevenzip_kdf(index, master[index]);

		/* do decryption and checks */
		cracked[index] = sevenzip_decrypt(master[index]);
	}
#endif // SIMD_COEF_32
	new_keys = 0;

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

static void sevenzip_set_key(char *key, int index)
{
	/* Convert key to utf-16-le format (--encoding aware) */
	int len;
	len = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
	if (len <= 0) {
		key[-len] = 0; // match truncation
		len = strlen16(saved_key[index]);
	}
	len *= 2;
	saved_len[index] = len;

	new_keys = 1;
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = *((struct custom_salt **)salt);
	return (unsigned int)(1 << my_salt->NumCyclesPower);
}

static unsigned int padding_size(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = *((struct custom_salt **)salt);
	return my_salt->length - my_salt->unpacksize;
}

static unsigned int compression_type(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = *((struct custom_salt **)salt);
	return my_salt->type;
}

struct fmt_main fmt_sevenzip = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8 | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"iteration count",
			"padding size",
			"compression type",
		},
		{ FORMAT_TAG },
		sevenzip_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
			padding_size,
			compression_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		salt_compare,
		set_salt,
		sevenzip_set_key,
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

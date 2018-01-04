/*
 * This software is Copyright (c) 2015-2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

/*
 * We've seen one single sample where we could not trust the padding check
 * (early rejection). To be able to crack such hashes, define this to 0.
 * This hits performance in some cases.
 */
#define TRUST_PADDING 0

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_sevenzip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_sevenzip);
#else

#include <stdint.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "common-opencl.h"
#include "options.h"
#include "aes.h"
#include "crc32.h"
#include "unicode.h"
#include "dyna_salt.h"
#include "lzma/LzmaDec.h"
#include "lzma/Lzma2Dec.h"
#include "memdbg.h"

#define FORMAT_LABEL		"7z-opencl"
#define FORMAT_NAME		"7-Zip"
#define FORMAT_TAG		"$7z$"
#define TAG_LENGTH		(sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME		"SHA256 AES OPENCL"
#define BENCHMARK_COMMENT	" (512K iterations)"
#define BENCHMARK_LENGTH	-1000
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define PLAINTEXT_LENGTH	((55-8)/2) // 23, rar3 uses 22
#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define SALT_SIZE		sizeof(struct custom_salt*)
#define SALT_ALIGN		sizeof(struct custom_salt*)

typedef struct {
	uint32_t length;
	uint16_t v[PLAINTEXT_LENGTH];
} sevenzip_password;

typedef struct {
	uint32_t key[32/4];
	uint32_t round;
	uint32_t reject;
} sevenzip_hash;

typedef struct {
	size_t length;
	size_t unpacksize;
	uint32_t iterations;
	//uint32_t salt_size;
	//uint8_t salt[16];
	uint8_t data[32]; /* Last two blocks of data */
} sevenzip_salt;

typedef struct {
	cl_uint total[2];
	cl_uint state[8];
	cl_uchar buffer[64];
} SHA256_CTX;

typedef struct {
	cl_ulong t;
	SHA256_CTX ctx;
	cl_uint len;
	cl_ushort buffer[PLAINTEXT_LENGTH];
} sevenzip_state;

static int *cracked;
static int any_cracked;
static int new_keys;

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
#if DEBUG
	{"$7z$128$19$0$1122$8$94fb9024fdd3e6c40000000000000000$3965424295$112$99$1127828817ff126bc45ff3c5225d9d0c5d00a52094909674e6ed3dc431546d9a672738f2fa07556340d604d2efd2901b9d2ac2c0686c25af9c520c137b16c50c54df8703fd0b0606fa721ad70aafb9c4e3b288ef49864e6034021969b4ce11e3b8e269a92090ccf593c6a0da06262116", ""},
	{"$7z$128$19$0$1122$8$6fd059d516d5490f0000000000000000$460747259$112$99$af163eb5532c557efca78fbb448aa04f348cd258c94233e6669f4e5025f220274c244d4f2347a7512571d9b6015a1e1a90e281983b743da957437b33092eddb55a5bc76f3ab6c7dbabb001578d1043285f5fa791fd94dd9779b461e44cbfe869f891007335b766774ccee3813ec8cd57", "&"},
	{"$7z$128$19$0$1122$8$6d4a12af68d83bfe0000000000000000$993697592$112$99$7c308faa36b667599ee4418435ab621884c5c115ee3b70be454fe99236422f4f2d5cd9c8fcfbe6b6b0805ee602ce8488a08f7ea14a4f5c0c060fc685bff187720a402b23a5cfe3c9c5a5ae07f91209031b8f9804ac10459e15a0158031f6c58e507401ec6e1e6de8f64d94201159432b", "&'"},
	{"$7z$128$19$0$1122$8$7527d758a59181830000000000000000$3917710544$112$99$61a9ca9e835bd0f2dc474b34d5d89bcf8cd1bb071a984ee1dcf224174a60bcee140fcf2fde8927fe4f3f4eb4a2cc39faff73f1898ae25cc92bd02939f4317ebb173bf3b6f01eef183163ddd533ad5c076f87341bd8b86d8460c68fc390aa8df89fc4076bdfd24e157f6c07e105c07612", "&'("},
	{"$7z$128$19$0$1122$8$68928bade860a2b80000000000000000$3235890186$112$99$4b685a569c3aed78d217bae9ec64fa06b614df55c1cb0d160563d87efe38813accb38dd7037f86cebc91751c2488769c7398dfefaf491c024f2d640dcb388a56404cd5ac475ba16b5f8206fa45d5923b3a0c8dd0f24460ccee0d93bea03ad58b8a8db502a55ba1775560b3d194f342f7", "&'()"},
	{"$7z$128$19$0$1122$8$81931b9ba0b069820000000000000000$3094344848$112$99$fdbb2622143d25b13992b1467ce9edce4e3df8ca07535735b76e8abcb0791e384a1d5547483e19c3bd6e5a0742d29c403cfc8b3a003b285e80b350ea9157600eb91c49b329903de9ec9b17d1c95b0e136b579e165a6e80550464fa99830bfd9ee58fc14516b614ff9f84ec80e6880a36", "&'()*"},
	{"$7z$128$19$0$1122$8$ccf696913989510d0000000000000000$1238556212$112$99$647264fbc665e73ecfe3ef7055fef0d91cb86833d6df08b2f7a3c1c89cf7cdaa09a802c8bfb2e5c6b55143a315df74d841b349fc8b43613d0f87cc90325fd56fc17ee08df7ce76cdc9cda61bd4d5632e20af3db16e921c755174f291c0aa6581844def4547380e2dd4a574435d17e1e8", "&'()*+"},
	{"$7z$128$19$0$1122$8$d618bd3ec8bafd800000000000000000$1349785$112$99$6514e2e7468e6f0ed63796cfc0588ac2d75f024c4a0fa03778bd252d316d03e48a08ffcc0011725ad4f867e9a9666630dff4f352c59bcbadb94b9d0e2c42d653b80f480005ce868a0b1a075b2e00abd743de0867d69cdc8b56c7f9770537d50e6bb11eb0d2d7d8b6af5dd8ecb50ab553", "&'()*+,"},
	{"$7z$128$19$0$1122$8$1c1586d191f190890000000000000000$642253888$112$99$f55cf9ab802b10a83471abe9319711ae79906cd6921365167c389470a3a8a72b0d877379daae2c24ea2258e8586f12d5036aff9ddc8e26861467b0843ffb72e4410c2be76ec111d37f875c81b244ed172f1f4765a220d830a9615787e9d07f8582146556e9c566b64897a47d18a82b36", "&'()*+,-"},
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
#if PLAINTEXT_LENGTH > 23
	{"$7z$128$19$0$1122$8$6fbd519735b131710000000000000000$1248418560$112$99$cc9e3c97073d7fd37f04d4e6983b386e3ac00f6292dedb0f566dccf22cdbbb55fee8669edade383e96aa0a740e2b42aa7fddbe5831cac10828c624ee03a1a256c6e777c3d714c55296cb815c509a252b9426fe8d4566c944efe3fac5ea94910e55a390aef2c729a031e832c406049810", "&'()*+,-./0123456789:;<="},
	{"$7z$128$19$0$1122$8$3ce1b899fc03d9c30000000000000000$1452122600$112$99$d4be60d5ab390713c7189f0dd808227c01f15f71fcf4bbccce6cb9238d6418c115eff59784d96ff8944575710a5799c7bcb761e8f1bfb7646a0e8fac3728ba4cca44fb82e5dd9f87bb26828566af64374b512fa094d35af8d743bded88b6257ec98a99b50dd225d4608b283bf035ac08", "&'()*+,-./0123456789:;<=>"},
	{"$7z$128$19$0$1122$8$656e2285aabed25b0000000000000000$3885982465$112$99$77f2871e556e7f5278a9e896e91cd386ca8935128957d31fdce0603ea0e71c08b908a4c2d9f2d279757ced848be9482067c9d7935c88e5233aaa94a101d29908f7f015646758029d2078d25d0886bb9f0cdc0dd5136d72e90ceeea678564b199866dd8c9e5fe927102ee2dcf1cd4167f", "&'()*+,-./0123456789:;<=>?"},
	{"$7z$128$19$0$1122$8$44ffefa48fa5a5b00000000000000000$1011653568$112$99$5d2504a1eb819218b9ad552e377d37e811ffccb64a554f404d982d209edfafb893b679cc881bbcbc606e67ffa055f712d7f140b554769511bc00321765830ea7c5db810fa2000ae7f4250b74aa61d881db66ae6f30e4c8e71887960c117b268d9934b8b5d52d4abdcb42b0e4ff40b805", "&'()*+,-./0123456789:;<=>?@"},
	{"$7z$128$19$0$1122$8$b6e089dd0c52b6b80000000000000000$1229766981$112$99$49a8334d64d9cc7d710fe3b9c35f5d7cb0ec44d5db8a90966fbee93f85fdeeeca859c55519addb20c4628c9204dd24d1169b34dc53a2a685440fae7ed6748c172a8e9dcc42c8dffe60196818ad17a6f9314fcfd4d97cab3c18cf279df344e00fd04eaff32f29cbfcdb6832cfb69fe351", "&'()*+,-./0123456789:;<=>?@A"},
#endif /* PLAINTEXT_LENGTH > 23 */
#endif /* DEBUG */
	{NULL}
};

static sevenzip_password *inbuffer;
static sevenzip_hash *outbuffer;
static sevenzip_salt currentsalt;
static cl_mem mem_in, mem_out, mem_salt;
static cl_kernel sevenzip_init, sevenzip_final, sevenzip_aes;

#define insize (sizeof(sevenzip_password) * global_work_size)
#define outsize (sizeof(sevenzip_hash) * global_work_size)
#define statesize (sizeof(sevenzip_state) * global_work_size)
#define saltsize sizeof(sevenzip_salt)
#define cracked_size (sizeof(*cracked) * global_work_size)

static struct fmt_main *self;

#define HASH_LOOPS	0x4000
#define LOOP_COUNT	((1 << currentsalt.iterations) / HASH_LOOPS)
#define STEP		0
#define SEED		16

static int split_events[] = { 2, -1, -1 };

static const char *warn[] = {
	"xfer: ",  ", init: ",  ", crypt: ",  ", final: ",  ", aes: ",  ", xfer: "
};

// This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, sevenzip_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, sevenzip_final));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, sevenzip_aes));
	return s;
}

static void create_clobj(size_t global_work_size, struct fmt_main *self)
{
	cl_int cl_error;

	inbuffer = (sevenzip_password*) mem_calloc(1, insize);
	outbuffer = (sevenzip_hash*) mem_alloc(outsize);

	cracked = mem_calloc(1, cracked_size);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem salt");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(sevenzip_init, 0, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(sevenzip_final, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(sevenzip_final, 1, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(sevenzip_final, 2, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(sevenzip_aes, 0, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(sevenzip_aes, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		MEM_FREE(cracked);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(sevenzip_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(sevenzip_final), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(sevenzip_aes), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void init(struct fmt_main *_self)
{
	CRC32_t crc;

	self = _self;
	opencl_prepare_dev(gpu_id);

	CRC32_Init(&crc);

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];
		cl_int cl_error;

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DHASH_LOOPS=%d",
		         PLAINTEXT_LENGTH, HASH_LOOPS);
		opencl_init("$JOHN/kernels/7z_kernel.cl",
		            gpu_id, build_opts);

		sevenzip_init = clCreateKernel(program[gpu_id], "sevenzip_init",
		                               &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		crypt_kernel = clCreateKernel(program[gpu_id], "sevenzip_loop",
		                              &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		sevenzip_final = clCreateKernel(program[gpu_id], "sevenzip_final",
		                               &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		sevenzip_aes = clCreateKernel(program[gpu_id], "sevenzip_aes",
		                              &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
		                       warn, 2, self,
		                       create_clobj, release_clobj,
		                       sizeof(sevenzip_state), 0, db);

		//  Auto tune execution from shared/included code.
		autotune_run(self, 1 << 19, 0, 15000000000ULL);
	}
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
	if (len != 0) /* salt length, we currently only support it in CPU format */
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
	if (!isdecu(p))
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
	cur_salt = *((struct custom_salt **)salt);

	//memcpy(currentsalt.salt, cur_salt->salt, cur_salt->SaltSize);
	//currentsalt.salt_size = cur_salt->SaltSize;

	if (currentsalt.iterations != cur_salt->NumCyclesPower)
		new_keys = 1;

	if (cur_salt->length >= 32)
		memcpy(currentsalt.data, cur_salt->data + cur_salt->length - 32, 32);

	currentsalt.length = cur_salt->length;
	currentsalt.unpacksize = cur_salt->unpacksize;
	currentsalt.iterations = cur_salt->NumCyclesPower;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, &currentsalt, 0, NULL, NULL),
		"Transfer salt to gpu");
}

static void clear_keys(void)
{
	memset(inbuffer, 0, insize);
}

static void sevenzip_set_key(char *key, int index)
{
	UTF16 c_key[PLAINTEXT_LENGTH + 1];
	int length = strlen(key);

	/* Convert password to utf-16-le format (--encoding aware) */
	length = enc_to_utf16(c_key, PLAINTEXT_LENGTH,
	                      (UTF8*)key, length);
	if (length <= 0)
		length = strlen16(c_key);
	length *= 2;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, c_key, length);

	new_keys = 1;
}

static char *get_key(int index)
{
	UTF16 c_key[PLAINTEXT_LENGTH + 1];
	int length = inbuffer[index].length;

	memcpy(c_key, inbuffer[index].v, length);
	c_key[length / 2] = 0;

	return (char*)utf16_to_enc(c_key);
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

static int sevenzip_decrypt(sevenzip_hash *derived)
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
	size_t crc_len = cur_salt->unpacksize;
	size_t aes_len = cur_salt->crc_len ?
		(cur_salt->crc_len * 11 + 150) / 160 * 16 : crc_len;

	/*
	 * Early rejection (only decrypt last 16 bytes). We don't seem to
	 * be able to trust this, see #2532, so we only do it for truncated
	 * hashes (it's the only thing we can do!).
	 */
	if ((TRUST_PADDING || cur_salt->type == 0x80) && derived->reject)
		return 0;

	if (cur_salt->type == 0x80) /* We only have truncated data */
		return 1;

	/* Complete decryption, or partial if possible */
	aes_len = MIN(aes_len, cur_salt->length);
	out = mem_alloc(aes_len);
	memcpy(iv, cur_salt->iv, 16);
	AES_set_decrypt_key((unsigned char*)derived->key, 256, &akey);
	AES_cbc_encrypt(cur_salt->data, out, aes_len, &akey, iv, AES_DECRYPT);

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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	//fprintf(stderr, "%s(%d) lws %zu gws %zu\n", __FUNCTION__, count, local_work_size, global_work_size);

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	if (ocl_autotune_running || new_keys) {
		int i;

		global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

		// Copy data to gpu
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		// Run 1st kernel
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], sevenzip_init, 1,
			NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]),
			"Run init kernel");

		// Run loop kernel
		for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
				crypt_kernel, 1, NULL, &global_work_size, lws, 0,
				NULL, multi_profilingEvent[2]),
				"Run loop kernel");
			BENCH_CLERROR(clFinish(queue[gpu_id]),
				"Error running loop kernel");
			opencl_process_event();
		}

		// Run final kernel
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], sevenzip_final, 1,
			NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]),
			"Run final loop kernel");
	}

	new_keys = 0;

	if (TRUST_PADDING || cur_salt->type == 0x80) {
		// Run AES kernel (only for truncated hashes)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], sevenzip_aes, 1,
			NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[4]),
			"Run AES kernel");
	}

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[5]),
		"Copy result back");

	if (!ocl_autotune_running) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (index = 0; index < count; index++) {
			/* decrypt and check */
			if ((cracked[index] = sevenzip_decrypt(&outbuffer[index])))
			{
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
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

struct fmt_main fmt_opencl_sevenzip = {
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
		reset,
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
		clear_keys,
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

#endif /* HAVE_OPENCL */

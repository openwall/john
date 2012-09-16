/* SXC cracker patch for JtR. Hacked together during Summer of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
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
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"sxc"
#define FORMAT_NAME		"SXC SHA-1 Blowfish"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		20
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests sxc_tests[] = {
	{"$sxc$*0*0*1024*16*4448359828281a1e6842c31453473abfeae584fb*8*dc0248bea0c7508c*16*1d53770002fe9d8016064e5ef9423174*860*864*f00399ab17b9899cd517758ecf918d4da78099ccd3557aef5e22e137fd5b81f732fc7c167c4de0cf263b4f82b50e3d6abc65da613a36b0025d89e1a09adeb4106da28040d1019bb4b36630fc8bc94fe5b515504bf8a92ea630bb95ace074868e7c10743ec970c89895f44b975a30b6ca032354f3e73ec86b2cc7a4f7a185884026d971b37b1e0e650376a2552e27ba955c700f8903a82a6df11f6cc2ecf63290f02ffdd278f890d1db75f9e8bd0f437c4ec613d3c6dcb421bbd1067be633593ba9bd58f77ef08e0cca64c732f892567d20de8d4c444fa9c1c1adc5e4657ef9740cb69ce55c8f9e6b1cfed0739ef002f1e1c1e54a5df50a759d92354f78eb90a9d9378f36df7d1edd8002ea0d637604fcd2408494c2d42b1771e2a2a20b55044836f76db4ed71e8a53f55a04f9437946603e7246c2d2d70caf6be0de82e8977fab4de84ca3783baedac041195d8b51166b502ff80c17db78f63d3632df1d5ef5b14d8d5553fc40b072030f9e3374c93e929a490c6cfb170f04433fc46f43b9c7d27f3f8c4ed759d4a20c2e53a0701b7c3d9201390a9b5597ce8ba35bd765b662e2242b9821bbb63b6be502d2150fff37e4b7f2a6b592fd0e319a7349df320e7fe7da600a2a05628dc00e04d480c085417f676bd0518bc39d9a9be34fc0cb192d5fa5e0c657cdf7c1ad265a2e81b90ac8b28d326f98b8f33c123df83edc964d2c17a904d0df8bd9ecbf629929d6e48cadc97f49a8941ada3d219e8c0f04f37cecc9a50cc5307fd2a488c34829b05cd1615ae0d1ef0ce450529aa755f9ae38332187ffe4144990de3265afaacb9f0f0fb9c67f6210369f7a0cc5bb346412db08e0f4732f91aa8d4b32fe6eece4fba118f118f6df2fb6c53fa9bc164c9ab7a9d414d33281eb0c3cd02abe0a4dd1c170e41c1c960a8f12a48a7b5e1f748c08e1b150a4e389c110ea3368bc6c6ef2bee98dc92c6825cbf6aee20e690e116c0e6cf48d49b38035f6a9b0cd6053b9f5b9f8360024c9c608cbba3fe5e7966b656fa08dec3e3ce3178a0c0007b7d177c7c44e6a68f4c7325cb98264b1e0f391c75a6a8fd3691581fb68ef459458830f2138d0fd743631efd92b742dfeb62c5ea8502515eb65af414bf805992f9272a7b1b745970fd54e128751f8f6c0a4d5bc7872bc09c04037e1e91dc7192d68f780cdb0f7ef6b282ea883be462ffeffb7b396e30303030", "openwall"},
	{"$sxc$*0*0*1024*16*64983af0b26a6ee614e6c65b32c1d906f70c6397*8*259cafe530bd09f8*16*8f53ea878d0795cfe05dcc65fb272c20*1024*1024*ffb0f736b69d8433f958e8f475f609948ad7c9dd052f2b92c14cb1b395ffcac043a3def76d58442e131701b3b53d56ea570633bb20c83068542420160f5db3cee5eece05b67b54d0d4cdf3fbfd928d94852924e391aa3f70cad598b48b946399b0cd1e9e7e7d081a888933f8a1973e83166799396e8290771463c623620b51fb5310b9b0e0de3e5597b66a091301ada3ba6a5d7515d1fcf0eff65e543b50f8fe2222619600054eaf69c7aa680c96bc403f115cab32d6d8e8bc0db3904a71ce3eb1283ca73fd6f75845d9b7d0275e4727a0f56bfbf962a9079f51849de2c9dee7f1dadbbae944f442169281004773309b0f8d68f2cf83076fd8b19afbccf5ab7dc58fb9554fee82e2c491d6434a4cef6f3209775343c840bc4bdfab6705000e67412ac74d00f5b6aba1fd21bca5213234a5a1100a9d93daa141a4936723ea77d008a35c9078167a3529706432b36b9ec012c060d093535c85ca6feb75165d620d7d663c3e76b9bf3af614556ed8560b446a8a73649cb935383a30b4fd8fd75522203e4575cf4bc2b7f01a9294310fe021c71acbf68f6f1e95f48c30c14151c51d4fb878a16272ee73753bc750cbd48007c842412ca1dcb6214215b082c00d619a5318e2ebe9149410f501170093784afc2bd71dd9f5a87b349b96661747b1627e8cba8a5c98559fb146fa7e30db4c6f648ce3c2209f84551a7a1cd46d9172ae1354b6d093f89f6f5f58d29c1d7af8830df62e67753caa8166322caa0f8adf4b61d2013d35baa7c002e1d4c83b1cba8aaa57cf4946627fa63ba7a6a5a5c803e8d5a4794845ab670ef950b918a360cd9f12e8f3424ecab1f505cb494ad35f28d12ff183471d0f47bd67e6abd3b8c8e206d11149474a19b5c13d165d8f6dc39cf579fe1000295328aeeb82e0ae8020d2f61e4c3d6e68c25a655ab72aad5e9e74af4cf27c74158fdb1a29a3d76cd658976fa0a30743247408df00a23b593f68861348a6c46af05d21a4b81fedbf5715462ec8ffc5f001a85c43058ac1fab488236588ef0bf08dd8dd7c7fce630a0a996395b503647d9a2f0dd63dd2f939eca8e1849ee4ed41a6d5672d947177e8f890692de879a20dd9e366ec494d270faf0d24fc076172a25998aac218586404687e7c77b55e77e0eff9b1c65c3f8da99deaa86411ab6aca2531d84b364349591bc73e7504163afd23c5208e321883ee611ea7e4e5885086e4fa7196e16b948cb54808b64b94106c74900e3190fd5f6068b490fd0c9c64481771527a0e2d00899fd5b7a9e7f508cc6770018fadf09d965d7a12ad3624d2161d9546d4a7937b5f961d7f7c4714786380c147e1ec6b0583503bd5a139b892831d1ea925993bb86f12e75d9010ceba230a1c286fa3d1d654a1672313cbf0763c05c622cee452f76957c42ba0e853ecda163d15e8600a702ccdc9e8f88a", "Ghe+t0Blaster"},
	{"$sxc$*0*0*1024*16*64983af0b26a6ee614e6c65b32c1d906f70c6397*8*9bb755c8a4fe8c34*16*112b9d41098c8677615755361da473a6*1024*1024*b95f0f2e0e1c7b4ee61168b646804d4b70b615f3c978cec65c9a7ab515417c79625d104373fd5012c3da6b356f8408a3a75edcc8b2aad0aa38bb33edd8933bdadbffde35a350ade73ccb9df29c2996082f5e94e324496835f8dfebe15ca38950e0f435d711ef964aa09915d58287967b5e321ca195a7f90253157afe82329da9a496c97292419b9a94cdb92f919e6d54700466aff61c200c5a355905b5a37c12d77b0e4ffd23f0204cfa664f4c0545f233db8d35af5fe337b459135da398fd23101becb194db305496474ba4179a7355285a9ec935044e1831f290f5f87ed3e00925e7fb4fc6bc38d9f0cfe9abf72560400490d2fd398d2d49516b618f99168602f323dd1786bcca394830341dfbeb377f9b7ef161dc1470f5e92b6152fa7a4f428e8ae40100791491a9e1c9385298522320488f00535866ac6e08354a75b8b2fd293066da7eb6b4ad7f3e13c8dc98cd815b2393f147fdac6279f76fdac9abd0a94131fa84fe4e99634a362a56d60ce588f6e0b66d6f8b6d411511272ffe32181d20e7d2c3d4b680764607afb2c29dcb94a845b920e96f6c27575534f8b7f9ddd93bdcef0d717d0a899fa937e7d2eeeb6d5b0338757f6e69dac72524d4b6f74edce1f937008eb3653bcc31a88712af940cf47ec3f3efd83e4da89d1a6cb7da6cf8d7d41430bc81a4b5d7bb46cad687f2f505e3379143ae274eed6201c3b17c1e05e516a14cbf2351ccf9fdd46e1309afb170bd01eb8f6a1d8e12441525199455fb550e3fc689b1801332b2d985e336b158f846fcbca18fbe6ea21438cf1fb5fdbce8d6350e65d6468342880845675ec721af2fb9df917a3968b4a1a477fc4c74ee38a71a230d77c2a7cf66ae6b83804488cbd25213ebc470cd845a2691b16161a640ebb385aa2381dc91f692f6c4ca2709b5a7e94dfb4548000a29b56f1da08701945d6209fabbd1621b28849fc27810775f1a0e0204d3ae9040a8cfb1386499a39d87149cfc1579de7d059662ad25a67abd42b30bb3608f09142ca030351c3a1e921e4c7bbc11aab846ef42eb5d1418c15ada77539aca096e0678439cd1b60950d2aa0cc4d2004b1ac48dc6a454c5a8e9ea7e910047c7c83895fd614fd9dfd961631eb23757646143c2aeb03c1a6476e78fc4ccf0f02cc1f88ec1b0080a170ac6871dc183939f7a4376965b0dfa7922012582eec4846ee621edc5547a2b9c4893e7f67f76541a4bd4a91827a57b3db5cdea29a2a3cc20238d89c8145c14b037360ad27f54f87317ef70472d6b1fd9f1168bcf8aba6071257b3adebab8d4e115188ed4af3fc3574fdccb4bc7eeb00a6a442f1b96a989b735f5e6059ec72c1677b77f437dcb93066f8591a11071799c3a0ec3b48f6160976aff1928c375358837e1ef02e20397b2e9d8d9c4bff23172c9b4c0b941cb1b49b5bc070f72a14cd384", "M1racl33"},
	{"$sxc$*0*0*1024*16*64983af0b26a6ee614e6c65b32c1d906f70c6397*8*ceb1edb1e3cb72fd*16*f7104c9b2789540f5fd4beef009c0139*1024*1024*709130b940a9663d0a5687133c6f78535d05a72936faed8c2f3c1b4e29423baaabcee4f0d7d57e3ad8d8c090486f974c4d0ce4be5b29ef8e1b02c01b4af1959ed0b277146a45aec35a48997b584b82697803193644eefd88a7eefcae8819839e13702f887278a597dd954babd82bf71bf8ca8559af0e5537be0264e358d36b4f5067960edf608de731e04d117de953386aadee71849edbc494fac3e6b14567a9e9c545a06d402acd3158441829f25478ed0f9086dabd2d3913b123b43c27176f8f08f30312d84e82d47654097a2bce95554357db3ce3d45a7441472067f55e4ea6244a3dedc23db4bea8f549109ffac382cf5b652c5b1ee431bcab1051567c263a9d668c5d6a15a6f8da754914746c1d3c7eb6347bdd8d6a3ac82e4c742fcf8721913c111dfd5398f2698db00f7220d2a3562e02f7f7a6505af3ba1ee10b46f2ab5b5d2f52d288fd12814c6edbcb8d50b6e8716fba0d5962747b971689fe75e94fa36ec39598ea30e15ab2b9c9f22ca04b890a13b18fb3c7a962050426bb2da08c8b993608b9c1ffd0a21e0c74e993242ead8eb30f86d7d2dcdbd4774d85c2e06adbe4b40050ff0ac1a8afe8fbc2175ec4da4676a691b1fce38421175734c20f07a604fea5287e1c33b420aa9db4de9bd97382c161b4ec0818add675e52ebf036aad779f24b824be4b2b013c470ff66cbf44f5800e128a3b328e80a5fd6295b9b3a94e915f9add6710cb9444432751a7a31c3a3422f48a5eabc26d9a52571b8447bdd0a5977ff7153d95337cef7ff2ec29774332fbeed6ee5eed5e12288cc13e14ba9d5ff3dd052e28ba96715f5b95d7ea214ebcd9e60b26308eb11370b824b5cff2644dd2117985b3c25ba8076d4025cf3a3a62da62d5e11d44422a142048e8cd00c7de6a0a55fd5dc09a3ed01dfe35b88268f351b6ff289fee8e52ac29fe32d9990e0d6d87f39727b6a762bac9d509c6ea235fc8bedc3bec2143eae9fd2cb831b798ef8261d72785002638b940947de0aad64f791f9a27e5b091e55adf4aee0649f6785bdd37e0248fedd1759d771aeacacb3ff6e7cf2d045f791428ab61710b54e869213393caf1b6bc99066678351deafc290cecc1f6b40b5532adbbab9a70408c61a437d4483b6a75cb61a55b20881efc0d849e0f60c1887f0fa091672179a145c4ab1b6487a0e939e0123d5aaffa3aec66ab593f9c25d27f22f4a73a999a4ab45e8bc7d71a85e2d40afadad1a1dc0b8389f96f91614293fa205583ef1c3440e3df50e8aa5f1a13e5929b72cd003461ff03d44d8c84bdada176b24459021d398b2b91b61a9c0b553a8714c703d32452c691a33f1581e98c2439514ca3e7deeef90850f8d6d89bf1d3a5762a56ef769ea588f5c1705bfb7b944cfbbb0632718ee3722f4e1929b35706d6413a315a11bc16349af109a7e675df2ab1eebe93", "excel123"},
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
	int original_length;
	int length;
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
	return !strncmp(ciphertext, "$sxc$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 6;	/* skip over "$sxc$*" */
	p = strtok(ctcopy, "*");
	cs.cipher_type = atoi(p);
	p = strtok(NULL, "*");
	cs.checksum_type = atoi(p);
	p = strtok(NULL, "*");
	cs.iterations = atoi(p);
	p = strtok(NULL, "*");
	cs.key_size = atoi(p);
	strtok(NULL, "*");
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
	cs.original_length = atoi(p);
	p = strtok(NULL, "*");
	cs.length = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.length; i++)
		cs.content[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
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
	ctcopy += 6;	/* skip over "$sxc$*" */
	strtok(ctcopy, "*");
	strtok(NULL, "*");
	strtok(NULL, "*");
	strtok(NULL, "*");
	p = strtok(NULL, "*");
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(keeptr);
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
		BF_cfb64_encrypt(cur_salt->content, output, cur_salt->length, &bf_key, ivec, &bf_ivec_pos, 0);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, output, cur_salt->original_length);
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
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

static void sxc_set_key(char *key, int index)
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

struct fmt_main sxc_fmt = {
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
		sxc_tests
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
		sxc_set_key,
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

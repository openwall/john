/* ODF cracker patch for JtR. Hacked together during Summer of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
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
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"odf"
#define FORMAT_NAME		"ODF SHA-1 Blowfish / SHA-256 AES"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		20
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests odf_tests[] = {
	{"$odf$*0*0*1024*16*df6c10f64d191a841812af53874b636d014ce3fe*8*07e28aff39d2660e*16*b124be9f3346fb77e0ebcc3bb80028f8*0*2276a1077f6a2a027bd565ce89824d6a20086e378876be05c4b8e3796a460e828c9803a692caf7a53492c220d1d7ecbf4e2d336c7abf5a7672acc804ca267318252cbc13676616d1fde38820f9fbeef1360067d9de096ba8c1032ae947bde1d0fedaf37b6020663d49faf36b7c095c5b9aae11c8fc2be74148f008edbdbb180b44028ad8259f1215b483542bf3027f56dee5f962448333b30f88e6ae4790b60d24abb286edff9adee831a4b3351fc47259043f0d683d7a25be7e47aff3aedca140005d866e218c8efcca32093c19bbece50bd96656d0f94a712d3c60d1e5342db86482fc73f05faf513ca0b137378126597b95986c372b412c953e97011259aab0839fe453c756559497a28ba88dce009e1e7980436131029d38e56a34f608e6471970d9959068808c898608024db9eb394c4feae7a364ea9272ec4ea2315a9f0407a4b27d5e49a8ab1e3ddce5c84927d5aecd7e68e4437a820ea8743c6b5b4e2abbb47b0001e2f77ceac4603e8774e4ccbc1adde794428c11ae4a7492727b620334302e63f72b0c06c1cf83800366916ee8295176819272d557863a831ee0a576841191482959aad69095831fa1d64e3e0e6f6c6a751bcdadf0fbaa27a17458709f708c04587cb208984c9525da6786e0e5aabefe30ad1dbbef66e85ce9d6dbe456fd85e4135de5cf16d9455976d7ca8de7b1b530661c74c0fae90c0fff1a2b5fcdfab19fcff75fadcec445ed8af6ab5babf1463e08458918be8045083de6db988c37e4be582cfac5cdf741d1f0322fb2902665c7ff347813348109e5d442e91fcb010c28f042da481e807084fcb4759b40ccf2cae77bad00cdfbfba4acf36aa1f74c30a315e3d7f1ca522b6306e8903352aafa51dc523d582d418934398d5eb88120e3656bfb640a239db507b285302a86855ea850ddc9af72fc62dc79336c9bc29ee8314c65adb0574e9c701d73d7fa977edd1d52a1ff2da5b8b94e1a0fdd01ffcc6583758f0a1f51750e45f12b58c6d38b140e5676cf3474224520ef7c52ca5e634f85456651f3d6f43d016ed7cc5da54ea640a3bc50c2b9d3dea8f93c0340d66ccd06efc5ae002108c33cf3a470c4a50f6a6ca2f11b8ad15511688c282b94ba6f1c332e239d10946dc46f763f08d12cb9edc1e79c0e07f7151f548e6d7d20ec13b52d911bf980cac60694e192651403c9a69abea045190e847be093fc9ba43fec55b32f77f5796ddca25b441f259d5c51e06df6c6588c6414899481ba9e06bcebec58f82ff3021b09c6beae13a5d22bc94870f72ab813d0c0be01d91f3d075192e7a5de765599d72244757d09539529a8347e077a36678166e5ed9f73a5aad2e147d8154095c397e3e5e4ba1987ca64c1301a0c6c3e438097ede9b701a105ec38fcb54abb31b367c7740cd9ac459e561094a34f01acee555e60267157e6", "test"},
	{"$odf$*1*1*1024*32*61802eba18eab842de1d053809ba40927fd40b26c69ddeca6a8a652ed9c16a28*16*c5c0815b931f313627100d592a9c972f*16*e9a48b7daff738deaabe442007fb2ec4*0*be3b65ea09642c2b4fdc23e553e1f5304bc5df222b624c6373d53e674f5df01fdb8873cdab7a5a685fa45ad5441a9d8869401b7fa076c488ad53fd9971e97244ecc9416484450d4fb2ee4ec08af4044d7def937e6545dea2ce36bd5c57b1f46b11b9cf90c8fb3accff149ce2d54820b181b9124db9aac131f6436d77cf716423f04d42438eed6f9ca14bd24b9b17d3478176addd5fa0254bf986fccd879e326485790e28b94ad5306868734b5ac1b1ddb3f876382dee6e9428e8230e84bf11b7e85ccbae8b4b424cd73160c380f874b37fbe3c7e88c13ef4bde74b56507d17095c2c32bb8bcded0637e4403107bb33252f72f5886a91b7720fe32a8659a09c217717e4c74a7c2e09fc40b46aa288309a36e86b9f1856e1bce176bc9690555431e05c7b67ff95df64f8f40053079bfc9dda021ab2714fecf74398b867ebef675958f29eaa15eb631845e358a0c5caff0b824a2a69a6eabee069d3d6236d77709fd60438c9e3ad9e42b26810375e1e587eff105ac295327ef8bf66f6462388b7727ec32d6abde2f8d6126b185124bb437753663f6ab1f321ddfdb36d9f1f528729492e0b1bb8d3b9eda3c86c1997c92b902f5160f77587c37e45b5c133b5d9709fea910a2e9b54c0960b0ebc870cdbb858aabe07ed27cba86d29a7e64c6e3863131859314a14e64c1168d4a2d5ca0697853fb1fe969ba968e31359881d51edce287eff415de8e60cec2068bb82157fbcf0cf9a95e92cb23f32e6156daced4bee6ba8c8b41174d01fcd7662911bcc10d5b4478f8209ce3b91075d10529780be4f17e841a1f1833d432c3dc854908643e58b03c8860dfbc710a29f79f75ea262cfcef9cd67fb67d73f55b300d42f4577445af2b9f224620204cfb88de2cbf57931ac0e0f8d98259a41d744cad6a58abc7761c266f4e93aca19356b07073c09ae9d1976f4f2e1a76c350cc7764c27ae257eb69ba4213dd0a7794fa83d220439a398efd988b6dbf0de4c08bc3e4830c9e482b9e0fd1679f14e6f132cf06bae1d763dde7ce6f525ff9a0ebad28aeca16496194f2a6263a20e7afeb43d83c8c936130d6508f2bf68b5ca50375948424193a7fb1106fdf63ff72896e1b2633907f01a693218e3303436542bcf2af24cc4a41621c36768ce9a84d32cc9f3c2b108bfc78c25b1c2ea94e6e0d65406f78bdb8bc33c94a9550e5cc3e995cfbd31da03afb929418acdc89b099415f9bdb7dab7a75d44a696e14b031d601ad8d907e14a28044706c0c2955df2cb34ffea82af367e487b6cc928dc87a33fc7555173e7faa5cfd1af6d3d6f496f23a9579db22dd4a2c16e950fdc90696d95a81183765a4fbddb42c488d40ac1de28483cf1cdddf821d3f859c57b13cb7f21a916bd0d89438a17634c68637f23e2544589e8ae5ee5bced91680c087cb3105cd74a09e88d3aae17d75e", "test"},
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int cipher_type;
	int checksum_type;
	int iterations;
	int key_size;
	int iv_length;
	int salt_length;
	unsigned char iv[16];
	unsigned char salt[32];
	unsigned char content[1024];
} *cur_salt;

static void init(struct fmt_main *pFmt)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$odf$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 6;	/* skip over "$odf$*" */
	p = strtok(ctcopy, "*");
	cs.cipher_type = atoi(p);
	p = strtok(NULL, "*");
	cs.checksum_type = atoi(p);
	p = strtok(NULL, "*");
	cs.iterations = atoi(p);
	p = strtok(NULL, "*");
	cs.key_size = atoi(p);
	p = strtok(NULL, "*");
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
	p = strtok(NULL, "*");
	for (i = 0; i < 1024; i++)
		cs.content[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	free(keeptr);
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
	ctcopy += 6;	/* skip over "$odf$*" */
	p = strtok(ctcopy, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	free(keeptr);
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
		if(cur_salt->checksum_type == 0 && cur_salt->cipher_type == 0) {
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
			BF_cfb64_encrypt(cur_salt->content, output, 1024, &bf_key, ivec, &bf_ivec_pos, 0);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, output, 1024);
			SHA1_Final((unsigned char*)crypt_out[index], &ctx);
		}
		else {
			SHA256_CTX ctx;
			AES_KEY akey;
	                unsigned char iv[32];
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, (unsigned char *)saved_key[index], strlen(saved_key[index]));
			SHA256_Final((unsigned char *)hash, &ctx);
			derive_key(hash, 32, cur_salt->salt,
					cur_salt->salt_length,
					cur_salt->iterations, key,
					cur_salt->key_size);
			memcpy(iv, cur_salt->iv, 32);
			memset(&akey, 0, sizeof(AES_KEY));
			if(AES_set_decrypt_key(key, 256, &akey) < 0) {
				fprintf(stderr, "AES_set_derypt_key failed!\n");
			}
			AES_cbc_encrypt(cur_salt->content, output, 1024, &akey, iv, AES_DECRYPT);
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, output, 1024);
			SHA256_Final((unsigned char*)crypt_out[index], &ctx);
		}
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

static void odf_set_key(char *key, int index)
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

struct fmt_main odf_fmt = {
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
		odf_tests
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
		odf_set_key,
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

/*
 * Format for cracking Jetico BestCrypt 8.x / 9.x containers.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_bestcrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_bestcrypt);
#else

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1 // this is a slow format

#include "sha2.h"
#include "loader.h"
#include "pkcs12.h"
#include "aes.h"
#include "xts.h"
#include "sph_whirlpool.h"

#define FORMAT_LABEL            "BestCrypt"
#define FORMAT_NAME             "Jetico BestCrypt (.jbc)"
#define ALGORITHM_NAME          "PKCS#12 PBE (SHA1/SHA2) 32/" ARCH_BITS_STR
// I could not get openssl to use passwords > 48 bytes, so we will cut support at this length (JimF).
#define PLAINTEXT_LENGTH        48
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define BENCHMARK_COMMENT       " (SHA-256 + AES XTS mode)"
#define BENCHMARK_LENGTH        0x507 // FIXME: format lacks cost
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define FORMAT_TAG              "$BestCrypt$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

#define kDigestSize32               32
#define kIVSize                     16
#define kKeySlotSize                256
#define kBCPasswordMaximumKeySize   64
#define bchaSHA256                  0x80
#define bchaWhirlpool512            0x80 + 1
#define pgphaSHA256                 8
#define pgphaSHA512                 10
#define kBCMode_XTS                 0xBC000004
#define kBCMode_CBC                 0xBC000002

static struct fmt_tests tests[] = {
	// SHA-256 + AES XTS mode
	{"$BestCrypt$1$5$3$16384$240$3154116612$128$32$51f7450dccbb1c947dd46138bf0d80d588b6938b02505642dde9e1ea61481485$1$a186f281fbbc68f3b27c7b4cc16b7916a2e19c2695b34ee4133a6ac6373db67b88fb54e3def1c0d288d3170dcb5860c2f190ab199fde7f1072a2a109441e608ae46890c5f18ab80803012a43d9cc595a45c5b9ed8b3ed3330cab1a29e5a96512e2f2e0e5927d6836c3a67c1cd13a61a8201a0a99be84c3e19e6d8a12330ae72c22179d37bb7d55034bb96b5cf9f73c11fa82be31d06bfe33305b616cc72079777a5f1f4a720b56470a83da08c17cbc86e34961c4f0bdb8556e2afa0b2b890780e03304725ce7cf8c592f037beb04b393f4f02e3bc9f6582082a39d31f2e643c5f7811f30eeee2ccc6c11496b7d70dc0d300e145408d28448ff5d929c42007dbe", "openwall"},
	// SHA-512 + AES XTS mode
	{"$BestCrypt$1$5$3$16384$240$3154116612$10$64$7f36390c85bc5695d49d5d135cb09e00cbf738bb203d0f0a0181805acc15d1cc6f856af0f738c44eead724a854700700a1595b5b30d47242a277b60df6491dde$1$a5b6a69b5cb04be789b42e1f50d3426048ea0df06c3b9a9932d85bd54b99aae202c1ca2e283786a4154f09fa01014ecab7f95c3b9a9b6adab1a695153ca8bffec2408566a7da986c0f107c57404c96823bbdc18a4b11337d211b49d7a133cf951b03c54aaccf3ed9b6445e472ba508add524fb67343e954efe313f544d8ecd6f99e9731fa147c62e17a07954f4a265b43cad4247d61529a3e8760d91c5a4314238eb78e10c2521309b7b827be302a32ee37e03854a8c4f872a07fac709b6170f2e7bd9d723f65ba3fd3766c42ed4a4f8dcc55e4c3b9d4e1dcf2bc54a23a87763f4379afdd9d8e934f254f713f3ba80369f26de2c5195c5e04405acdb2893990a", "openwall"},
	// Whirlpool 512 + AES XTS mode
	{"$BestCrypt$1$5$3$16384$240$3154116612$129$64$06b513b2ac314636f616747c4171700133c00d335ee6a6c3a8db60bf672531624f099fa90b8047a5aceb2492c5858cab529cf9ba5d7e8c715e33517b64ef4251$1$5fc5bf3251a22f40cd23bf7a2bed453915f9037d80630d50c4c1d9d5ed3380fbf495e3013a2f1ada864afb2d4cdcc8dcaa8f86be5898bad53244d4382a42ba857420cff29b85c644c43305e9d0daf70a8db9dcaa0acc2d6b7c7e16374c30936a7d457a155ad5f6427c2818b85065eb6ab3751f91d8321ccdbfd13df038a26a01dbee887db43564588a7387e001ec5d23b22cb003a814ebb7cb4cec9b4cfd93e15bdedff0dd6dbbfff6e7fb3abf5f29ce891e3e432795600ea447c95a0900bd48d5ecc18fd6191b34dffe411412e8e8a8a8840d95cf77a51fb58248fbf940429a977f6f392cf6d1fe7b1ead0ee7ccc5264725c476b3f1fe087ffb8d811b6b2a8b", "openwall"},
	// SHA-256 + AES CBC mode
	{"$BestCrypt$1$5$3$16384$240$3154116610$128$32$42ea77745d3430a906f988ce035de539626dd6ef256120cabca0995e3682b89b$1$4ba52a18d7a31b9e460fe89940e879d51e3ef775240233864f11e4cbba50cb716488878ab4d5cc039c56d3cf5eb6682e8a97c35edd5b187d1f361e05c3714fcca4acc7dd158ee2cb43a5043aa795d8cf992abdcb1bb3d159b90a934ff5b9f2faa5112ed43d88c55b6cc19e478c3d7a6f6198f51273ce99a6910837227a8f681e1cc3c10b0573644628775a03b40c0e651aecf19599578a1d5de5f2791267b67beabc40e40632261190663484d0d9f4ffb5403a60cc14bcfd803d83871cbe1dfd5b6d31452c6696fb3d563d0bb28b7b8010dd0b161441530cac8a345d867146edb3a09c4b35e928add8955a414dc402b5ee89bfde514769f93defa22c6399b07f", "openwall"},
	// Whirlpool-512 + AES CBC mode
	{"$BestCrypt$1$5$3$16384$240$3154116610$129$64$8ede312199fd2c95c895a70020a257dc8d26b7768e701e0db21b8dbcc5d74817c9e92b96a672b8b5a073f3d78c8cedeec18620dbcf968095f05e4d0c42b2a9ca$1$a8980d15deb806a89cfdf186766d319b6cc336f880883e639c09cba1a12e69b72a7bd2943207c1cab29965ff22f321954dfeb8a4569954d918e05c6833b400cbab1783d72f343df07b9697c5fcd09f4a6815b965f6c2f5ca555e34bdf8fba50e7ab24d3b56c1f5779334f6a02ebb0ab2d0d76bbd946b7af2d7f3a77db2f649bab287cb8b5721acc5ab1e030e2f278cc708f532555e0ab0cee908a77d870a657d94629d791a3746fca3855dfffb8f8694ef0e574458127105bbb259ce8b518447ec1b6abc1b9edab5fe09526213d16b76735c9cda90ce1e8d6aabce22001980de31789d25443c691b2bd6563f00f0f6ac78a63d6372abc4c59c0a937ea99d630d", "openwall"},
	// SHA-512 + AES CBC mode
	{"$BestCrypt$1$5$3$16384$240$3154116610$10$64$82157a6df840155fd2bb70681dbf1553e62d7559f8d0fd484364e4681d56c51d2b48f04b1c5a7f7c1b2a2ac20197da5c4d48ff1bd4f0a182364d37af17f43afb$1$c18fc91acef0de092e122344327c5f28e83c0bac3210474f2cf1ca497f467e32fcf371d017e8a529c5eef911791417bff07904eccf4c9c6b4e3cb03c4758d820faa9408a4333cf7b2ba58298f85468f4c5255a4a0abda8233102f6ad8eac3e4b8327469f81904485a7c9662c83affbe59029569b90ac75aabec934c8ab813b870bb960dc3b6e4f3e8fc4f6d360070fbe0d47064aaf341faa557839f07925cf52c3856b28dbdfc910ca6dc9ed6b6c44803e025e0d07b016565dae4d1cc646110719f4195b3c553c62b9e35a79bfbce645c66d7d8e1d8040b38dfbbf020130385ad77d085f60ddaaadcf6f768057b805ace60fa869a454ed2b8c96121f0f10ef10", "openwall"},
	// Created on Windows using BestCrypt v9.03, Whirlpool-512 (default and unchangeable on Windows) + AES CBC mode
	{"$BestCrypt$1$5$3$16384$240$3154116610$129$64$65656e4d18c599d592a8ca416fcab3d64de3592733aca7f145020396ca9150827f041b6cd49cea398f26c1794d943cc84b14cf8379a19edce7667a56dade5cec$1$7bebd0fa023ca12834a90c372955bb8a62b09a22c054507199b4db023dd12bb44ae21d34f9dc8dd6915c5655ad239e7c004afd618fdb3bdba5e0f8ca567c19e6a4ef603d05579cce3437bfee0f13db9772dbc2bf3f30265719e6e6058d0137a182220a0487910ea77fa40dbf0341b519f64f54159e7663f4a2979633f19cc594c9832c47455c0ed926c6b42bc0e529902e612898413704ab509f556c4239eb27d8c8f9a1cf536e44b1fb32e0a4894bf137f27ab4d2c4a1c19e4bf9369fe0b7fde27523b8a9f4643559a2fdf2b49ad13015007c8facc1e5b2fdbd1f5efa3acc02b00ccf0da3b0da772b3ab54a5ffe42af396d0908596d35323b3d7dec15ea7f2b", "password123"},
	// container-password@123.jbc, first active key slot
	{"$BestCrypt$1$5$3$16384$240$3154116612$129$64$c8d1e54303eb356636e138295e49533f250d4c327f57ceae134cb3995a7c01ea8814b0352dd7300899d2adf803c90f7a6872c27234693a8ba2dd354be30dbee5$1$904d7e7ff0aacae28afb5c81bc2d69c40de1d482969166237de478fc22a94131cb736058c06b08510fd259fa9e4adf00f687b9e7a1333becfbca76f36d6e583293feb5eed9257f7962930ddfb06e28d1ebc41b4a646fe25c7c43086667500d3ec40fe53cc899da0b859c62fc2494d14c9d5bd110f9c5da2419367386bb20e65f9d66b44192dd9034ee946f46da52b709cbf65da0f1787a35d64dd4c6d4da24be6554e594029e58e4b8df7bd76cc86d508a93e78644d936fb422c265557a5f4da4e92653aafe9bbbcc20c6d851fac8845251cee63f1081066d6093c4c2ce0f47229602a8a441b3e83271b8fcc7bcdfef108b2488d3b7b0eb070b11cb0ef3d6d31", "password@123"},
	// container-password@123.jbc, second active key slot
	{"$BestCrypt$1$5$3$16384$240$3154116612$129$64$c8d1e54303eb356636e138295e49533f250d4c327f57ceae134cb3995a7c01ea8814b0352dd7300899d2adf803c90f7a6872c27234693a8ba2dd354be30dbee5$1$4c72ff9af13e578d116d48e251e93a87c43cb518e0256b0092c9db1dabe7c1422105423a1a7a8fb21c7e8c22e4542a9d58b3bc17198a9ec1151ac3e7d20cf5db9c24c39ec3f259a47cac4e6340b42d4b025942796f616ed088c162bdd78ef0cce258ec5e5b2c0b5915d0bfd5432b578a3694cefff2a9a4a3e1367279fcde9c7c9575f945ce704b888089029df99d4613b1fa8f4a16bd18bfc346942eda549bf4ff216cd6f304f284dea1a3e1a10fe6f7b74b3661980a5b8cd8fbe8a00b2065abb23822477caa88c4881e7bebefff696c1e205213800066fd4f28b56abb36585f51b37de4ffd7f2b6597db33ebb60d70ce00a38d0a4ba549a15d97a780986bed6", "openwall123"},
	{NULL}
};

typedef struct {
        unsigned char data[kKeySlotSize];
} KEY_BLOCK;

// PBE key block format for version 5
typedef struct {
	unsigned char keyblock[128]; // KGEncryptedBlock32<key_data_t> keyblock, encoded key, is this size fixed?
	unsigned char iv[kIVSize]; // unencrypted initial vector
} pbe_format_v5_32; // used when digestSize <= 32

typedef struct {
	unsigned char keyblock[160]; // KGEncryptedBlock64<key_data_t> keyblock, encoded key, is this size fixed?
	unsigned char iv[kIVSize]; // unencrypted initial vector
} pbe_format_v5_64; // used when digestSize <= 64

struct KGEncryptedBlock32 {
	unsigned char data[96]; // is this offset fixed?
	unsigned char digest[kDigestSize32];
};

struct KGEncryptedBlock64 {
	unsigned char data[96]; // is this offset fixed?
	unsigned char digest[kDigestSize32];
};

static struct custom_salt {
	int version;
	int wKeyGenId;
	int wVersion;
	int iterations;
	int alg_id;
	uint32_t mode_id;
	int hash_id;
	int salt_size;
	unsigned char salt[64];
	int active_slots;
	unsigned char key[256]; // one active key per hash
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int *cracked, cracked_count;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int salt_size, extra;
	int res;
	uint32_t mode_id;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // wKeyGenId
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res != 5)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // wVersion
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iterations
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // alg_id
		goto bail;
	if (!isdec(p))
		goto bail;
	if (atoi(p) != 240) // AES
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // mode_id
		goto bail;
	if (!isdecu(p))
		goto bail;
	mode_id = strtoul(p, NULL, 10);
	if (mode_id != kBCMode_CBC && mode_id != kBCMode_XTS) // only CBC + XTS modes for now
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // hash_id
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res != bchaSHA256 && res != pgphaSHA512 && res != bchaWhirlpool512)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // salt_size
		goto bail;
	if (!isdec(p))
		goto bail;
	salt_size = atoi(p);
	if (salt_size > 64)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) > salt_size * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // active keys
		goto bail;
	if (!isdec(p))
		goto bail;
	if (atoi(p) != 1) // one active key per hash
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // keys
		goto bail;
	if (hexlenl(p, &extra) > 256 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;
	memset(&cs, 0, sizeof(cs));

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.version = atoi(p);
	p = strtokm(NULL, "$");
	cs.wKeyGenId = atoi(p);
	p = strtokm(NULL, "$");
	cs.wVersion = atoi(p);
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "$");
	cs.alg_id = atoi(p);
	p = strtokm(NULL, "$");
	cs.mode_id = (uint32_t)strtoul(p, NULL, 10);;
	p = strtokm(NULL, "$");
	cs.hash_id = atoi(p);
	p = strtokm(NULL, "$");
	cs.salt_size = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.salt_size && p[2*i]; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	cs.active_slots = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.active_slots * kKeySlotSize && p[2*i]; i++)
		cs.key[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

	MEM_FREE(keeptr);

	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
		if (cur_salt->hash_id == bchaWhirlpool512) {
			unsigned char key[kBCPasswordMaximumKeySize];
			int keylen = 0;
			pbe_format_v5_64* pbe64;
			unsigned char out[256] = {0};
			AES_KEY aes_key;
			sph_whirlpool_context ctx;
			unsigned char hash[64];
			unsigned char iv[16] = {0};
			struct KGEncryptedBlock64 *p;

			if (cur_salt->mode_id == kBCMode_XTS)
				keylen = 64; // for AES-256 XTS mode
			else if (cur_salt->mode_id == kBCMode_CBC)
				keylen = 32;
			pkcs12_pbe_derive_key(2, cur_salt->iterations,  // 2 is a hack to indicate Whirlpool-512
					MBEDTLS_PKCS12_DERIVE_KEY, // key material
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->salt_size, key, keylen);
			pbe64 = (pbe_format_v5_64*)cur_salt->key;
			memcpy(iv, pbe64->iv, 8);
			if (cur_salt->mode_id == kBCMode_XTS) {
				AES_XTS_decrypt_custom_tweak(key, iv, out, pbe64->keyblock, 256, 256);
			}
			if (cur_salt->mode_id == kBCMode_CBC) {
				// decrypt data stored in encrypted block, AES CBC mode
				memcpy(iv + 8, pbe64->iv, 8); // isn't BestCrypt great?
				AES_set_decrypt_key(key, 256, &aes_key);
				AES_cbc_encrypt(pbe64->keyblock, out, 160, &aes_key, iv, AES_DECRYPT);
			}
			sph_whirlpool_init(&ctx);
			sph_whirlpool(&ctx, out, 90); // only 90 bytes are used, calculate_digest(hash, data, sizeof(*data), digest), sizeof(*data) == 90
			sph_whirlpool_close(&ctx, hash);
			p = (struct KGEncryptedBlock64 *)out;
			cracked[index] = (0 == memcmp(hash, p->digest, kDigestSize32));
		} else if (cur_salt->hash_id == bchaSHA256) {
			unsigned char key[kBCPasswordMaximumKeySize];
			int keylen = 0;
			pbe_format_v5_32* pbe32;
			unsigned char out[256] = {0};
			AES_KEY aes_key;
			SHA256_CTX ctx;
			unsigned char hash[32];
			unsigned char iv[16] = {0};
			struct KGEncryptedBlock32 *p;

			if (cur_salt->mode_id == kBCMode_XTS)
				keylen = 64;
			else if (cur_salt->mode_id == kBCMode_CBC)
				keylen = 32;
			pkcs12_pbe_derive_key(256, cur_salt->iterations,
					MBEDTLS_PKCS12_DERIVE_KEY,
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->salt_size, key, keylen);
			pbe32 = (pbe_format_v5_32*)cur_salt->key;
			memcpy(iv, pbe32->iv, 8); // iv[8:16] is all zero for XTS mode
			if (cur_salt->mode_id == kBCMode_XTS) {
				AES_XTS_decrypt_custom_tweak(key, iv, out, pbe32->keyblock, 256, 256);
			} else if (cur_salt->mode_id == kBCMode_CBC) {
				memcpy(iv + 8, pbe32->iv, 8); // iv[8:16] is repeat of iv[0:8] for CBC mode
				AES_set_decrypt_key(key, 256, &aes_key);
				AES_cbc_encrypt(pbe32->keyblock, out, 128, &aes_key, iv, AES_DECRYPT);
			}
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, out, 90);
			SHA256_Final(hash, &ctx);
			p = (struct KGEncryptedBlock32 *)out;
			cracked[index] = (0 == memcmp(hash, p->digest, kDigestSize32));
		} else if (cur_salt->hash_id == pgphaSHA512) {
			unsigned char key[kBCPasswordMaximumKeySize];
			int keylen = 0;
			pbe_format_v5_64* pbe64;
			unsigned char out[256] = {0};
			AES_KEY aes_key;
			SHA512_CTX ctx;
			unsigned char hash[64];
			unsigned char iv[16] = {0};
			struct KGEncryptedBlock64 *p;

			if (cur_salt->mode_id == kBCMode_XTS)
				keylen = 64;
			else if (cur_salt->mode_id == kBCMode_CBC)
				keylen = 32;
			pkcs12_pbe_derive_key(10, cur_salt->iterations, // 10 is a hack to indicate BestCrypt specific PKCS12 PBE with SHA-512
					MBEDTLS_PKCS12_DERIVE_KEY,
					(unsigned char*)saved_key[index],
					saved_len[index], cur_salt->salt,
					cur_salt->salt_size, key, keylen);
			pbe64 = (pbe_format_v5_64*)cur_salt->key;
			memcpy(iv, pbe64->iv, 8);
			if (cur_salt->mode_id == kBCMode_XTS) {
				AES_XTS_decrypt_custom_tweak(key, iv, out, pbe64->keyblock, 256, 256);
			} else if (cur_salt->mode_id == kBCMode_CBC) {
				memcpy(iv + 8, pbe64->iv, 8);
				AES_set_decrypt_key(key, 256, &aes_key);
				AES_cbc_encrypt(pbe64->keyblock, out, 160, &aes_key, iv, AES_DECRYPT);
			}
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, out, 90);
			SHA512_Final(hash, &ctx);
			p = (struct KGEncryptedBlock64 *)out;
			cracked[index] = (0 == memcmp(hash, p->digest, kDigestSize32));
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
	return 1;
}

static void set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int bestcrypt_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}

struct fmt_main fmt_bestcrypt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
/* FIXME: Should also report hash_id as a tunable cost */
			"iteration count",
		},
		{ FORMAT_TAG },
		tests
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
			bestcrypt_iteration_count,
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

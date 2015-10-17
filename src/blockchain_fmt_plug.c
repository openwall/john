/* blockchain "My Wallet" cracker patch for JtR. Hacked together during June of
 * 2013 by Dhiru Kholia <dhiru at openwall.com>.
 *
 * See https://blockchain.info/wallet/wallet-format
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * improved dection, added iteration count and handle v2 hashes, Feb, 2015, JimF.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_blockchain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_blockchain);
#else

#include <string.h>
#include <errno.h>
#include "arch.h"
#include "jumbo.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "pbkdf2_hmac_sha1.h"
#include "aes.h"
#ifdef _OPENMP
#include <omp.h>
//#define OMP_SCALE               1 // tuned on core i7
#ifndef OMP_SCALE
#define OMP_SCALE               64 // tuned on AMD K8 dual-HT (XOP)
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"Blockchain"
#define FORMAT_NAME		"My Wallet"
#define FORMAT_TAG		"$blockchain$"
#define TAG_LENGTH		12

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME		"PBKDF2-SHA1 AES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME		"PBKDF2-SHA1 AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT	" (x10)"
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define PLAINTEXT_LENGTH	125
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

#define BIG_ENOUGH 		(8192 * 32)

// increase me (in multiples of 16) to increase the decrypted and search area
#define SAFETY_FACTOR 		160

static struct fmt_tests agile_keychain_tests[] = {
	{"$blockchain$400$53741f25a90ef521c90bb2fd73673e64089ff2cca6ba3cbf6f34e0f80f960b2f60b9ac48df009dc30c288dcf1ade5f16c70a3536403fc11a68f242ba5ad3fcceae3ca5ecd23905997474260aa1357fc322b1434ffa026ba6ad33707c9ad5260e7230b87d8888a45ddc27513adb30af8755ec0737963ae6bb281318c48f224e9c748f6697f75f63f718bebb3401d6d5f02cf62b1701c205762c2f43119b68771ed10ddab79b5f74f56d611f61f77b8b65b5b5669756017429633118b8e5b8b638667e44154de4cc76468c4200eeebda2711a65333a7e3c423c8241e219cdca5ac47c0d4479444241fa27da20dba1a1d81e778a037d40d33ddea7c39e6d02461d97185f66a73deedff39bc53af0e9b04a3d7bf43648303c9f652d99630cd0789819376d68443c85f0eeb7af7c83eecddf25ea912f7721e3fb73ccaedf860f0f033ffc990ed73db441220d0cbe6e029676fef264dc2dc497f39bedf4041ba355d086134744d5a36e09515d230cd499eb20e0c574fb1bd9d994ce26f53f21d06dd58db4f8e0efbcaee7038df793bbb3daa96", "strongpassword"},
	{"$blockchain$384$ece598c58b22a3b245a02039ce36bdf589a86b6344e802b4a3ac9b727cc0b6977e9509bc1ac4d1b7b9cbf9089ecdc89706f0a469325f7ee218b2212b6cd3e32677be20eee91e267fe13ebded02946d4ae1163ef22b3dca327d7390091247ac770288a0c7be181b21a48a8f945d9913cdfdc4cfd739ee3a41ced11cacde22e3233250e36f8b8fb4d81de5298a84374af75b88afda3438eed232e52aa0eb29e0d475456c86ae9d1aaadca14bc25f273c93fd4d7fd8316ed5306733bca77e8214277edd3155342abe0710985dc20b4f80e6620e386aa7658f92df25c7c932f0eb1beca25253662bd558647a3ba741f89450bfdba59a0c016477450fbcecd62226626e06ed2e3f5a4180e32d534c7769bcd1160aad840cfd3b7b13a90d34fedb3408fe74379a9e8a840fe3bfee8e0ee01f77ee389613fa750c3d2771b83eeb4e16598f76c15c311c325bd5d54543571aa20934060e332f451e58d67ad0f4635c0c021fa76821a68d64f1a5fb6fd70365eef4442cedcc91eb8696d52d078807edd89d", "qwertyuiop1"},
	/* here is a v2 hash.  NOTE, it uses 5000 pbkdf2 for the hash */
	{"$blockchain$v2$5000$544$9a4d5157d4969636b2fe0738f77a376feda2fb979738c5cf0e712f5d4a2f001608824a865d25041bc85e0ad35985999fcfae7d218eb109a703781f57e7b5a03c29ffdfb756ec8ee38ed8941b056922cdd174c8e89feb40e1a0e1766792845f57992ae9d7667eff41a5e5580f3f289b050d76cc0f049cbd30c675efc3a553c0f19f30cb9589c7c3773dd095de92a991963789408351f543c1dc307751e5f781c278da77270035e3743df01ab4e41155b6437d9c7e64388a28f8331aca4822e6b89cdd5f45061b99768218d853a3575bbd029564826bcb188d55444273cda588d4e593fc5d29696713d747cfc8302a3e9c9dbb1bb3754c2e00f28b69d8faeb2e45c04085359c6a9b6bfecfd0a6a8f27ad647b6bfd498f2224a8c0442f7fe730656263ac2869923b296ad9955dbad515b4f88ad33619bdacc33ae7f14c65fce029e0f9e4a9c414716d9a23e4361aa264493bb6fc9a7fda82599b0232174b9fc92a1c717ca2cc6deb8bd6aaf3706b95fdfdc582316cb3d271178dafe3a6704a918e07be057bef676bb144840c7f26676f183f2744fc2fe22c9c3feb7461b4383981c00b6fff403fef578f6e5464dc2d0bcb7b8d0dc2e7add502b34c8fe9f9b638eebe7ede25e351b17ea8b8c1f5213b69780c0ba7ef3d5734c0635e9d2ee49524914f047d45536180be25e7610db809db694ceeb16a3bfd8abd5ab0cda4415203408387698fe707568566f7f567164707091a806ac2d11b9b9dd0c3c991ff037f457", "Openwall1234#"},
	/* this is the 'raw' hash to the line above.  We do not handle this yet, but probably should.  It is also mime, and not base-16 */
	//{"{\"pbkdf2_iterations\":5000,\"version\":2,\"payload\":\"mk1RV9SWljay/gc493o3b+2i+5eXOMXPDnEvXUovABYIgkqGXSUEG8heCtNZhZmfz659IY6xCacDeB9X57WgPCn/37dW7I7jjtiUGwVpIs3RdMjon+tA4aDhdmeShF9XmSrp12Z+/0Gl5VgPPyibBQ12zA8EnL0wxnXvw6VTwPGfMMuVicfDdz3Qld6SqZGWN4lAg1H1Q8HcMHdR5feBwnjadycANeN0PfAatOQRVbZDfZx+ZDiKKPgzGspIIua4nN1fRQYbmXaCGNhTo1dbvQKVZIJryxiNVURCc82liNTlk/xdKWlnE9dHz8gwKj6cnbsbs3VMLgDyi2nY+usuRcBAhTWcaptr/s/QpqjyetZHtr/UmPIiSowEQvf+cwZWJjrChpkjspatmVXbrVFbT4itM2Gb2swzrn8Uxl/OAp4PnkqcQUcW2aI+Q2GqJkSTu2/Jp/2oJZmwIyF0ufySoccXyizG3ri9aq83Brlf39xYIxbLPScReNr+OmcEqRjge+BXvvZ2uxRIQMfyZnbxg/J0T8L+IsnD/rdGG0ODmBwAtv/0A/71ePblRk3C0Ly3uNDcLnrdUCs0yP6fm2OO6+ft4l41Gxfqi4wfUhO2l4DAun7z1XNMBjXp0u5JUkkU8EfUVTYYC+JedhDbgJ22lM7rFqO/2KvVqwzaRBUgNAg4dpj+cHVoVm9/VnFkcHCRqAasLRG5ud0MPJkf8Df0Vw==\"}", "Openwall1234#"},
	{"$blockchain$v2$5000$544$a48c0a5f37986945940bd374f2e473a8f7c04719c04f7e3843f9f58caef832a738f6e3eb48f78ee059495790b0db93d8e2a1bbe9b81cdf6ac278599a30be0a12fcfa341fc29705948b2d885b2e93627ab53f5b67c4294bf2ae59571c04fbedc5a0e65547d356fef8b8090ad8e5744d63224f160b00f898e2583b2abe818454d15878afc11d0aee31f12e0553a84dff23e8e1438a212ae9c51d2c203d6c3e4746cddc94182f83fb8b2f7de79d3493d991f3d8718a58b6af7c2d33d8ef77b76e20bb859b13fad787ea7ad9a057e3ac9697b051c6749e3d3dc9a7699e13b08c7254ad687cf09f005800ab190e13c7cf9b881582b52e6c154e562fe73a723b0b1c0b80be352873c1ab8456a4a0d57bb5185f5c4cb1e150359578344ea8321cc5a0a94807fe06a89742226b2c74e8b6f1653ea84bf79e525fc92ebb7aa9106774e1b9dc794f5280ab2a5df818aeae0e467aeac0083aaea0b1f9d4c754324938caa4e8594aa69f988a0c424ae1fe5e1b91c82bccf6f995ec28d3e300b2eb62daa6ba72b4df46a788d724ec0f1f102d262b6c129ee9cd0d5674d3bc71350091b23a6219ff900653cdb52143b549829330abd15eb1f2d8e742565ed5ede6285908b040b75ca0b1871bbfb8e3a8115afef2ff8c46f180765387fb55e896a9c3a3073f57509a4102dec52d77dbb88f97cf6d83f0834b1dc7c0343a1a6b2144f2d264a3f0c4d9eb014c07fde9f1c1b6cc02fdb2e87583277194332d90b3b491d1a441ed57ce", "johntheripper!"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned char data[BIG_ENOUGH];
	int length;
	int iter;
} *cur_salt;

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	int omp_t = 1;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_align(sizeof(*saved_key),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked = mem_calloc_align(sizeof(*cracked),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto err;
	if (!strcmp(p, "v2")) {
		if ((p = strtokm(NULL, "$")) == NULL)
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)
			goto err;
	}
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if(len > BIG_ENOUGH || !len)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (hexlenl(p) != len * 2)
		goto err;

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
	int i;
	char *p;

	static union {
		struct custom_salt _cs;
		ARCH_WORD_32 dummy;
	} un;
	struct custom_salt *cs = &(un._cs);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	if (!strcmp(p, "v2")) {
		p = strtokm(NULL, "$");
		cs->iter = atoi(p);
		p = strtokm(NULL, "$");
	} else
		cs->iter = 10;
	cs->length = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs->length; i++)
		cs->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}
static int blockchain_decrypt(unsigned char *derived_key, unsigned char *data)
{
	unsigned char out[SAFETY_FACTOR];
	AES_KEY akey;
	unsigned char iv[16];
	memcpy(iv, cur_salt->data, 16);

	if(AES_set_decrypt_key(derived_key, 256, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed in crypt!\n");
	}
	AES_cbc_encrypt(data + 16, out, 16, &akey, iv, AES_DECRYPT);
	/* various tests */
	if (out[0] != '{') // fast test
		return -1;

	// "guid" will be found in the first block
	if (memmem(out, 16, "\"guid\"", 6)) {
		memcpy(iv, cur_salt->data, 16); //IV has to be reset.
		AES_cbc_encrypt(data + 16, out, SAFETY_FACTOR, &akey, iv, AES_DECRYPT);
		if (memmem(out, SAFETY_FACTOR, "\"sharedKey\"", 11) &&
			memmem(out, SAFETY_FACTOR, "\"options\"", 9))
			// Note, we 'could' check that the guid and sharedKey values are
			// 'valid' GUID's, but there really is no point. We already have
			// 2^216 confidence in the simple text strings being found.
			return 0;
	}
	return -1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
#ifdef SIMD_COEF_32
		unsigned char master[MAX_KEYS_PER_CRYPT][32];
		int lens[MAX_KEYS_PER_CRYPT], i;
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens,
			cur_salt->data, 16, cur_salt->iter, pout, 32, 0);
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			if(blockchain_decrypt(master[i], cur_salt->data) == 0)
				cracked[i+index] = 1;
			else
				cracked[i+index] = 0;
		}
#else
		unsigned char master[32];
		pbkdf2_sha1((unsigned char *)saved_key[index],
			strlen(saved_key[index]),
			cur_salt->data, 16,
			cur_salt->iter, master, 32, 0);
#if !ARCH_LITTLE_ENDIAN
		{
			int i;
			for (i = 0; i < 32/sizeof(ARCH_WORD_32); ++i) {
				((ARCH_WORD_32*)master)[i] = JOHNSWAP(((ARCH_WORD_32*)master)[i]);
			}
		}
#endif
		if(blockchain_decrypt(master, cur_salt->data) == 0)
			cracked[index] = 1;
		else
			cracked[index] = 0;
#endif
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

static void agile_keychain_set_key(char *key, int index)
{
	int saved_len = strlen(key);

	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_blockchain = {
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
		{ NULL },
		agile_keychain_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		agile_keychain_set_key,
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

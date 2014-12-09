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
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               1 // tuned on core i7
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"Blockchain"
#define FORMAT_NAME		"My Wallet"
#define FORMAT_TAG		"$blockchain$"
#define TAG_LENGTH		12

#ifdef MMX_COEF
#define ALGORITHM_NAME		"PBKDF2-SHA1 AES " SHA1_N_STR MMX_TYPE
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
#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

#define BIG_ENOUGH 		(8192 * 32)

// increase me (in multiples of 16) to increase the decrypted and search area
#define SAFETY_FACTOR 		16

static struct fmt_tests agile_keychain_tests[] = {
	{"$blockchain$400$53741f25a90ef521c90bb2fd73673e64089ff2cca6ba3cbf6f34e0f80f960b2f60b9ac48df009dc30c288dcf1ade5f16c70a3536403fc11a68f242ba5ad3fcceae3ca5ecd23905997474260aa1357fc322b1434ffa026ba6ad33707c9ad5260e7230b87d8888a45ddc27513adb30af8755ec0737963ae6bb281318c48f224e9c748f6697f75f63f718bebb3401d6d5f02cf62b1701c205762c2f43119b68771ed10ddab79b5f74f56d611f61f77b8b65b5b5669756017429633118b8e5b8b638667e44154de4cc76468c4200eeebda2711a65333a7e3c423c8241e219cdca5ac47c0d4479444241fa27da20dba1a1d81e778a037d40d33ddea7c39e6d02461d97185f66a73deedff39bc53af0e9b04a3d7bf43648303c9f652d99630cd0789819376d68443c85f0eeb7af7c83eecddf25ea912f7721e3fb73ccaedf860f0f033ffc990ed73db441220d0cbe6e029676fef264dc2dc497f39bedf4041ba355d086134744d5a36e09515d230cd499eb20e0c574fb1bd9d994ce26f53f21d06dd58db4f8e0efbcaee7038df793bbb3daa96", "strongpassword"},
	{"$blockchain$384$ece598c58b22a3b245a02039ce36bdf589a86b6344e802b4a3ac9b727cc0b6977e9509bc1ac4d1b7b9cbf9089ecdc89706f0a469325f7ee218b2212b6cd3e32677be20eee91e267fe13ebded02946d4ae1163ef22b3dca327d7390091247ac770288a0c7be181b21a48a8f945d9913cdfdc4cfd739ee3a41ced11cacde22e3233250e36f8b8fb4d81de5298a84374af75b88afda3438eed232e52aa0eb29e0d475456c86ae9d1aaadca14bc25f273c93fd4d7fd8316ed5306733bca77e8214277edd3155342abe0710985dc20b4f80e6620e386aa7658f92df25c7c932f0eb1beca25253662bd558647a3ba741f89450bfdba59a0c016477450fbcecd62226626e06ed2e3f5a4180e32d534c7769bcd1160aad840cfd3b7b13a90d34fedb3408fe74379a9e8a840fe3bfee8e0ee01f77ee389613fa750c3d2771b83eeb4e16598f76c15c311c325bd5d54543571aa20934060e332f451e58d67ad0f4635c0c021fa76821a68d64f1a5fb6fd70365eef4442cedcc91eb8696d52d078807edd89d", "qwertyuiop1"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned char data[BIG_ENOUGH];
	int length;
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
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
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
	if ((p = strtok(ctcopy, "$")) == NULL)
		goto err;
	len = atoi(p);
	if(len > BIG_ENOUGH)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != len * 2)
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
	p = strtok(ctcopy, "$");
	cs->length = atoi(p);
	p = strtok(NULL, "$");
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
	AES_cbc_encrypt(data + 16, out, SAFETY_FACTOR, &akey, iv, AES_DECRYPT);
	/* various tests */
	if (out[0] != '{') // fast test
		return -1;

	// We are assuming that "guid" will be found in the first block
	// itself (when SAFETY_FACTOR is 16).
	if (memmem(out, SAFETY_FACTOR, "\"guid\"", 6))
		return 0;

	if (memmem(out, SAFETY_FACTOR, "sharedKey", 9))
		return 0;

	// the tests above should be enough (TM)
	// if (memmem(out, cur_salt->length, "pbkdf2_iterations", 17))
	//	return 0;

	return -1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
#ifdef MMX_COEF
		unsigned char master[MAX_KEYS_PER_CRYPT][32];
		int lens[MAX_KEYS_PER_CRYPT], i;
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens,
			cur_salt->data, 16, 10, pout, 32, 0);
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
			10, master, 32, 0);
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

struct fmt_main fmt_blockchain = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		agile_keychain_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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

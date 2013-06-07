/* blockchain "My Wallet" cracker patch for JtR. Hacked together during June of
 * 2013 by Dhiru Kholia <dhiru at openwall.com>.
 *
 * See https://blockchain.info/wallet/wallet-format
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru at openwall.com>
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation. */

#include <string.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#undef MMX_COEF // XXX
#include "pbkdf2_hmac_sha1.h"
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               1 // tuned on core i7
#endif

#define FORMAT_LABEL		"blockchain"
#define FORMAT_NAME		"blockchain My Wallet PBKDF2-HMAC-SHA-1 AES (10 iterations!)"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define PLAINTEXT_LENGTH	125
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define BIG_ENOUGH 		(8192 * 32)

static struct fmt_tests agile_keychain_tests[] = {
	{"$blockchain$400$53741f25a90ef521c90bb2fd73673e64089ff2cca6ba3cbf6f34e0f80f960b2f60b9ac48df009dc30c288dcf1ade5f16c70a3536403fc11a68f242ba5ad3fcceae3ca5ecd23905997474260aa1357fc322b1434ffa026ba6ad33707c9ad5260e7230b87d8888a45ddc27513adb30af8755ec0737963ae6bb281318c48f224e9c748f6697f75f63f718bebb3401d6d5f02cf62b1701c205762c2f43119b68771ed10ddab79b5f74f56d611f61f77b8b65b5b5669756017429633118b8e5b8b638667e44154de4cc76468c4200eeebda2711a65333a7e3c423c8241e219cdca5ac47c0d4479444241fa27da20dba1a1d81e778a037d40d33ddea7c39e6d02461d97185f66a73deedff39bc53af0e9b04a3d7bf43648303c9f652d99630cd0789819376d68443c85f0eeb7af7c83eecddf25ea912f7721e3fb73ccaedf860f0f033ffc990ed73db441220d0cbe6e029676fef264dc2dc497f39bedf4041ba355d086134744d5a36e09515d230cd499eb20e0c574fb1bd9d994ce26f53f21d06dd58db4f8e0efbcaee7038df793bbb3daa96", "strongpassword"},
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

// XXX implement valid
static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext,  "$blockchain$", 12) != 0)
		return 0;

	return 1;
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

	ctcopy += 12;
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
	unsigned char out[BIG_ENOUGH];
	AES_KEY akey;
	unsigned char iv[16] = { 0 };

	if(AES_set_decrypt_key(derived_key, 256, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed in crypt!\n");
	}
	AES_cbc_encrypt(data, out, cur_salt->length, &akey, iv, AES_DECRYPT);

	/* various tests */
	if (jtr_memmem(out, cur_salt->length, "pbkdf2_iterations", 17))
		return 0;

	if (jtr_memmem(out, cur_salt->length, "sharedKey", 9))
		return 0;

	// XXX more tests required?
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
		unsigned char master[32];
		/* fixed salt :-( :-( */
		unsigned char salt[16] = {83,116,31,37,169,14,245,33,201,11,178,253,115,103,62,100};
		pbkdf2_sha1((unsigned char *)saved_key[index],
			strlen(saved_key[index]),
			salt, 16,
			10, master, 32, 0);
		if(blockchain_decrypt(master, cur_salt->data) == 0)
			cracked[index] = 1;
		else
			cracked[index] = 0;
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

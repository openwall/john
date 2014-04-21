/* bitcoin-qt (bitcoin) wallet cracker patch for JtR. Hacked together during
 * April of 2013 by Dhiru Kholia <dhiru at openwall dot com>.
 *
 * Also works for Litecoin-Qt (litecoin) wallet files!
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru at openwall dot com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * This cracks password protected bitcoin (bitcoin-qt) "wallet" files.
 *
 * bitcoin => https://github.com/bitcoin/bitcoin
 *
 * Thanks to Solar for asking to add support for bitcoin wallet files.
 */

#include <openssl/evp.h>
#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               1
static int omp_t = 1;
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"Bitcoin"
#define FORMAT_NAME		""
#define ALGORITHM_NAME		"SHA256 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	64
#define BINARY_SIZE		0
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define SZ 			128

static struct fmt_tests bitcoin_tests[] = {
	/* bitcoin wallet hashes */
	{"$bitcoin$96$169ce74743c260678fbbba92e926198702fd84e46ba555190f6f3d82f6852e4adeaa340d2ac065288e8605f13d1d7c86$16$26049c64dda292d5$177864$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "openwall"},
	{"$bitcoin$96$bd97a08e00e38910550e76848949285b9702fe64460f70d464feb2b63f83e1194c745e58fa4a0f09ac35e5777c507839$16$26049c64dda292d5$258507$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "password"},
	{"$bitcoin$96$4eca412eeb04971428efec70c9e18fb9375be0aa105e7eec55e528d0ba33a07eb6302add36da86736054dee9140ec9b8$16$26049c64dda292d5$265155$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "strongpassword"},
	/* litecoin wallet hash */
	{"$bitcoin$96$54401984b32448917b6d18b7a11debe91d62aaa343ab62ed98e1d3063f30817832c744360331df94cbf1dcececf6d00e$16$bfbc8ee2c07bbb4b$194787$96$07a206d5422640cfa65a8482298ad8e8598b94d99e2c4ce09c9d015b734632778cb46541b8c10284b9e14e5468b654b9$66$03fe6587bf580ee38b719f0b8689c80d300840bbc378707dce51e6f1fe20f49c20", "isyourpasswordstronger"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	unsigned char cry_master[SZ];
	int cry_master_length;
	unsigned char cry_salt[SZ];
	int cry_salt_length;
	int cry_rounds;
	unsigned char ckey[SZ];
	int ckey_length;
	unsigned char public_key[SZ];
	int public_key_length;
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

// #define  BTC_DEBUG

#ifdef BTC_DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static int ishex(char *q)
{
       while (atoi16[ARCH_INDEX(*q)] != 0x7F)
               q++;
       return !*q;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p = NULL;
	int res;
	if (strncmp(ciphertext, "$bitcoin$", 9))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 9;

	// FIXME: The author of the format could add some comments
	//        explaining what each part of the hash means...

	if ((p = strtok(ctcopy, "$")) == NULL)
		goto err;
	if (strlen(p) > 10)	// FIXME: can > 10 safely be reduced to >= 10?
		goto err;
	res = atoi(p);	// FIXME: atoi: undefined behavior
	if ((p = strtok(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) > 10)
		goto err;
	res = atoi(p);	// FIXME: atoi: undefined behavior
	if ((p = strtok(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2)
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) > 10)	// FIXME: there's still the change of an overflow!
		goto err;
	// res = atoi(p); /* cry_rounds */
	if ((p = strtok(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) > 10)
		goto err;
	res = atoi(p); /* ckey_length */
	if ((p = strtok(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2)
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) > 10)
		goto err;
	res = atoi(p); /* public_key_length */
	if ((p = strtok(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2)
		goto err;
	if (!ishex(p))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	int i;
	char *p;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += 9;
	p = strtok(ctcopy, "$");
	cs.cry_master_length = atoi(p) / 2;
	p = strtok(NULL, "$");
	for (i = 0; i < cs.cry_master_length; i++)
		cs.cry_master[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "$");
	cs.cry_salt_length = atoi(p) / 2;
	p = strtok(NULL, "$");
	for (i = 0; i < cs.cry_salt_length; i++)
		cs.cry_salt[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtok(NULL, "$");
	cs.cry_rounds = atoi(p);

	p = strtok(NULL, "$");
	cs.ckey_length = atoi(p) / 2;
	p = strtok(NULL, "$");
	for (i = 0; i < cs.ckey_length; i++)
		cs.ckey[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "$");
	cs.public_key_length = atoi(p) / 2;
	p = strtok(NULL, "$");
	for (i = 0; i < cs.public_key_length; i++)
		cs.public_key[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char key[32];
		unsigned char output[SZ];
		unsigned char iv[16];
		int fOk = 1;
		int padval = 0;
		EVP_CIPHER_CTX ctx;
		int nPLen = cur_salt->cry_master_length, nFLen = 0;
		EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), cur_salt->cry_salt,
				(unsigned char *)saved_key[index], strlen(saved_key[index]),
				cur_salt->cry_rounds, key, iv);

		/* NOTE: write our code instead of using following high-level OpenSSL functions */
		EVP_CIPHER_CTX_init(&ctx);
		if (fOk)
			fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);
		if (fOk)
			fOk = EVP_DecryptUpdate(&ctx, output, &nPLen, cur_salt->cry_master, cur_salt->cry_master_length);
		if (fOk)
			fOk = EVP_DecryptFinal_ex(&ctx, output + nPLen, &nFLen);
		EVP_CIPHER_CTX_cleanup(&ctx);
		if (fOk) {
			padval = *(output + nPLen + 15);
			if (padval >= 4) { /* good enough? */
				/* NOTE: check remaining padding bytes too! */
				any_cracked = cracked[index] = 1;
				// print_hex(output + nPLen, 16);
			}
		}
		/* NOTE: do we really need to add "the" stronger check? */
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
	return cracked[index];
}

static void bitcoin_set_key(char *key, int index)
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

#if FMT_MAIN_VERSION
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)my_salt->cry_rounds;
}
#endif

struct fmt_main fmt_bitcoin = {
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
		FMT_CASE | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		bitcoin_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
#endif
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		bitcoin_set_key,
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

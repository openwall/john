/* Cracker for Oracle's O5LOGON protocol hashes. Hacked together during
 * September of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * O5LOGON is used since version 11g. CVE-2012-3137 applies to Oracle 11.1
 * and 11.2 databases. Oracle has "fixed" the problem in version 11.2.0.3.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

/*
 * Modifications (c) 2014 Harrison Neal, released under the same terms
 * as the original.
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"
#include "sha.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               512 // tuned on core i7
#endif

#define FORMAT_LABEL		"o5logon-aesni"
#define FORMAT_NAME		"Oracle O5LOGON protocol w/ OpenSSL AES-NI support"
#define ALGORITHM_NAME		"SHA1 (AES-NI AES) 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define CIPHERTEXT_LENGTH	48
#define SALT_LENGTH		10
#define BINARY_SIZE		0
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests o5logon_tests[] = {
	{"$o5logon$566499330E8896301A1D2711EFB59E756D41AF7A550488D82FE7C8A418E5BE08B4052C0DC404A805C1D7D43FE3350873*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$3BB71A77E1DBB5FFCCC8FC8C4537F16584CB5113E4CCE3BAFF7B66D527E32D29DF5A69FA747C4E2C18C1837F750E5BA6*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$ED91B97A04000F326F17430A65DACB30CD1EF788E6EC310742B811E32112C0C9CC39554C9C01A090CB95E95C94140C28*7FD52BC80AA5836695D4", "test1"},
	{"$o5logon$B7711CC7E805520CEAE8C1AC459F745639E6C9338F192F92204A9518B226ED39851C154CB384E4A58C444A6DF26146E4*3D14D54520BC9E6511F4", "openwall"},
	{"$o5logon$76F9BBAEEA9CF70F2A660A909F85F374F16F0A4B1BE1126A062AE9F0D3268821EF361BF08EBEF392F782F2D6D0192FD6*3D14D54520BC9E6511F4", "openwall"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, any_cracked;

static EVP_CIPHER_CTX *evp_ctx;
static const EVP_CIPHER **evp_cipher;

static struct custom_salt {
	char unsigned salt[SALT_LENGTH]; /* AUTH_VFR_DATA */
	char unsigned ct[CIPHERTEXT_LENGTH]; /* AUTH_SESSKEY */
} *cur_salt;

static void init(struct fmt_main *self)
{
	int i;

#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);

	evp_ctx = mem_calloc_tiny(sizeof(*evp_ctx) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	evp_cipher = mem_calloc_tiny(sizeof(*evp_cipher) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);

	for (i = 0; i < self->params.max_keys_per_crypt; i++) {
		EVP_CIPHER_CTX_init(&evp_ctx[i]);
		EVP_CIPHER_CTX_set_padding(&evp_ctx[i], 0);

		evp_cipher[i] = EVP_aes_192_cbc();
	}
}

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
	char *p;
	if (strncmp(ciphertext,  "$o5logon$", 9))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 9;
	p = strtok(ctcopy, "*"); /* ciphertext */
	if(!p)
		goto err;
	if(strlen(p) != CIPHERTEXT_LENGTH * 2)
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt */
		goto err;
	if(strlen(p) != SALT_LENGTH * 2)
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
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	ctcopy += 9;	/* skip over "$o5logon$" */
	p = strtok(ctcopy, "*");
	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < SALT_LENGTH; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
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
		memset(cracked, 0, sizeof(*cracked) * count);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char key[24];
		unsigned char pt[16];
		unsigned char iv[16];

		int evp_len;

		SHA_CTX ctx;

		memset(&key[20], 0, 4);
		memcpy(iv, cur_salt->ct + 16, 16);

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA1_Update(&ctx, cur_salt->salt, 10);
		SHA1_Final(key, &ctx);

		// Mod: use EVP routines
		EVP_DecryptInit(&evp_ctx[index], evp_cipher[index], key, iv);
		EVP_DecryptUpdate(&evp_ctx[index], pt, &evp_len, cur_salt->ct + 32, 16);
		if (!memcmp(pt + 8, "\x08\x08\x08\x08\x08\x08\x08\x08", 8))
			any_cracked = cracked[index] = 1;

		EVP_CIPHER_CTX_cleanup(&evp_ctx[index]);
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

static void o5logon_set_key(char *key, int index)
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

struct fmt_main fmt_o5logon_aesni = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
		},
#endif
		o5logon_tests
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
		{
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		o5logon_set_key,
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

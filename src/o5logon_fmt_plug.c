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

#include "sha.h"
#include <string.h>
#include <openssl/aes.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"o5logon"
#define FORMAT_NAME		"Oracle O5LOGON protocol"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
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
static int *cracked;

static struct custom_salt {
	char unsigned salt[10]; /* AUTH_VFR_DATA */
	char unsigned ct[48]; /* AUTH_SESSKEY */
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
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$o5logon$", 9);
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
	for (i = 0; i < 48; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 10; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

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
		unsigned char key[24] = {0};
		unsigned char pt[48];
		unsigned char iv[16] = {0};
		AES_KEY akey;
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA1_Update(&ctx, cur_salt->salt, 10);
		SHA1_Final(key, &ctx);

		AES_set_decrypt_key(key, 192, &akey);
		AES_cbc_encrypt(cur_salt->ct + 16, pt + 16, 32, &akey, iv, AES_DECRYPT);
		if (!memcmp(pt + 40, "\x08\x08\x08\x08\x08\x08\x08\x08", 8)) {
			cracked[index] = 1;
		}
		else
			cracked[index] = 0;

	}
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

struct fmt_main o5logon_fmt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		o5logon_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
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

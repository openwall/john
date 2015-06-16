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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_o5logon;
#elif FMT_REGISTERS_H
john_register_one(&fmt_o5logon);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"
#include "sha.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes/aes.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               512 // tuned on core i7
#endif
//#define OMP_SCALE                8192 // tuned on K8-Dual HT
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"o5logon"
#define FORMAT_NAME		"Oracle O5LOGON protocol"
#define ALGORITHM_NAME		"SHA1 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define CIPHERTEXT_LENGTH	48
#define SALT_LENGTH		10
#define BINARY_SIZE		0
#define BINARY_ALIGN	1
#define SALT_ALIGN		1
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests o5logon_tests[] = {
	{"$o5logon$566499330E8896301A1D2711EFB59E756D41AF7A550488D82FE7C8A418E5BE08B4052C0DC404A805C1D7D43FE3350873*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$3BB71A77E1DBB5FFCCC8FC8C4537F16584CB5113E4CCE3BAFF7B66D527E32D29DF5A69FA747C4E2C18C1837F750E5BA6*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$ED91B97A04000F326F17430A65DACB30CD1EF788E6EC310742B811E32112C0C9CC39554C9C01A090CB95E95C94140C28*7FD52BC80AA5836695D4", "test1"},
	{"$o5logon$B7711CC7E805520CEAE8C1AC459F745639E6C9338F192F92204A9518B226ED39851C154CB384E4A58C444A6DF26146E4*3D14D54520BC9E6511F4", "openwall"},
	{"$o5logon$76F9BBAEEA9CF70F2A660A909F85F374F16F0A4B1BE1126A062AE9F0D3268821EF361BF08EBEF392F782F2D6D0192FD6*3D14D54520BC9E6511F4", "openwall"},
	{"$o5logon$C35A36EA7FF7293EF828B2BD5A2830CA28A57BF621EAE14B605D41A88FC2CF7EFE7C73495FB22F06D6D98317D63DDA71*406813CBAEED2FD4AD23", "MDDATA"},
	{"$o5logon$B9AC30E3CD7E1D7C95FA17E1C62D061289C36FD5A6C45C098FF7572AB9AD2B684FB7E131E03CE1543A5A99A30D68DD13*447BED5BE70F7067D646", "sys"},
	// the following hash (from HITCON 2014 CTF) revealed multiple bugs in this format (false positives)!
	// m3odbe
	// m3o3rt
	{"$o5logon$A10D52C1A432B61834F4B0D9592F55BD0DA2B440AEEE1858515A646683240D24A61F0C9366C63E93D629292B7891F44A*878C0B92D61A594F2680", "m3ow00"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, any_cracked;

static struct custom_salt {
	char unsigned salt[SALT_LENGTH]; /* AUTH_VFR_DATA */
	char unsigned ct[CIPHERTEXT_LENGTH]; /* AUTH_SESSKEY */
} *cur_salt;

static aes_fptr_cbc aesFunc;

static void init(struct fmt_main *self)
{
	static char Buf[128];

#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));

	aesFunc = get_AES_dec192_CBC();
	sprintf(Buf, "%s %s", self->params.algorithm_name,
	        get_AES_type_string());
	self->params.algorithm_name=Buf;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
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
	p = strtokm(ctcopy, "*"); /* ciphertext */
	if(!p)
		goto err;
	if(strlen(p) != CIPHERTEXT_LENGTH * 2)
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
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
	p = strtokm(ctcopy, "*");
	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
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
	const int count = *pcount;
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

		// No longer using AES key here.

		SHA_CTX ctx;

		memset(&key[20], 0, 4);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA1_Update(&ctx, cur_salt->salt, 10);
		SHA1_Final(key, &ctx);

		memcpy(iv, cur_salt->ct + 16, 16);

		// Using AES function:
		// in (cipher), out (plain), key, block count, iv
		aesFunc(cur_salt->ct + 32, pt, key, 1, iv);
		if (!memcmp(pt + 8, "\x08\x08\x08\x08\x08\x08\x08\x08", 8)) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
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

static void o5logon_set_key(char *key, int index)
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

struct fmt_main fmt_o5logon = {
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		o5logon_tests
	}, {
		init,
		done,
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
		NULL,
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

#endif /* plugin stanza */

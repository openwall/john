/*
 * Post.Office MD5 cracker.
 * Uses a modified version of Solar Designer's MD5 routine.
 *
 * This file adapted from other code in this project.
 *
 * To extract these crypts from Post.Office, use something
 * along the lines of:
 *
 *   /usr/local/post.office/cmdutils/listacct \
 *	-i POP-Address,Account-ID,Password,Name | \
 *	perl -ne 'chop;@a=split(/;/);print
 *	(($a[0]?$a[0]:$a[1]).":".$a[2].":0:0:".$a[3]."::\n");'
 *
 * Then find any passwords ending in UNIX-PASSWORD and tidy
 * them up (and crack as plain DES crypts); this module will
 * handle the others.
 *
 * This crypt format may also be found in LDAP directories of
 * users migrated from Post.Office, for example the crypt format
 * can be supported by OpenWave and qmail-ldap.
 *
 * Copyright (c) 2005 David Luyer <david at luyer.net>
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_PO;
#elif FMT_REGISTERS_H
john_register_one(&fmt_PO);
#else

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"

#define FORMAT_LABEL			"po"
#define FORMAT_NAME			"Post.Office"
#define ALGORITHM_NAME			"MD5 32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		64
#define CIPHERTEXT_LENGTH		64

#define BINARY_SIZE			4
#define BINARY_ALIGN			4
#define SALT_SIZE			32
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"550c41c11bab48f9dbd8203ed313eef0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "abc123"},
	{"0c78bdef7d5448105cfbbc9aaa490a44550c41c11bab48f9dbd8203ed313eef0", "abc123"},
	{"9be296cf73d2f548dae3cccafaff1dd982916963c701200625cba2acd40d6569", "FRED"},
	{"a0e2078f0354846ec5bc4c7d7be08a4682916963c701200625cba2acd40d6569", ""},
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
static int saved_key_len;
static unsigned char po_buf[SALT_SIZE * 2 + 2 + PLAINTEXT_LENGTH + 128 /* MD5 scratch space */];
static uint32_t MD5_out[4];

static void po_init(struct fmt_main *self) {
	/* Do nothing */
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strlen(ciphertext) == 64 &&
	    strspn(ciphertext, HEXCHARS_lc) == 64) {
		return 1;
	}
	return 0;
}

#define COMMON_GET_HASH_VAR MD5_out
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	return	((int)atoi16[ARCH_INDEX(((char *)salt)[0])] |
		((int)atoi16[ARCH_INDEX(((char *)salt)[1])] << 4) |
		((int)atoi16[ARCH_INDEX(((char *)salt)[2])] << 8)) & (SALT_HASH_SIZE - 1);
}

static void set_key(char *key, int index)
{
	saved_key_len = strnzcpyn(saved_key, key, sizeof(saved_key));
}

static char *get_key(int index)
{
	saved_key[PLAINTEXT_LENGTH] = 0;
	return saved_key;
}

static int cmp_all(void *binary, int count)
{
	return *(uint32_t *)binary == MD5_out[0];
}

static int cmp_one(void *binary, int index)
{
	return 1;
}

static int cmp_exact(char *source, int index)
{
        static char fullmd5[16];
        int i;

        for (i=0;i<16;i++)
        {
                fullmd5[i] = atoi16[ARCH_INDEX(source[i*2])]*16 + atoi16[ARCH_INDEX(source[i*2+1])];
        }
	return !memcmp(fullmd5, MD5_out, sizeof(fullmd5));
}

static void *get_binary(char *ciphertext)
{
	static char *binarycipher;
        int i;

	if (!binarycipher) binarycipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

        for (i=0;i<BINARY_SIZE;i++)
        {
                binarycipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
        }
        return (void *)binarycipher;
}

static char *get_salt(char *ciphertext)
{
	static char out[SALT_SIZE];

	memcpy(out, ciphertext + 32, SALT_SIZE);
	return out;
}

static void set_salt(char *salt)
{
	memcpy(po_buf, salt, 32);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	MD5_CTX ctx;

	po_buf[32] = 'Y';
	memcpy(po_buf + 33, saved_key, saved_key_len);
	po_buf[saved_key_len + 33] = 247;
	memcpy(po_buf + saved_key_len + 34, po_buf, 32);
	MD5_Init(&ctx);
	MD5_Update(&ctx, po_buf, saved_key_len+66);
	MD5_Final((unsigned char*)MD5_out, &ctx);

	return *pcount;
}

struct fmt_main fmt_PO = {
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
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		{ NULL },
		tests
	}, {
		po_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		(void *(*)(char *))get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		(void (*)(void *))set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

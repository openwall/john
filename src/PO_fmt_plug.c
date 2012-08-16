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

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5_go.h"

typedef ARCH_WORD_32 MD5_word;
typedef MD5_word MD5_binary[4];
#if ARCH_LITTLE_ENDIAN
#define MD5_out MD5_out_go
#else
#define MD5_out MD5_bitswapped_out_go
#endif
extern MD5_binary MD5_out;

#define FORMAT_LABEL			"po"
#define FORMAT_NAME			"Post.Office MD5"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		64
#define CIPHERTEXT_LENGTH		64

#define BINARY_SIZE			4
#define SALT_SIZE			32

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
static char po_buf[SALT_SIZE * 2 + 2 + PLAINTEXT_LENGTH + 128 /* MD5 scratch space */];

static void po_init(struct fmt_main *self) {
	/* Do nothing */
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strlen(ciphertext) == 64 &&
	    strspn(ciphertext, "0123456789abcdef") == 64) {
		return 1;
	}
	return 0;
}

static int binary_hash_0(void *binary)
{
	return *(MD5_word *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(MD5_word *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(MD5_word *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(MD5_word *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(MD5_word *)binary & 0xFFFFF;
}

static int get_hash_0(int index)
{
	return MD5_out[0] & 0xF;
}

static int get_hash_1(int index)
{
	return MD5_out[0] & 0xFF;
}

static int get_hash_2(int index)
{
	return MD5_out[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return MD5_out[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return MD5_out[0] & 0xFFFFF;
}

static int salt_hash(void *salt)
{
	return	((int)atoi16[ARCH_INDEX(((char *)salt)[0])] |
		((int)atoi16[ARCH_INDEX(((char *)salt)[1])] << 4) |
		((int)atoi16[ARCH_INDEX(((char *)salt)[2])] << 8)) & (SALT_HASH_SIZE - 1);
}

static void set_key(char *key, int index)
{
	strnfcpy(saved_key, key, PLAINTEXT_LENGTH);
	saved_key_len = strlen(saved_key);
}

static char *get_key(int index)
{
	saved_key[PLAINTEXT_LENGTH] = 0;
	return saved_key;
}

static int cmp_all(void *binary, int index)
{
	/* also used for cmp_one */
	return *(MD5_word *)binary == MD5_out[0];
}

static int cmp_exact(char *source, int index)
{
        static char fullmd5[16];
        int i;

        for(i=0;i<16;i++)
        {
                fullmd5[i] = atoi16[ARCH_INDEX(source[i*2])]*16 + atoi16[ARCH_INDEX(source[i*2+1])];
        }
	return !memcmp(fullmd5, MD5_out, sizeof(MD5_binary));
}

static void *get_binary(char *ciphertext)
{
	static char *binarycipher;
        int i;

	if (!binarycipher) binarycipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

        for(i=0;i<BINARY_SIZE;i++)
        {
                binarycipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
        }
        return (void *)binarycipher;
}

static char *get_salt(char *ciphertext)
{
	static char *out;

	if (!out) out = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);
	memcpy(out, ciphertext + 32, SALT_SIZE);
	return out;
}

static void set_salt(char *salt)
{
	memcpy(po_buf, salt, 32);
}

static void po_crypt(int count)
{
	po_buf[32] = 'Y';
	memcpy(po_buf + 33, saved_key, saved_key_len);
	po_buf[saved_key_len + 33] = 247;
	memcpy(po_buf + saved_key_len + 34, po_buf, 32);
	MD5_Go((unsigned char *)po_buf, saved_key_len + 66);
}

struct fmt_main fmt_PO = {
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
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		po_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		(void *(*)(char *))get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		(void (*)(void *))set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		po_crypt,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		cmp_all,
		cmp_all,
		cmp_exact
	}
};



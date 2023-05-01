/*
  KRB4_fmt.c

  AFS/krb4 TGT dictionary attack module for Solar Designer's John the Ripper.

  tgtsnarf files should only contain entries for one cell/realm.

  Copyright (c) 1999 Dug Song <dugsong@monkey.org>
  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. The name of author may not be used to endorse or promote products
     derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_KRB4;
#elif FMT_REGISTERS_H
john_register_one(&fmt_KRB4);
#else

#include <string.h>
#include <ctype.h>
#include <openssl/des.h>

#include "arch.h"
#include "DES_std.h"
#include "KRB4_std.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#define TGT_LENGTH		16	/* 2 des_cblock's */

#define FORMAT_LABEL		"krb4"
#define FORMAT_NAME		"Kerberos v4 TGT"
#define FORMAT_TAG		"$af$"
#define FORMAT_TAG2		"$k4$"
#define FORMAT_TAG_LEN	(sizeof(FORMAT_TAG)-1)

#define ALGORITHM_NAME		"DES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x208
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		0
#define BINARY_ALIGN		MEM_ALIGN_NONE
#define SALT_SIZE		TGT_LENGTH + REALM_SZ
#define SALT_ALIGN		MEM_ALIGN_NONE
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests tests[] = {
	{"$af$UMICH.EDU$bb46613c503ad92e649d99d038efddb2", "w00w00"},
	{"$af$UMICH.EDU$95cd4367d4828d117b745ed63b9229be", "asdfjkl;"},
	{"$af$UMICH.EDU$000084efbde96969fd54d1a2ec8c287d", "hello!"},
	{"$af$UMICH.EDU$e9660a21b280875a7ecfc68aa771e34a", "a12345"},
	{"$af$UMICH.EDU$566f2b8629b9be36680866b0e613f239", "a1b2c3"},
	{"$af$UMICH.EDU$bebcedf43f7f2aa78cf9c0639e494c92", "abcdefg12345678"},
	{"$af$ENGIN.UMICH.EDU$9ef1034301e1f1fcf1516cb65aa1cc79", "asdfjkl;"},
	{"$af$ENGIN.UMICH.EDU$02ad23a6364df67a4db473de053cacbb", "a1b2c3"},
	{"$af$ENGIN.UMICH.EDU$14d0a59a2f9e746f1a3bf02ec4fb447e", "abc123!"},
	{"$af$ENGIN.UMICH.EDU$44feffd06e68e30bc8890e253760858d", "12345"},
	{NULL}
};

static const unsigned char odd_parity[256]={
	1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
       16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
       32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
       49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
       64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
       81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
       97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
      112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
      128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
      145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
      161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
      176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
      193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
      208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
      224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
      241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
};

static struct salt_st {
	unsigned char		tgt[TGT_LENGTH];
	char			realm[REALM_SZ+1];
} *saved_salt;

static struct key_st {
	DES_cblock		key;
	DES_key_schedule	sched;
	char			string[PLAINTEXT_LENGTH + 1];
} saved_key;


static int valid(char *ciphertext, struct fmt_main *self)
{
	char *tgt;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0 &&
	    strncmp(ciphertext, FORMAT_TAG2, FORMAT_TAG_LEN) != 0)
		return 0;
	ciphertext += FORMAT_TAG_LEN;
	tgt = strchr(ciphertext, '$');

	if (!tgt)
		return 0;
	if (tgt-ciphertext > REALM_SZ)
		return 0;
	++tgt;
	if (!ishexlc(tgt)) return 0;
	if (strlen(tgt) != TGT_LENGTH * 2)
		return 0;

	return 1;
}

static int hex_decode(char *src, unsigned char *dst, int outsize)
{
	char *p, *pe;
	unsigned char *q, *qe, ch, cl;

	pe = src + strlen(src);
	qe = dst + outsize;

	for (p = src, q = dst; p < pe && q < qe && isxdigit(((unsigned char)(*p))); p += 2) {
		ch = tolower(((unsigned char)(p[0])));
		cl = tolower(((unsigned char)(p[1])));

		if ((ch >= '0') && (ch <= '9')) ch -= '0';
		else if ((ch >= 'a') && (ch <= 'f')) ch -= 'a' - 10;
		else return (-1);

		if ((cl >= '0') && (cl <= '9')) cl -= '0';
		else if ((cl >= 'a') && (cl <= 'f')) cl -= 'a' - 10;
		else return (-1);

		*q++ = (ch << 4) | cl;
	}
	return (q - dst);
}

static void *get_salt(char *ciphertext)
{
	static struct salt_st salt;
	char *p;

	memset(&salt, 0, sizeof(salt));
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) == 0) {
		ciphertext += FORMAT_TAG_LEN;
		p = strchr(ciphertext, '$');
		strnzcpy(salt.realm, ciphertext, (p - ciphertext) + 1);
		ciphertext = p + 1;
	}
	else {
		salt.realm[0] = '\0';
		ciphertext += 4;
	}
	if (hex_decode(ciphertext, salt.tgt, sizeof(salt.tgt)) !=
	    sizeof(salt.tgt))
		return (NULL);

	return (&salt);
}

static void set_salt(void *salt)
{
	saved_salt = (struct salt_st *)salt;
}

static void krb4_set_key(char *key, int index)
{
	strnzcpy(saved_key.string, key, sizeof(saved_key.string));
}

static char *get_key(int index)
{
	return (saved_key.string);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	if (saved_salt->realm[0] != '\0')
		afs_string_to_key(saved_key.string,
		                  saved_salt->realm,
		                  &saved_key.key);
	else
		DES_string_to_key(saved_key.string,
		                  &saved_key.key);

	return *pcount;
}

static int krb4_check_parity(DES_cblock *key)
{
	int i;

	for (i = 0; i < DES_KEY_SZ; i++) {
		if ((*key)[i] != odd_parity[(*key)[i]])
			return (0);
	}
	return 1;
}

static int cmp_all(void *binary, int count)
{
	DES_cblock tmp;

	DES_set_key_unchecked(&saved_key.key, &saved_key.sched);

	DES_pcbc_encrypt(saved_salt->tgt, (unsigned char *)&tmp,
	                 sizeof(tmp), &saved_key.sched,
	                 &saved_key.key, DES_DECRYPT);

	return (krb4_check_parity(&tmp));
}

static int cmp_one(void *binary, int count)
{
	unsigned char text[TGT_LENGTH];

	DES_pcbc_encrypt(saved_salt->tgt, text,
	                 sizeof(text), &saved_key.sched, &saved_key.key,
	                 DES_DECRYPT);

	return (memcmp(text + 8, "krbtgt", 6) == 0);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_KRB4 = {
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
		{ FORMAT_TAG, FORMAT_TAG2 },
		tests
	}, {
		fmt_default_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		krb4_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
#endif /* HAVE_LIBCRYPTO */

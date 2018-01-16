/*
 * AIX smd5 cracker patch for JtR. Hacked together during April of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_smd5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_smd5);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "md5.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "memdbg.h"

#define FORMAT_LABEL            "aix-smd5"
#define FORMAT_NAME             "AIX LPA {smd5} (modified crypt-md5)"
#define FORMAT_TAG              "{smd5}"
#define FORMAT_TAG1             "$1$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG1_LEN         (sizeof(FORMAT_TAG1)-1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests smd5_tests[] = {
	/* following hashes are AIX non-standard smd5 hashes */
	{"{smd5}s8/xSJ/v$uGam4GB8hOjTLQqvBfxJ2/", "password"},
	{"{smd5}alRJaSLb$aKM3H1.h1ycXl5GEVDH1e1", "aixsucks?"},
	{"{smd5}eLB0QWeS$Eg.YfWY8clZuCxF0xNrKg.", "0123456789ABCDE"},
	/* following hashes are AIX standard smd5 hashes (with corrected tag)
	 * lpa_options = std_hash=true */
	{"$1$JVDbGx8K$T9h8HK4LZxeLPMTAxCfpc1", "password"},
	{"$1$1Cu6fEvv$42kuaJ5fMEqyVStPuFG040", "0123456789ABCDE"},
	{"$1$ql5x.xXL$vYVDhExol2xUBBpERRWcn1", "jtr>hashcat"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	int is_standard;
	unsigned char salt[16];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	char *ctcopy;
	char *keeptr;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0 &&
		strncmp(ciphertext, FORMAT_TAG1, FORMAT_TAG1_LEN))
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		ctcopy += FORMAT_TAG_LEN;
	else
		ctcopy += FORMAT_TAG1_LEN;

	if ((p = strtokm(ctcopy, "$")) == NULL)	/* salt */
		goto err;
	if (strlen(p) != 8)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* hash */
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
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	keeptr = ctcopy;
	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		ctcopy += FORMAT_TAG_LEN;
		cs.is_standard = 0;
	}
	else {
		ctcopy += FORMAT_TAG1_LEN;
		cs.is_standard = 1;
	}

	p = strtokm(ctcopy, "$");
	strncpy((char*)cs.salt, p, 9);
	p = strtokm(NULL, "$");

	MEM_FREE(keeptr);

	return (void *)&cs;
}

#define TO_BINARY(b1, b2, b3) \
	value = \
		(uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out.b[b1] = value >> 16; \
	out.b[b2] = value >> 8; \
	out.b[b3] = value;

static void* get_binary(char *ciphertext)
{
	static union {
		char b[16];
		ARCH_WORD w;
	} out;
	char *pos;
	uint32_t value;

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		pos = ciphertext + FORMAT_TAG_LEN;
	else
		pos = ciphertext + FORMAT_TAG1_LEN;

	while (*pos++ != '$');

	TO_BINARY(0, 6, 12);
	TO_BINARY(1, 7, 13);
	TO_BINARY(2, 8, 14);
	TO_BINARY(3, 9, 15);
	TO_BINARY(4, 10, 5);
	out.b[11] =
		(uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6);

	return out.b;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

/*
 * $Id: md5_crypt.c,v 1.1 2002-05-11 14:42:35 cpbotha Exp $
 *
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * Origin: Id: crypt.c,v 1.3 1995/05/30 05:42:22 rgrimes Exp
 *
 */

static void crypt_md5(char *pw, char *salt, int is_standard, char *passwd)
{
	char *magic = "$1$";
	/* This string is magic for this algorithm.  Having
	 * it this way, we can get get better later on */
	char *sp, *ep;
	unsigned char final[16];
	int sl, pl, i, j;
	MD5_CTX ctx, ctx1;

	/* Refine the Salt first */
	sp = salt;

	/* If it starts with the magic string, then skip that */
	if (!strncmp(sp, magic, strlen(magic)))
		sp += strlen(magic);

	/* It stops at the first '$', max 8 chars */
	for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++)
		continue;

	/* get the length of the true salt */
	sl = ep - sp;

	MD5_Init(&ctx);

	/* The password first, since that is what is most unknown */
	MD5_Update(&ctx,(unsigned char *)pw,strlen(pw));

	// The following license text applies to the "if" code block
	// License: belongs to the PUBLIC DOMAIN, donated to hashcat, credits MUST go to atom
	//          (hashcat) and philsmd for their hard work. Thx
	// Disclaimer: WE PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER
	//         EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
	//         OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	//         Furthermore, NO GUARANTEES THAT IT WORKS FOR YOU AND WORKS CORRECTLY
	if (is_standard) {
		/* Then our magic string */
		MD5_Update(&ctx,(unsigned char *)magic,strlen(magic));

		/* Then the raw salt */
		MD5_Update(&ctx,(unsigned char *)sp,sl);
	}
	else {
		MD5_Update(&ctx,(unsigned char *)sp,sl);
	}

	/* Then just as many characters of the MD5_(pw,salt,pw) */
	MD5_Init(&ctx1);
	MD5_Update(&ctx1,(unsigned char *)pw,strlen(pw));
	MD5_Update(&ctx1,(unsigned char *)sp,sl);
	MD5_Update(&ctx1,(unsigned char *)pw,strlen(pw));

	MD5_Final(final,&ctx1);

	for (pl = strlen(pw); pl > 0; pl -= 16)
		MD5_Update(&ctx,(unsigned char *)final,pl>16 ? 16 : pl);

	memset(final, 0, sizeof final);

	/* Then something really weird... */
	for (j = 0, i = strlen(pw); i; i >>= 1)
		if (i & 1)
			MD5_Update(&ctx, (unsigned char *)final+j, 1);
		else
			MD5_Update(&ctx, (unsigned char *)pw+j, 1);

	/* Now make the output string */
	strcpy(passwd, magic);
	strncat(passwd, sp, sl);
	strcat(passwd, "$");
	MD5_Final(final,&ctx);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for (i = 0; i < 1000; i++) {
		MD5_Init(&ctx1);
		if (i & 1)
			MD5_Update(&ctx1,(unsigned char *)pw,strlen(pw));
		else
			MD5_Update(&ctx1,(unsigned char *)final,16);

		if (i % 3)
			MD5_Update(&ctx1,(unsigned char *)sp,sl);

		if (i % 7)
			MD5_Update(&ctx1,(unsigned char *)pw,strlen(pw));

		if (i & 1)
			MD5_Update(&ctx1,(unsigned char *)final,16);
		else
			MD5_Update(&ctx1,(unsigned char *)pw,strlen(pw));
		MD5_Final(final,&ctx1);
	}
	memcpy(passwd, final, 16);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		crypt_md5(saved_key[index], (char*)cur_salt->salt, cur_salt->is_standard, (char *)crypt_out[index]);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void smd5_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int salt_hash(void *salt)
{
	return *(unsigned int*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_smd5 = {
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
		{ FORMAT_TAG, FORMAT_TAG1 },
		smd5_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		set_salt,
		smd5_set_key,
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

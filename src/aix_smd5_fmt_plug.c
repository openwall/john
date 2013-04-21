/* AIX smd5 cracker patch for JtR. Hacked together during April of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "md5.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               1 // FIXME
#endif

#define FORMAT_LABEL		"aix-smd5"
#define FORMAT_NAME		"AIX smd5 (modified crypt-md5)"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests smd5_tests[] = {
	/* non-standard hash */
	{"{smd5}JVDbGx8K$184fdfd9a6ee848d568bcd72879e8527$0", "password"},
	/* standard hash */
	{"{smd5}JVDbGx8K$2a5c5e31d6bdd265aff6b3e8df93651b$1", "password"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int is_standard;
	char unsigned salt[16];
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
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	char *ctcopy;
	char *keeptr;
	int res;
	if (strncmp(ciphertext, "{smd5}", 6) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 6;

	if ((p = strtok(ctcopy, "$")) == NULL)	/* salt */
		goto err;
	if (strlen(p) != 8)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* hash */
		goto err;
	if (strlen(p) != 32)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* is_standard */
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
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
	keeptr = ctcopy;
	ctcopy += 6;

	p = strtok(ctcopy, "$");
	strncpy((char*)cs.salt, p, 9);
	p = strtok(NULL, "$");
	p = strtok(NULL, "$");
	cs.is_standard = atoi(p);

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = ciphertext + 6 + 8 + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

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
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		crypt_md5(saved_key[index], (char*)cur_salt->salt, cur_salt->is_standard, (char *)crypt_out[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
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

struct fmt_main fmt_smd5 = {
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
		smd5_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		smd5_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

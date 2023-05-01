/*
 * This patch Copyright (C) 2010 by James Nobis - quel
 * - quel NOSPAM quelrod NOSPAM net, and it is herby released to the general
 * public under the follow terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * format specification
 * http://www.hmailserver.com/forum/viewtopic.php?p=97515&sid=b2c1c6ba1e10c2f0654ca9421b2059e8#p97515
 * inspiration from the generic sha-1 and md5
 * Copyright (c) 2010 by Solar Designer
 *
 * JimF Feb, 2015: converted into a 'thin' format, hooked to dynamic_61
 */

#if AC_BUILT
#include "../autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_hmailserver;
#elif FMT_REGISTERS_H
john_register_one(&fmt_hmailserver);
#else

#include "../sha2.h"

#include "../params.h"
#include "../common.h"
#include "../formats.h"
#include "../dynamic.h"

#define FORMAT_LABEL        "hMailServer"
#define FORMAT_NAME         ""

#define ALGORITHM_NAME      "?" /* filled in by dynamic */

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    7

// set PLAINTEXT_LENGTH to 0, so dyna will set this
#define PLAINTEXT_LENGTH	0
#define CIPHERTEXT_LENGTH   64

#define BINARY_SIZE         32
#define DYNA_BINARY_SIZE	16
#define BINARY_ALIGN        4
#define SALT_SIZE           6
#define DYNA_SALT_SIZE		(sizeof(char*))
#define SALT_ALIGN          4

#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static struct fmt_tests hmailserver_tests[] = {
    {"cc06fa688a64cdeea43d3c0fb761fede7e3ccf00a9daea9c79f7d458e06f88327f16dd", "password"},
    {"fee4fd4446aebcb3332aa5c61845b7bcbe5a3126fedf51a6359663d61b87d4f6ee87df", "12345678"},
    {"2d7b784370c488b6548394ba11513e159220c83e2458ed01d8c7cdadd6bf486b433703", "1234"},
    {"0926aadc8d49682c3f091af2dbf7f16f1cc7130b8e6dc86978d3f1bef914ce0096d4b3", "0123456789ABCDE"},
    {NULL}
};

static char Conv_Buf[120];
static struct fmt_main *pDynamic;
static void hmailserver_init(struct fmt_main *self);
static void get_ptr();

/* this function converts a 'native' phps signature string into a $dynamic_6$ syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	if (text_in_dynamic_format_already(pDynamic, ciphertext))
		return ciphertext;

	snprintf(Buf, sizeof(Conv_Buf), "$dynamic_61$%s$%6.6s", &ciphertext[6], ciphertext);
	return Buf;
}

static char *our_split(char *ciphertext, int index, struct fmt_main *self)
{
	get_ptr();
	return pDynamic->methods.split(Convert(Conv_Buf, ciphertext), index, self);
}

static char *our_prepare(char *split_fields[10], struct fmt_main *self)
{
	get_ptr();
	return pDynamic->methods.prepare(split_fields, self);
}


static int hmailserver_valid(char *ciphertext, struct fmt_main *self)
{
	int i;

	if (!ciphertext)
		return 0;

	get_ptr();
	i = strnlen(ciphertext, CIPHERTEXT_LENGTH + SALT_SIZE + 1);

	if (i != CIPHERTEXT_LENGTH + SALT_SIZE)
		return pDynamic->methods.valid(ciphertext, pDynamic);
	return pDynamic->methods.valid(Convert(Conv_Buf, ciphertext), pDynamic);
}

static void * our_salt(char *ciphertext)
{
	get_ptr();
	return pDynamic->methods.salt(Convert(Conv_Buf, ciphertext));
}

static void * our_binary(char *ciphertext)
{
	get_ptr();
	return pDynamic->methods.binary(Convert(Conv_Buf, ciphertext));
}


struct fmt_main fmt_hmailserver =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		0, PLAINTEXT_LENGTH, DYNA_BINARY_SIZE, BINARY_ALIGN, DYNA_SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_DYNAMIC,
		{ NULL },
		{ NULL },
		hmailserver_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		hmailserver_init,
		fmt_default_done,
		fmt_default_reset,
		our_prepare,
		hmailserver_valid,
		our_split
	}
};

static void link_funcs()
{
	fmt_hmailserver.methods.salt   = our_salt;
	fmt_hmailserver.methods.binary = our_binary;
	fmt_hmailserver.methods.split = our_split;
	fmt_hmailserver.methods.prepare = our_prepare;
}

static void hmailserver_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		get_ptr();
		pDynamic->methods.init(pDynamic);
		self->private.initialized = 1;
	}
}

static void get_ptr()
{
	if (!pDynamic) {
		pDynamic = dynamic_THIN_FORMAT_LINK(&fmt_hmailserver, Convert(Conv_Buf, hmailserver_tests[0].ciphertext), "hmailserver", 0);
		link_funcs();
	}
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */

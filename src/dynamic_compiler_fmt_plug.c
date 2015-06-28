/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2015. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2015 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.

 * dynamic_compiler_fmt.c  (in thin fully self describing format)
 *
 * This can be 'any' valid expresion which dynamic_compiler can handle
 *
 * NOTE, only 1 expression can be used
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_CompiledDynamic;
#elif FMT_REGISTERS_H
john_register_one(&fmt_CompiledDynamic);
#else

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"
#include "dynamic_compiler.h"
#include "memdbg.h"

#define FORMAT_LABEL		"dynamic="
#define FORMAT_NAME			""

#define ALGORITHM_NAME		"?"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

#define BINARY_ALIGN		MEM_ALIGN_WORD

#define DYNA_SALT_SIZE		(sizeof(char*))
#define SALT_ALIGN			MEM_ALIGN_WORD

extern const char *dyna_script;
extern const char *dyna_signature;
extern const char *dyna_one_line;
extern int dyna_sig_len;

static struct fmt_tests tests[] = {
	{"@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72", "abc"},
	{NULL},
};

static char Conv_Buf[512];
static int dyna_type;
static char dyna_hash_type[24];
static int dyna_hash_type_len;
static struct fmt_main *pDynamic;
static void our_init(struct fmt_main *self);
static void get_ptr();

/* this function converts a 'native' @dynamic= signature string into a $dynamic_6xxx$ syntax string */
static char *Convert(char *Buf, char *ciphertext, int in_load)
{
	char *cp;

	if (text_in_dynamic_format_already(pDynamic, ciphertext))
		return ciphertext;

	cp = ciphertext;
	if (!strncmp(ciphertext, "@dynamic=", 9)) {
		cp = strchr(&ciphertext[1], '@');
		if (!cp)
			return "*";
		++cp;
	}
	if (in_load)
		snprintf(Buf, sizeof(Conv_Buf), "$dynamic_6xxx$%s", cp);
	else
		snprintf(Buf, sizeof(Conv_Buf), "%s%s", dyna_hash_type, cp);

	return Buf;
}

static char *our_split(char *ciphertext, int index, struct fmt_main *self)
{
	extern int ldr_in_pot;
	if (strncmp(ciphertext, "@dynamic=", 9) && strncmp(ciphertext, dyna_signature, dyna_sig_len)) {
		// convert back into @dynamic@ format
		static char Buf[512];
		sprintf(Buf, "%s%s", dyna_signature, ciphertext);
		ciphertext = Buf;
	}
	if (ldr_in_pot == 1 && !strncmp(ciphertext, "@dynamic=", 9)) {
		static char Buf[512], Buf2[512];
		char *cp = strchr(&ciphertext[1], '@');
		if (cp) {
			strcpy(Buf, &cp[1]);
			sprintf(Buf2, "%s%s", dyna_signature, Buf);
			ciphertext = Buf2;
		}
	}
	return ciphertext;
}

static int our_valid(char *ciphertext, struct fmt_main *self)
{
	if (!ciphertext ) // || strlen(ciphertext) < CIPHERTEXT_LENGTH)
		return 0;

	get_ptr();
//	if (strncmp(ciphertext, dyna_signature, dyna_sig_len) != 0)
//		return 0;

	return pDynamic->methods.valid(Convert(Conv_Buf, ciphertext, 0), pDynamic);
}


static void * our_salt(char *ciphertext)
{
	get_ptr();
	return pDynamic->methods.salt(Convert(Conv_Buf, ciphertext, 0));
}
static void * our_binary(char *ciphertext)
{
	get_ptr();
	return pDynamic->methods.binary(Convert(Conv_Buf, ciphertext, 0));
}

struct fmt_main fmt_CompiledDynamic =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		0, 0, 16, BINARY_ALIGN, DYNA_SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_DYNAMIC,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		our_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		our_valid,
		our_split
	}
};

static void link_funcs() {
	fmt_CompiledDynamic.methods.salt   = our_salt;
	fmt_CompiledDynamic.methods.binary = our_binary;
	fmt_CompiledDynamic.methods.split = our_split;
	fmt_CompiledDynamic.methods.prepare = fmt_default_prepare;
	fmt_CompiledDynamic.params.tests[0].ciphertext = (char*)dyna_one_line;
}

static void our_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		get_ptr();
		pDynamic->methods.init(pDynamic);
		self->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pDynamic) {
		dynamic_LOCAL_FMT_FROM_PARSER_FUNCTIONS(dyna_script, &dyna_type, &fmt_CompiledDynamic, Convert);
		sprintf (dyna_hash_type, "$dynamic_%d$", dyna_type);
		dyna_hash_type_len = strlen(dyna_hash_type);

		pDynamic = dynamic_THIN_FORMAT_LINK(&fmt_CompiledDynamic, Convert(Conv_Buf, (char*)dyna_one_line, 0), "@dynamic=", 0);
		link_funcs();
	}
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */

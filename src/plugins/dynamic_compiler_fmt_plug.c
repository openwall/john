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

#include "arch.h"

#if defined(SIMD_COEF_32) && !ARCH_LITTLE_ENDIAN
	#undef SIMD_COEF_32
	#undef SIMD_COEF_64
	#undef SIMD_PARA_MD5
	#undef SIMD_PARA_MD4
	#undef SIMD_PARA_SHA1
	#undef SIMD_PARA_SHA256
	#undef SIMD_PARA_SHA512
	#define BITS ARCH_BITS_STR
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
#include "dynamic_types.h"
#include "options.h"

#define FORMAT_LABEL		"dynamic="
#define FORMAT_NAME			""

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	7

#define BINARY_ALIGN		MEM_ALIGN_WORD

#define DYNA_SALT_SIZE		(sizeof(char*))
#define SALT_ALIGN			MEM_ALIGN_WORD

extern const char *dyna_script;
extern const char *dyna_signature;
extern int dyna_sig_len;

static struct fmt_tests tests[DC_NUM_VECTORS + 1] = {
	{"@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72", "abc"},
	{"@dynamic=md5($p)@527bd5b5d689e2c32ae974c6229ff785", "john"},
	{"@dynamic=md5($p)@9dc1dc3f8499ab3bbc744557acf0a7fb", "passweird"},
#if SIMD_COEF_32 < 4
	{"@dynamic=md5($p)@fc58a609d0358176385b00970bfb2b49", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABCDEF"},
#else
	{"@dynamic=md5($p)@142a42ffcb282cf8087dd4dfebacdec2", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzABC"},
#endif
	{"@dynamic=md5($p)@d41d8cd98f00b204e9800998ecf8427e", ""},
	{NULL},
};

static char Conv_Buf[512];
static int dyna_type;
static char dyna_hash_type[24];
static int dyna_hash_type_len;
static struct fmt_main *pDynamic;
static void our_init(struct fmt_main *self);
static void get_ptr();
static char* (*dyna_split)(char *ciphertext, int index, struct fmt_main *self);

/* this function converts a 'native' @dynamic= signature string into a $dynamic_6xxx$ syntax string */
static char *Convert(char *Buf, char *ciphertext, int in_load)
{
	char *cp;

	if (text_in_dynamic_format_already(pDynamic, ciphertext))
		return ciphertext;

	cp = ciphertext;
	if (!strncmp(ciphertext, "@dynamic=", 9)) {
		if (!strncmp(ciphertext, dyna_signature, dyna_sig_len))
			cp = &ciphertext[dyna_sig_len];
		else {
			cp = strchr(&ciphertext[1], '@');
			if (!cp)
				return "*";
			++cp;
		}
	}
	if (in_load)
		snprintf(Buf, sizeof(Conv_Buf), "$dynamic_6xxx$%s", cp);
	else
		snprintf(Buf, sizeof(Conv_Buf), "%s%s", dyna_hash_type, cp);

	return Buf;
}

static char *our_split(char *ciphertext, int index, struct fmt_main *self)
{
	ciphertext = dynamic_compile_split(ciphertext);
	return dyna_split(ciphertext, index, self);
}
extern char *load_regen_lost_salt_Prepare(char *split_fields1);
static char *our_prepare(char **fields, struct fmt_main *self)
{
	if (options.format && !strncmp(options.format, "dynamic=", 8)) {
		extern const char *options_format;
		char *ct;
		options_format = options.format;
		if (options.regen_lost_salts && !strchr(fields[1], '$')) {
			char *cp = load_regen_lost_salt_Prepare(fields[1]);
			if (cp)
				return cp;
		}
		ct = dynamic_compile_prepare(fields[0], fields[1]);
		return ct;
	}
	return fields[1];
}

static int our_valid(char *ciphertext, struct fmt_main *self)
{
	if (!ciphertext ) // || strlen(ciphertext) < CIPHERTEXT_LENGTH)
		return 0;

	get_ptr();
//	if (strncmp(ciphertext, dyna_signature, dyna_sig_len) != 0)
//		return 0;

	if (strnlen(ciphertext, sizeof(Conv_Buf)) >= sizeof(Conv_Buf))
		return 0;

	return pDynamic->methods.valid(Convert(Conv_Buf, ciphertext, 0), pDynamic);
}


static void *our_salt(char *ciphertext)
{
	get_ptr();
	return pDynamic->methods.salt(Convert(Conv_Buf, ciphertext, 0));
}
static void our_done(void)
{
	dynamic_compile_done();
	pDynamic->methods.done();
}
static void *our_binary(char *ciphertext)
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
			/* for now, turn off FMT_SPLIT_UNIFIES_CASE until we get the code right */
		0, 0, 16, BINARY_ALIGN, DYNA_SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_DYNAMIC /*| FMT_SPLIT_UNIFIES_CASE */ ,
		{ NULL },
		{ NULL },
		tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		our_init,
		our_done,
		fmt_default_reset,
		our_prepare,
		our_valid,
		our_split
	}
};

static void link_funcs() {
	static char max_vector[PLAINTEXT_BUFFER_SIZE];
	char *cp;
	private_subformat_data *pPriv = fmt_CompiledDynamic.private.data;
	int i;

	cp = strrchr(fmt_CompiledDynamic.params.algorithm_name, ')');
	if (cp) {
		fmt_CompiledDynamic.params.label = fmt_CompiledDynamic.params.algorithm_name;
		++cp;
		if (*cp == '^')
		{
			while (*cp != ' ')
				++cp;
		}
		*cp++ = 0;
		if (*cp  == ' ') ++cp;
		fmt_CompiledDynamic.params.algorithm_name = cp;
	}
	fmt_CompiledDynamic.methods.salt   = our_salt;
	fmt_CompiledDynamic.methods.binary = our_binary;
	dyna_split = fmt_CompiledDynamic.methods.split;
	fmt_CompiledDynamic.methods.split = our_split;
	fmt_CompiledDynamic.methods.prepare = our_prepare;
	fmt_CompiledDynamic.methods.done = our_done;

	for (i = 0; i < DC_NUM_VECTORS; i++)
		fmt_CompiledDynamic.params.tests[i].ciphertext = (char*)dyna_line[i];

	/* for now, turn off FMT_SPLIT_UNIFIES_CASE until we get the code right */
	fmt_CompiledDynamic.params.flags &= ~FMT_SPLIT_UNIFIES_CASE;

	if ((pPriv->pSetup->flags&MGF_SALTED) != MGF_SALTED)
		fmt_CompiledDynamic.params.benchmark_length |= 0x100;
	else
		fmt_CompiledDynamic.params.benchmark_length = BENCHMARK_LENGTH;

	if (pPriv->pSetup->flags&MGF_PASSWORD_UPCASE) {
		tests[0].plaintext = "ABC";
		tests[1].plaintext = "JOHN";
		tests[2].plaintext= "PASSWEIRD";
		for (i = 0; i < pPriv->pSetup->MaxInputLen; i++)
			max_vector[i] = 'A' + (i % 26);
		max_vector[i] = 0;
	} else if (pPriv->pSetup->flags&MGF_PASSWORD_LOCASE) {
		tests[0].plaintext = "abc";
		tests[1].plaintext = "john";
		tests[2].plaintext= "passweird";
		for (i = 0; i < fmt_CompiledDynamic.params.plaintext_length; i++)
			max_vector[i] = 'a' + (i % 26);
		max_vector[i] = 0;
	} else {
		tests[0].plaintext = "abc";
		tests[1].plaintext = "john";
		tests[2].plaintext= "passweird";
		for (i = 0; i < fmt_CompiledDynamic.params.plaintext_length; i++)
			max_vector[i] = 'A' + (i % 26) + ((i % 52) > 25 ? 0x20 : 0);
		max_vector[i] = 0;
	}
	tests[3].plaintext = max_vector;
	tests[4].plaintext = "";
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
		sprintf(dyna_hash_type, "$dynamic_%d$", dyna_type);
		dyna_hash_type_len = strlen(dyna_hash_type);
		pDynamic = dynamic_THIN_FORMAT_LINK(&fmt_CompiledDynamic, Convert(Conv_Buf, (char*)dyna_line[0], 0), "@dynamic=", 0);
		link_funcs();
	}
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */

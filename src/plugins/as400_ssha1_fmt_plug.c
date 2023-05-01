/*
 * as400_ssha1_fmt_plug.c
 *
 * AS/400 SaltedSHA1 plugin for JtR
 * This software is Copyright (c) 2016 Bart Kulach (@bartholozz) and Rob Schoemaker (@5up3rUs3r)
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This plugin is loosely based on the lotus85 plugin by Sébastien Kaczmarek <skaczmarek@quarkslab.com>
 *
 * AS/400 SHA1 hash is calculated as follows:
 * - userid is padded with spaces to be 10 characters long,
 *   converted to uppercase and UTF-16BE
 * - password is converted to UTF-16BE
 * - Hash is calculated from SHA1(userid+password)
 *
 * See http://www.hackthelegacy.org for details and tooling to retrieve hashes from AS/400 systems
 *
 *
 * Salted sha1, as seen in IBM AS-400.  This is $dynamic_1590$ format, with a 20
 * byte salt (10 utf16be space padded chars of userid).
 * The format is:  sha1(utf16be((space_pad_10(uc($s)).$p))
 *
 * Converted to thin dynamic format by JimF, 2016.  Released to public domain.
 * All usage, in source or binary allowed.
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_AS400_ssha1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_AS400_ssha1);
#else

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"
#include "options.h"
#include "unicode.h"
#include "base64_convert.h"

#define FORMAT_LABEL            "as400-ssha1"
#define FORMAT_NAME             "AS400-SaltedSHA1"

#define ALGORITHM_NAME          "?"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7

#define BINARY_SIZE             20
#define BINARY_FOR_DYNA         16
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_SIZE               20
#define DYNA_SALT_SIZE          (sizeof(char*))
#define SALT_ALIGN              MEM_ALIGN_WORD
#define FORMAT_TAG              "$as400ssha1$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

// set PLAINTEXT_LENGTH to 0, so dyna will set this
#define PLAINTEXT_LENGTH	0

static struct fmt_tests as400_ssha1_tests[] = {
	{"$as400ssha1$4C106E52CA196986E1C52C7FCD02AF046B76C73C$ROB", "banaan"},
	{"$as400ssha1$CED8050C275A5005D101051FF5BCCADF693E8AB7$BART", "Kulach007"},
	{"$as400ssha1$1BA6C7D54E9696ED33F4DF201E348CA8CA815F75$SYSOPR", "T0Psecret!"},
	{"$as400ssha1$A1284B4F1BDD7ED598D4B5060D861D6D614620D3$SYSTEM", "P@ssword01"},
	{"$as400ssha1$94C55BC7EDF1996AC62E8145CDBFA285CA79ED2E$QSYSDBA", "qsysdba"},
	{"$dynamic_1590$CDF4063E283B51EDB7B9A8E6E542042000BD9AE9$HEX$0051005300450043004F00460052002000200020", "qsecofr!"},
	{"$dynamic_1590$44D43148CFE5CC3372AFD2610BEE3D226B2B50C5$HEX$0054004500530054003100200020002000200020", "password1"},
	{"$dynamic_1590$349B12D6588843A1632649A501ABC353EBF409E4$HEX$0054004500530054003200200020002000200020", "secret"},
	{"$dynamic_1590$A97F2F9ED9977A8A628F8727E2851415B06DC540$HEX$0054004500530054003300200020002000200020", "test3"},
	{NULL}
};

extern struct options_main options;

static char Conv_Buf[160];
static struct fmt_main *pDynamic;
static void our_init(struct fmt_main *self);
static void get_ptr();

/* this function converts a 'native' AS400 signature string into a $dynamic_1590$ syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	size_t len, i;
	char *cp, salt[11];
	unsigned char *ucp;
	UTF16 sBuf[10+1], sBUF[10+1];

	if (text_in_dynamic_format_already(pDynamic, ciphertext))
		return ciphertext;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return ciphertext;

	len = snprintf(Buf, sizeof(Conv_Buf) - SALT_SIZE, "$dynamic_1590$%40.40s$HEX$", &ciphertext[FORMAT_TAG_LEN]);
	cp = strchr(&ciphertext[FORMAT_TAG_LEN+1], '$') + 1;
	// space pad salt to 10 bytes
	strcpy(salt, cp);
	while (strlen(salt) < 10)
		strcat(salt, " ");
	// convert to up case utf16be. NOTE, we do the upcase in le, then hand convert to be.
	enc_to_utf16(sBuf, 11, (UTF8*)salt, 10);
	utf16_uc(sBUF, 11, sBuf, 10);
	// now turn into BE by hand.
	ucp = (unsigned char*)sBUF;
	for (i = 0; i < 10; ++i) {
		unsigned char c = ucp[i<<1];
		ucp[i<<1] = ucp[(i<<1)+1];
		ucp[(i<<1)+1] = c;
	}
	base64_convert(sBUF, e_b64_raw, 20, &Buf[len], e_b64_hex, 41, 0, 0);
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

static int our_valid(char *ciphertext, struct fmt_main *self)
{
	if (!ciphertext ) // || strlen(ciphertext) < CIPHERTEXT_LENGTH)
		return 0;

	get_ptr();

	if (!strncmp(ciphertext, "$dynamic_1590$", 14))
		return pDynamic->methods.valid(ciphertext, pDynamic);

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	if (hexlenu(&ciphertext[FORMAT_TAG_LEN], 0) != BINARY_SIZE * 2)
		return 0;
	if (ciphertext[FORMAT_TAG_LEN + 2 * BINARY_SIZE] != '$')
		return 0;
	if (strlen(&ciphertext[FORMAT_TAG_LEN + 2 * BINARY_SIZE + 1]) > 10)
		return 0;
	if (options.input_enc == UTF_8 && !valid_utf8((UTF8*)ciphertext)) {
		static int error_shown = 0;
#ifdef HAVE_FUZZ
		if (options.flags & (FLG_FUZZ_CHK | FLG_FUZZ_DUMP_CHK))
			return 0;
#endif
		if (!error_shown)
			fprintf(stderr, "%s: Input file is not UTF-8. Please use --input-enc to specify a codepage.\n", self->params.label);
		error_shown = 1;
		return 0;
	}
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

struct fmt_main fmt_AS400_ssha1 =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		0, PLAINTEXT_LENGTH, BINARY_FOR_DYNA, BINARY_ALIGN, DYNA_SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_ENC | FMT_UNICODE | FMT_DYNAMIC,
		{ NULL },
		{ NULL },
		as400_ssha1_tests
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
	fmt_AS400_ssha1.methods.salt   = our_salt;
	fmt_AS400_ssha1.methods.binary = our_binary;
	fmt_AS400_ssha1.methods.split = our_split;
	fmt_AS400_ssha1.methods.prepare = our_prepare;
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
		pDynamic = dynamic_THIN_FORMAT_LINK(&fmt_AS400_ssha1, Convert(Conv_Buf, as400_ssha1_tests[0].ciphertext), "as400-ssha1", 0);
		link_funcs();
	}
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */

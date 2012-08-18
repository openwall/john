/*
 * This is thin md5(unicode($p)) made from rawMD5go_fmt_plug.c by magnum 2011,
 * now linking to $dynamic_29$. Below is original comments from rawMD5go:
 *
 * This software is Copyright (c) 2004 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Minor changes by David Luyer <david at luyer.net> to
 * use a modified (faster) version of Solar Designer's
 * md5 implementation.
 *
 * More improvement by
 * Balázs Bucsay - earthquake at rycon.hu - http://www.rycon.hu/
 * (2times faster, but it's only works up to 54characters)
 *
 * Finally, support for SSE intrinsics
 *
 * This format is now 'thin', and links to $dynamic_0$ format.
 * JimF, March, 2011
 *
 */

#include <string.h>
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "dynamic.h"
#include "options.h"
#include "unicode.h"

#define FORMAT_LABEL			"raw-md5u"
#define FORMAT_NAME				"md5(unicode($p))"

#define ALGORITHM_NAME			"?" /* filled in by md5-gen */
#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		54 // octets, not characters. Trimmed in init(),  now 'trimmed' in the $dynamic_29$ and we harvest the actual length from that format.
#define CIPHERTEXT_LENGTH		32
#define BINARY_SIZE				16
#define SALT_SIZE				0

/* Note, some tests may be replaced in init() depending on --enc */
static struct fmt_tests rawmd5u_tests[] = {
	{"16c47151c18ac087cd12b3a70746c790", "test1"},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"9c3abef89ff76f8acd80eae37b35f64f", "test2"},
	{"849ee1b88b5d887bdb058180a666b450", "test3"},
	{"8c4cb7e8b33b56a833cdaa8673f3b425", "test4"},
	{"537e738b1ac5551f65106368dc301ece", "thatsworking"},
	{NULL}
};

static char Conv_Buf[80];
static struct fmt_main *pDynamic_29;
static void rawmd5u_init(struct fmt_main *self);

/* this function converts a 'native' raw md5 signature string into a $dynamic_29$ syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	if (text_in_dynamic_format_already(pDynamic_29, ciphertext))
		return ciphertext;
	if (!ciphertext || strlen(ciphertext) < CIPHERTEXT_LENGTH)
		return "*";

	sprintf(Buf, "$dynamic_29$%s", ciphertext);
	return Buf;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;

	if (!ciphertext || strlen(ciphertext) < CIPHERTEXT_LENGTH)
		return 0;

	if (!pDynamic_29)
		rawmd5u_init(self);
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) {
		return pDynamic_29->methods.valid(ciphertext, pDynamic_29);
	}

	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  ))
			return 0;
	}
	return pDynamic_29->methods.valid(Convert(Conv_Buf, ciphertext), pDynamic_29);
}

static void * our_salt(char *ciphertext)
{
	return pDynamic_29->methods.salt(Convert(Conv_Buf, ciphertext));
}
static void * our_binary(char *ciphertext)
{
	return pDynamic_29->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_rawmd5u =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH, BINARY_SIZE, SALT_SIZE, 1, 1, FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8, rawmd5u_tests
	}, {
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		rawmd5u_init,
		fmt_default_prepare,
		valid
	}
};

static void rawmd5u_init(struct fmt_main *self)
{
	if (options.utf8) {
		rawmd5u_tests[1].ciphertext = "94a4e171de16580742c4d141e6607bf7";
		rawmd5u_tests[1].plaintext = "\xE2\x82\xAC";	// Euro sign
		rawmd5u_tests[2].ciphertext = "03c60810f0e54d16e826aca385d776c8";
		rawmd5u_tests[2].plaintext = "\xE2\x82\xAC\xE2\x82\xAC";	// 2 x euro
		rawmd5u_tests[3].ciphertext = "2d554433d7cde7ec8d16aaf126c3be6b";
		rawmd5u_tests[3].plaintext = "\xE2\x82\xAC\xC3\xBC";	// euro and u-umlaut
		rawmd5u_tests[4].ciphertext = "8007d9070b27db7b30433df2cd10abc1";
		rawmd5u_tests[4].plaintext = "\xC3\xBC\xE2\x82\xAC";	// u-umlaut and euro
	} else {
		if (CP_to_Unicode[0xfc] == 0x00fc) {
			rawmd5u_tests[1].ciphertext = "ea7ab2b5c07650badab30790d0c9b63e";
			rawmd5u_tests[1].plaintext = "\xFC";	// German u-umlaut in iso-8859-1
			rawmd5u_tests[2].ciphertext = "f0a0b9f1dea0e458cec9a284ff434d44";
			rawmd5u_tests[2].plaintext = "\xFC\xFC";
			rawmd5u_tests[3].ciphertext = "d25a0b436b768777cc9a343d283dbf5a";
			rawmd5u_tests[3].plaintext = "\xFC\xFC\xFC";
			rawmd5u_tests[4].ciphertext = "719917322bf12168f8c55939e4fec8de";
			rawmd5u_tests[4].plaintext = "\xFC\xFC\xFC\xFC";
		}
	}
	if (self->private.initialized == 0) {
		pDynamic_29 = dynamic_THIN_FORMAT_LINK(&fmt_rawmd5u, Convert(Conv_Buf, rawmd5u_tests[0].ciphertext), "thin");
		fmt_rawmd5u.methods.binary = our_binary;
		fmt_rawmd5u.methods.salt = our_salt;
		fmt_rawmd5u.params.algorithm_name = pDynamic_29->params.algorithm_name;
		fmt_rawmd5u.params.plaintext_length = pDynamic_29->params.plaintext_length;
		self->private.initialized = 1;
	}
}

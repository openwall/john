/*
 * This software is Copyright © 2004 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Converted to thin format, into $dynamic_19$ format.
 */

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"

#define FORMAT_LABEL		"pix-md5"
#define FORMAT_NAME			"PIX MD5"
#define ALGORITHM_NAME		"?" /* filled in by md5-gen */
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		16
#define BINARY_SIZE				16

#define SALT_SIZE			0

static struct fmt_tests pixmd5_tests[] = {
	{"2KFQnbNIdI.2KYOU", "cisco"},
	{"TRPEas6f/aa6JSPL", "test1"},
	{"OMT6mXmAvGyzrCtp", "test2"},
	{"gTC7RIy1XJzagmLm", "test3"},
	{"oWC1WRwqlBlbpf/O", "test4"},
	{"NuLKvvWGg.x9HEKO", "password"},
	{"8Ry2YjIyt7RRXU24", ""},
	{".7nfVBEIEu4KbF/1","0123456789abcdef"},        // added a exact 16 byte password, to make sure it works properly
	{NULL}
};

static char Conv_Buf[80];
static struct fmt_main *pFmt_Dynamic_19;
static void pixmd5_init(struct fmt_main *pFmt);
static void get_ptr();

/* this function converts a 'native' pixmd5 signature string into a Dynamic_19 syntax string */
static char *Convert(char *Buf, char *ciphertext) {
	// 2KFQnbNIdI.2KYOU -> $dynamic_19$2KFQnbNIdI.2KYOU
	if (text_in_dynamic_format_already(pFmt_Dynamic_19, ciphertext))
		return ciphertext;

	if (strlen(ciphertext) == CIPHERTEXT_LENGTH) {
		sprintf(Buf, "$dynamic_19$%s", ciphertext);
		return Buf;
	}
	return ciphertext;
}

static char *our_split(char *ciphertext, int index) {
	return Convert(Conv_Buf, ciphertext);
}
static void * our_salt(char *ciphertext) {
	get_ptr();
	return pFmt_Dynamic_19->methods.salt(Convert(Conv_Buf, ciphertext));
}

static int valid(char *ciphertext, struct fmt_main *pFmt) {
	int i;

	if (!ciphertext)
		return 0;
	get_ptr();
	i = strlen(ciphertext);
	if (i > CIPHERTEXT_LENGTH)
		return pFmt_Dynamic_19->methods.valid(ciphertext, pFmt_Dynamic_19);
	if (i == CIPHERTEXT_LENGTH)
		return pFmt_Dynamic_19->methods.valid(Convert(Conv_Buf, ciphertext), pFmt_Dynamic_19);
	return 0;
}

static void * our_binary(char *ciphertext) {
	return pFmt_Dynamic_19->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_pixMD5 = {
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		16, BINARY_SIZE, SALT_SIZE, 1, 1, FMT_CASE | FMT_8_BIT, pixmd5_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		pixmd5_init,
		fmt_default_prepare,
		valid
	}
};

static void pixmd5_init(struct fmt_main *pFmt)
{
	if (pFmt->private.initialized == 0) {
		pFmt_Dynamic_19 = dynamic_THIN_FORMAT_LINK(&fmt_pixMD5, Convert(Conv_Buf, pixmd5_tests[0].ciphertext), "pix-md5", 1);
		fmt_pixMD5.methods.salt   = our_salt;
		fmt_pixMD5.methods.binary = our_binary;
		fmt_pixMD5.methods.split = our_split;
		fmt_pixMD5.params.algorithm_name = pFmt_Dynamic_19->params.algorithm_name;
		pFmt->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pFmt_Dynamic_19) {
		pFmt_Dynamic_19 = dynamic_THIN_FORMAT_LINK(&fmt_pixMD5, Convert(Conv_Buf, pixmd5_tests[0].ciphertext), "pix-md5", 0);
		fmt_pixMD5.methods.salt   = our_salt;
		fmt_pixMD5.methods.binary = our_binary;
		fmt_pixMD5.methods.split = our_split;
	}
}

/**
 * GNU Emacs settings: K&R with 1 tab indent.
 * Local Variables:
 * c-file-style: "k&r"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */

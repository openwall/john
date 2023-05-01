/*
 * This software is Copyright (c) 2004 bartavelle, <simon at banquise.net>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Converted to thin format, into $dynamic_19$ format.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pixMD5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pixMD5);
#else

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"

#define FORMAT_LABEL		"pix-md5"
#define FORMAT_NAME		"Cisco PIX"
#define ALGORITHM_NAME		"?" /* filled in by md5-gen */
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH		0x107

// set PLAINTEXT_LENGTH to 0, so dyna will set this  (note, 16 was right, but just let dyna set it)
#define PLAINTEXT_LENGTH		0
#define CIPHERTEXT_LENGTH		16
#define BINARY_SIZE				16
#define BINARY_ALIGN			MEM_ALIGN_WORD
#define SALT_ALIGN				MEM_ALIGN_WORD

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
	// repeat first hash in exactly the same format that is used in john.pot
	{"$dynamic_19$2KFQnbNIdI.2KYOU", "cisco"},
	{NULL}
};

static char Conv_Buf[80];
static struct fmt_main *pDynamic_19;
static void pixmd5_init(struct fmt_main *self);
static void get_ptr();

/* this function converts a 'native' pixmd5 signature string into a Dynamic_19 syntax string */
static char *Convert(char *Buf, char *ciphertext) {
	// 2KFQnbNIdI.2KYOU -> $dynamic_19$2KFQnbNIdI.2KYOU
	if (text_in_dynamic_format_already(pDynamic_19, ciphertext))
		return ciphertext;

	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) == CIPHERTEXT_LENGTH) {
		sprintf(Buf, "$dynamic_19$%s", ciphertext);
		return Buf;
	}
	return ciphertext;
}

static char *our_split(char *ciphertext, int index, struct fmt_main *self)
{
	get_ptr();
	return pDynamic_19->methods.split(Convert(Conv_Buf, ciphertext), index, self);
}
static void * our_salt(char *ciphertext) {
	get_ptr();
	return pDynamic_19->methods.salt(Convert(Conv_Buf, ciphertext));
}

static int valid(char *ciphertext, struct fmt_main *self) {
	int i;

	if (!ciphertext)
		return 0;
	get_ptr();

	i = strnlen(ciphertext, CIPHERTEXT_LENGTH + 1);
	if (i > CIPHERTEXT_LENGTH)
		return pDynamic_19->methods.valid(ciphertext, pDynamic_19);
	if (i == CIPHERTEXT_LENGTH)
		return pDynamic_19->methods.valid(Convert(Conv_Buf, ciphertext), pDynamic_19);
	return 0;
}

static void * our_binary(char *ciphertext) {
	get_ptr();
	return pDynamic_19->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_pixMD5 = {
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		0, PLAINTEXT_LENGTH, BINARY_SIZE, BINARY_ALIGN, SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_DYNAMIC,
		{ NULL },
		{ NULL },
		pixmd5_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		pixmd5_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		our_split
	}
};

static void link_funcs() {
	fmt_pixMD5.methods.salt   = our_salt;
	fmt_pixMD5.methods.binary = our_binary;
	fmt_pixMD5.methods.split = our_split;
}

static void pixmd5_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		get_ptr();
		pDynamic_19->methods.init(pDynamic_19);
		self->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pDynamic_19) {
		pDynamic_19 = dynamic_THIN_FORMAT_LINK(&fmt_pixMD5, Convert(Conv_Buf, pixmd5_tests[0].ciphertext), "pix-md5", 0);
		link_funcs();
	}
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */

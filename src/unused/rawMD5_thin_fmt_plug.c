/*
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

#define FORMAT_LABEL			"raw-md5"
#define FORMAT_NAME				"Raw MD5"
#define ALGORITHM_NAME			"?"  /* filled in by md5-gen */

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		55
#define CIPHERTEXT_LENGTH		32
#define BINARY_SIZE				16
#define SALT_SIZE				0

static struct fmt_tests rawmd5_tests[] = {
	{"5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{"ad0234829205b9033196ba818f7a872b", "test2"},
	{"8ad8757baa8564dc136c1e07507f4a98", "test3"},
	{"86985e105f79b95d6bc918fb45ec7727", "test4"},
	{"378e2c4a07968da2eca692320136433d", "thatsworking"},
	{"8db219468effb0a1b8a420602ff5621d", "BathanBathan"},
	{"5c3d7e2282483ac33fa27ec21842a5a5", "waleedabdullah"},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{NULL}
};

static struct fmt_main *pDynamic_0;
static void rawmd5_init(struct fmt_main *self);
static char Conv_Buf[80];

/* this function converts a 'native' mediawiki signature string into a Dynamic_9 syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	if (text_in_dynamic_format_already(pDynamic_0, ciphertext))
		return ciphertext;
	sprintf(Buf, "$dynamic_0$%s", ciphertext);
	return Buf;
}


static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;

	if (!ciphertext || strlen(ciphertext) < CIPHERTEXT_LENGTH)
		return 0;
	if (!pDynamic_0)
		rawmd5_init(self);
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) {
		return pDynamic_0->methods.valid(ciphertext, pDynamic_0);
	}
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  ))
			return 0;
	}
	return pDynamic_0->methods.valid(Convert(Conv_Buf, ciphertext), pDynamic_0);
}

static void * our_salt(char *ciphertext)
{
	return pDynamic_0->methods.salt(Convert(Conv_Buf, ciphertext));
}
static void * our_binary(char *ciphertext)
{
	return pDynamic_0->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_rawMD5go =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH, BINARY_SIZE, SALT_SIZE, 1, 1, FMT_CASE | FMT_8_BIT, rawmd5_tests
	}, {
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		rawmd5_init,
		fmt_default_prepare,
		valid
	}
};

static void rawmd5_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		pDynamic_0 = dynamic_THIN_FORMAT_LINK(&fmt_rawMD5go, Convert(Conv_Buf, rawmd5_tests[0].ciphertext), "raw-md5");
		fmt_rawMD5go.methods.binary = our_binary;
		fmt_rawMD5go.methods.salt = our_salt;
		fmt_rawMD5go.params.algorithm_name = pDynamic_0->params.algorithm_name;
		self->private.initialized = 1;
	}
}

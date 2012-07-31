/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright © 2009 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Cracks phpass 'portable' hashes, and phpBBv3 hashes, which
 * are simply phpass portable, with a slightly different signature.
 * These are 8 byte salted hashes, with a 1 byte 'salt' that
 * defines the number of loops to compute.  Internally we work
 * with 8 byte salt (the 'real' salt), but let john track it as
 * 9 byte salts (the loop count byte is appended to the 'real'
 * 8 byte salt value.
 *
 * code should be pretty fast, and pretty well debugged.  Works
 * even if there are multiple loop count values in the set of
 * hashes. PHPv5 kicked up the default loop number, but it is
 * programatically allowed to have different looping counts.
 * This format should handle all valid loop values.
 *
 * This format is now a 'shell'.  It simply is used to filter out
 * the $H$??????? hashes, and convert them into $dynamic_17$??????
 * and setup and forward the 'work' to the $dynamic_17$ to do the 'real'
 * work.
 *
 */

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"

#define FORMAT_LABEL			"phpass"
#define FORMAT_NAME			"phpass MD5"

#define ALGORITHM_NAME			"?" /* filled in by md5-gen */
#define BENCHMARK_COMMENT		" ($P$9)"
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		38
#define CIPHERTEXT_LENGTH		34

#define BINARY_SIZE				16
#define SALT_SIZE				8

static struct fmt_tests phpassmd5_tests[] = {
	{"$H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00", "test1"},
	{"$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1", "123456"},
	{"$H$9pdx7dbOW3Nnt32sikrjAxYFjX8XoK1", "123456"},
	{"$P$912345678LIjjb6PhecupozNBmDndU0", "thisisalongertestPW"},
	{"$H$9A5she.OeEiU583vYsRXZ5m2XIpI68/", "123456"},
	{"$P$917UOZtDi6ksoFt.y2wUYvgUI6ZXIK/", "test1"},
	{"$P$91234567AQwVI09JXzrV1hEC6MSQ8I0", "thisisalongertest"},
	{"$P$9234560A8hN6sXs5ir0NfozijdqT6f0", "test2"},
	{"$P$9234560A86ySwM77n2VA/Ey35fwkfP0", "test3"},
	{"$P$9234560A8RZBZDBzO5ygETHXeUZX5b1", "test4"},
	{"$P$612345678si5M0DDyPpmRCmcltU/YW/", "JohnRipper"}, // 256
	{"$P$6T4Krr44HLrUqGkL8Lu67lzZVbvHLC1", "test12345"}, // 256
	{"$H$712345678WhEyvy1YWzT4647jzeOmo0", "JohnRipper"}, // 512 (phpBB w/older PHP version)
	{"$P$8DkV/nqeaQNTdp4NvWjCkgN48AK69X.", "test12345"}, // 1024
	{"$P$B12345678L6Lpt4BxNotVIMILOa9u81", "JohnRipper"}, // 8192 (WordPress)
	{"$P$91234567xogA.H64Lkk8Cx8vlWBVzH0", "thisisalongertst"},
	{NULL}
};

/* (256+256+512+1024+8192)/5 = 2048 */

static char Conv_Buf[80];
static struct fmt_main *pDynamic_17;
static void phpassmd5_init(struct fmt_main *self);
static void get_ptr();

/* this function converts a 'native' phpass signature string into a $dynamic_17$ syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	if (text_in_dynamic_format_already(pDynamic_17, ciphertext))
		return ciphertext;

	sprintf(Buf, "$dynamic_17$%s%10.10s", &ciphertext[3+8+1], &ciphertext[2]);
	return Buf;
}

static char *our_split(char *ciphertext, int index)
{
	return Convert(Conv_Buf, ciphertext);
}

static int phpassmd5_valid(char *ciphertext, struct fmt_main *self)
{
		int i;
		unsigned count_log2;

		if (!ciphertext || strlen(ciphertext) < CIPHERTEXT_LENGTH)
				return 0;
		get_ptr();
		if (strlen(ciphertext) != CIPHERTEXT_LENGTH) {
			return pDynamic_17->methods.valid(ciphertext, pDynamic_17);
		}
		// Handle both the phpass signature, and the phpBB v3 signature (same formula)
		// NOTE we are only dealing with the 'portable' encryption method
		if (strncmp(ciphertext, "$P$", 3) != 0 && strncmp(ciphertext, "$H$", 3) != 0)
				return 0;
		for (i = 3; i < 34; ++i)
				if (atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
						return 0;

		count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
		if (count_log2 < 7 || count_log2 > 31)
				return 0;

		return pDynamic_17->methods.valid(Convert(Conv_Buf, ciphertext), pDynamic_17);
}

static void * our_salt(char *ciphertext)
{
	get_ptr();
	return pDynamic_17->methods.salt(Convert(Conv_Buf, ciphertext));
}
static void * our_binary(char *ciphertext)
{
	return pDynamic_17->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_phpassmd5 =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH, BINARY_SIZE, SALT_SIZE+1, 1, 1, FMT_CASE | FMT_8_BIT, phpassmd5_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		phpassmd5_init,
		fmt_default_prepare,
		phpassmd5_valid
	}
};

static void phpassmd5_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		pDynamic_17 = dynamic_THIN_FORMAT_LINK(&fmt_phpassmd5, Convert(Conv_Buf, phpassmd5_tests[0].ciphertext), "phpass", 1);
		fmt_phpassmd5.methods.salt   = our_salt;
		fmt_phpassmd5.methods.binary = our_binary;
		fmt_phpassmd5.methods.split = our_split;
		fmt_phpassmd5.params.algorithm_name = pDynamic_17->params.algorithm_name;
		self->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pDynamic_17) {
		pDynamic_17 = dynamic_THIN_FORMAT_LINK(&fmt_phpassmd5, Convert(Conv_Buf, phpassmd5_tests[0].ciphertext), "phpass", 0);
		fmt_phpassmd5.methods.salt   = our_salt;
		fmt_phpassmd5.methods.binary = our_binary;
		fmt_phpassmd5.methods.split = our_split;
	}
}

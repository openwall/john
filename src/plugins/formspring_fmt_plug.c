/*
 * formspring_fmt_plug.c
 *
 * Salted sha256, as seen in the part1.txt 'dump' believed to be from formspring.
 * This uses $dynamic_61$ format, with a 2 digit salt. The format is:  sha256($s.$p).
 *
 * By JimF, 2012.  The reason for this format, is so that I can add
 * a method to find these when we ONLY have the hash, and not the salt.
 * In that mode (-regen-lost-salts=6) JtR will load the flat hash data
 * (without the salts), and then will create a salt record for ALL valid
 * salts from '00' to '99', and point ALL of the hashes to these salts.
 * Then john will test all hashes, using ALL salts, thus will find all
 * sha256($s.$p) where the $s is a 2 byte salt.  NOTE there are only 100 salts
 *
 * NOTE This file was taken from the osc_fmt_plug.c, which is also a
 * 'thin' dynamic format to do salt-regen.
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_FORMSPRING;
#elif FMT_REGISTERS_H
john_register_one(&fmt_FORMSPRING);
#else

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"
#include "options.h"

#define FORMAT_LABEL		"FormSpring"
#define FORMAT_NAME		"" /* sha256($salt.$pass) */

#define ALGORITHM_NAME		"?" /* filled in by dynamic */
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	7

#define BINARY_SIZE		    32
#define DYNA_BINARY_SIZE	16
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define HEX_SIZE		    (BINARY_SIZE * 2)

#define SALT_SIZE			2
#define DYNA_SALT_SIZE		(sizeof(char*))
#define SALT_ALIGN			MEM_ALIGN_WORD

// set PLAINTEXT_LENGTH to 0, so dyna will set this
#define PLAINTEXT_LENGTH	0
#define CIPHERTEXT_LENGTH	(SALT_SIZE + 1 + HEX_SIZE)

static struct fmt_tests formspring_tests[] = {
	{"2a4fa0bf8c6a01dd625d3141746451ba51e07f99dc9143f1e25a37f65cb02eb4$RA", "test1"},
	// repeat in the same format that is used in john.pot
	{"$dynamic_61$2a4fa0bf8c6a01dd625d3141746451ba51e07f99dc9143f1e25a37f65cb02eb4$RA", "test1"},
	{"b06b5c132bb1adf421ce6ac406bfabba380546deaab92bd20c3d56baaa70b6cf$  ", "test1"},
	{"cdefb423bad94e3abfe5fc4044bb315a2b875220eb8c8b840849df7ef45bdcef$  ", "test3"},
	// these fail, salt too long
	//{"$dynamic_61$a987090ac31f466c4637e22858aa3db0001e7c0ad8e6724e26e76b8e531df46c$76931fac", "abc"},
	//{"$dynamic_61$bb18710c098cc97a204d9a17bdd701d323a48ccaf67adcf67186a91da3619ac9$9dab2b36", "john"},
	//{"$dynamic_61$eecc9358bf47c8739dd988c1926a5346721557ed50665c4ef41224fceb009ad5$c248b87d", "passweird"},
	{NULL}
};

extern struct options_main options;

static char Conv_Buf[120];
static struct fmt_main *pDynamic_61;
static void formspring_init(struct fmt_main *self);
static void get_ptr();

/* this function converts a 'native' phps signature string into a $dynamic_6$ syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	if (text_in_dynamic_format_already(pDynamic_61, ciphertext))
		return ciphertext;

	snprintf(Buf, sizeof(Conv_Buf), "$dynamic_61$%s", ciphertext);
	return Buf;
}

static char *our_split(char *ciphertext, int index, struct fmt_main *self)
{
	get_ptr();
	return pDynamic_61->methods.split(Convert(Conv_Buf, ciphertext), index, self);
}

static char *our_prepare(char *split_fields[10], struct fmt_main *self)
{
	get_ptr();
	return pDynamic_61->methods.prepare(split_fields, self);
}

static int formspring_valid(char *ciphertext, struct fmt_main *self)
{
	if (!ciphertext )
		return 0;

	get_ptr();

	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) == CIPHERTEXT_LENGTH &&
	    strncmp(ciphertext, "$dynamic", 8))
		ciphertext = Convert(Conv_Buf, ciphertext);
	if (!pDynamic_61->methods.valid(ciphertext, pDynamic_61))
		return 0;
	// safe, since this has already passed dynamic valid. We know there is a '$'
	// for the salt, otherwise it would fail valid before this point.
	if (strlen(strrchr(ciphertext, '$')) != SALT_SIZE + 1) {
		// check for $HEX$ (such as re-reading from the .pot file
		ciphertext = strstr(ciphertext, "$HEX$");
		if (ciphertext && strlen(ciphertext) == 5 + SALT_SIZE * 2)
			return 1;
		return 0;
	}
	return 1;
}


static void * our_salt(char *ciphertext)
{
	get_ptr();
	return pDynamic_61->methods.salt(Convert(Conv_Buf, ciphertext));
}
static void * our_binary(char *ciphertext)
{
	get_ptr();
	return pDynamic_61->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_FORMSPRING =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		0, PLAINTEXT_LENGTH, DYNA_BINARY_SIZE, BINARY_ALIGN, DYNA_SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_DYNAMIC,
		{ NULL },
		{ NULL },
		formspring_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		formspring_init,
		fmt_default_done,
		fmt_default_reset,
		our_prepare,
		formspring_valid,
		our_split
	}
};

static void link_funcs() {
	fmt_FORMSPRING.methods.salt   = our_salt;
	fmt_FORMSPRING.methods.binary = our_binary;
	fmt_FORMSPRING.methods.split = our_split;
	fmt_FORMSPRING.methods.prepare = our_prepare;
}

static void formspring_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		get_ptr();
		pDynamic_61->methods.init(pDynamic_61);
		self->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pDynamic_61) {
		pDynamic_61 = dynamic_THIN_FORMAT_LINK(&fmt_FORMSPRING, Convert(Conv_Buf, formspring_tests[0].ciphertext), "formspring", 0);
		link_funcs();
	}
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */

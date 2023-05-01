/*
 * osc_fmt_plug.c
 *
 * Salted md5, as seen in osCommerce.  This is $dynamic_4$ format, with a 2
 * byte salt. The format is:  md5($s.$p).
 *
 * By JimF, 2012.  The reason for this format, is so that I can add
 * a method to find these when we ONLY have the hash, and not the salt.
 * In that mode (-regen-lost-salts=2) JtR will load the flat hash data
 * (without the salts), and then will create a salt record for ALL valid
 * salts from '  ' to '~~', and point ALL of the hashes to these salts.
 * Then john will test all hashes, using ALL salts, thus will find all
 * md5($s.$p) where the $s is a 2 byte salt.  NOTE there are 95^2 salts
 * (9025 salts).
 *
 * NOTE This file was taken from the PHPS_fmt_plug.c (which is also a
 * 'thin' dynamic format). That format already had hooks to do the salt
 * loading. We have 3 byte salts there, but it works the same (just
 * 95x slower due to the extra salt byte).
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_OSC;
#elif FMT_REGISTERS_H
john_register_one(&fmt_OSC);
#else

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"
#include "options.h"

#define FORMAT_LABEL		"osc"
#define FORMAT_NAME		"osCommerce" /* md5($salt.$pass) */

#define ALGORITHM_NAME		"?" /* filled in by md5-gen */
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	7

#define MD5_BINARY_SIZE		16
#define MD5_HEX_SIZE		(MD5_BINARY_SIZE * 2)

#define BINARY_SIZE			MD5_BINARY_SIZE
#define BINARY_ALIGN		MEM_ALIGN_WORD

#define SALT_SIZE			2
#define DYNA_SALT_SIZE		(sizeof(char*))
#define SALT_ALIGN			MEM_ALIGN_WORD

// set PLAINTEXT_LENGTH to 0, so dyna will set this
#define PLAINTEXT_LENGTH	0
#define CIPHERTEXT_LENGTH	(1 + 3 + 1 + SALT_SIZE * 2 + 1 + MD5_HEX_SIZE)

static struct fmt_tests osc_tests[] = {
	{"$OSC$2020$05de5c963ee6234dc7d52f7589a1922b", "welcome"},
	{"$OSC$3132$c02e8eef3eaa1a813c2ff87c1780f9ed", "3456test1"},
	// repeat the hashes in the same form that is used in john.pot
	{"$dynamic_4$05de5c963ee6234dc7d52f7589a1922b$HEX$2020", "welcome"},
	{"$dynamic_4$c02e8eef3eaa1a813c2ff87c1780f9ed$12", "3456test1"},
	{NULL}
};

extern struct options_main options;

static char Conv_Buf[80];
static struct fmt_main *pDynamic_4;
static void osc_init(struct fmt_main *self);
static void get_ptr();

/* this function converts a 'native' phps signature string into a $dynamic_6$ syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	unsigned long val, i;
	char *cp;

	if (text_in_dynamic_format_already(pDynamic_4, ciphertext))
		return ciphertext;

	cp = strchr(&ciphertext[7], '$');
	if (!cp)
		return "*";

	snprintf(Buf, sizeof(Conv_Buf) - SALT_SIZE, "$dynamic_4$%s$", &cp[1]);
	for (i = 0; i < SALT_SIZE; ++i)
	{
		char bTmp[3];
		bTmp[0] = ciphertext[5+i*2];
		bTmp[1] = ciphertext[5+i*2+1];
		bTmp[2] = 0;
		val = strtoul(bTmp, 0, 16);
		sprintf(bTmp, "%c", (unsigned char)val);
		strcat(Buf, bTmp);
	}
	return Buf;
}

static char *our_split(char *ciphertext, int index, struct fmt_main *self)
{
	get_ptr();
	return pDynamic_4->methods.split(Convert(Conv_Buf, ciphertext), index, self);
}

static char *our_prepare(char *split_fields[10], struct fmt_main *self)
{
	get_ptr();
	return pDynamic_4->methods.prepare(split_fields, self);
}

static int osc_valid(char *ciphertext, struct fmt_main *self)
{
	int i;

	if (!ciphertext )
		return 0;

	get_ptr();
	i = strnlen(ciphertext, CIPHERTEXT_LENGTH + 1);

	if (i != CIPHERTEXT_LENGTH) {
		return pDynamic_4->methods.valid(ciphertext, pDynamic_4);
	}

	if (strncmp(ciphertext, "$OSC$", 5) != 0)
		return 0;

	if (ciphertext[9] != '$')
		return 0;

	for (i = 0;i < SALT_SIZE*2; ++i)
		if (atoi16[ARCH_INDEX(ciphertext[i+5])] == 0x7F)
			return 0;

	for (i = 0;i < MD5_HEX_SIZE; ++i)
		if (atoi16[ARCH_INDEX(ciphertext[i+5+1+SALT_SIZE*2])] == 0x7F)
			return 0;

	return pDynamic_4->methods.valid(Convert(Conv_Buf, ciphertext), pDynamic_4);
}


static void * our_salt(char *ciphertext)
{
	get_ptr();
	return pDynamic_4->methods.salt(Convert(Conv_Buf, ciphertext));
}
static void * our_binary(char *ciphertext)
{
	get_ptr();
	return pDynamic_4->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_OSC =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		0, PLAINTEXT_LENGTH, BINARY_SIZE, BINARY_ALIGN, DYNA_SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_DYNAMIC,
		{ NULL },
		{ NULL },
		osc_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		osc_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		osc_valid,
		our_split
	}
};

static void link_funcs() {
	fmt_OSC.methods.salt   = our_salt;
	fmt_OSC.methods.binary = our_binary;
	fmt_OSC.methods.split = our_split;
	fmt_OSC.methods.prepare = our_prepare;
}

static void osc_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		get_ptr();
		pDynamic_4->methods.init(pDynamic_4);
		self->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pDynamic_4) {
		pDynamic_4 = dynamic_THIN_FORMAT_LINK(&fmt_OSC, Convert(Conv_Buf, osc_tests[0].ciphertext), "osc", 0);
		link_funcs();
	}
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */

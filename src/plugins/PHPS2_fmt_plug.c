/*
 * PHPS_fmt.c  (in thin fully self describing format)
 *
 * Salted PHP on the form (php-code): $hash = MD5(MD5($pass).$salt);
 *
 * this file is being setup as a 'how-to' template.
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_PHPS2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_PHPS2);
#else

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"

#define FORMAT_LABEL		"PHPS2"
#define FORMAT_NAME			"" /* md5(md5($pass).$salt) */

#define ALGORITHM_NAME		"?" /* filled in by dynamic */
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	7

#define BINARY_SIZE			16
#define BINARY_ALIGN		MEM_ALIGN_WORD

#define SALT_SIZE			3
#define DYNA_SALT_SIZE		(sizeof(char*))
#define SALT_ALIGN			MEM_ALIGN_WORD

// set PLAINTEXT_LENGTH to 0, so dyna will set this
#define PLAINTEXT_LENGTH	0
#define CIPHERTEXT_LENGTH	(1 + 4 + 1 + SALT_SIZE * 2 + 1 + MD5_HEX_SIZE)

static char *dyna_script =
	"Expression=md5(md5($p).$s)\n"
	"Flag=MGF_SALTED\n"
	"Flag=MGF_KEYS_BASE16_IN1\n"
	"SaltLen=3\n"
	"MaxInputLenX86=110\n"
	"MaxInputLen=55\n"
	"Func=DynamicFunc__set_input_len_32_cleartop\n"
	"Func=DynamicFunc__append_salt\n"
	"Func=DynamicFunc__crypt_md5\n"
	"Test=$PHPS$433925$5d756853cd63acee76e6dcd6d3728447:welcome\n"
	"Test=$PHPS$73616c$aba22b2ceb7c841473c03962b145feb3:password\n"
	"Test=$PHPS$247824$ad14afbbf0e16d4ad8c8985263a3d051:test\n";  // salt is $x$ (I want to test that a $ works)
static struct fmt_tests phps_tests[] = {
	{"$PHPS$433925$5d756853cd63acee76e6dcd6d3728447", "welcome"},
	{"$PHPS$73616c$aba22b2ceb7c841473c03962b145feb3", "password"},
	{"$PHPS$247824$ad14afbbf0e16d4ad8c8985263a3d051","test"},  // salt is $x$ (I want to test that a $ works)
	{NULL}
};

static char Conv_Buf[80];
static int dyna_type;
static char dyna_hash_type[24];
static int dyna_hash_type_len;
static struct fmt_main *pDynamic;
static void phps_init(struct fmt_main *self);
static void get_ptr();

/* this function converts a 'native' phps signature string into a $dynamic_6$ syntax string */
static char *Convert(char *Buf, char *ciphertext, int in_load)
{
	unsigned long val, i;
	char *cp;

	if (text_in_dynamic_format_already(pDynamic, ciphertext))
		return ciphertext;

	cp = strchr(&ciphertext[7], '$');
	if (!cp)
		return "*";

	if (in_load)
		snprintf(Buf, sizeof(Conv_Buf) - SALT_SIZE, "$dynamic_6xxx$%s$", &cp[1]);
	else
		snprintf(Buf, sizeof(Conv_Buf) - SALT_SIZE, "%s%s$", dyna_hash_type, &cp[1]);
	for (i = 0; i < SALT_SIZE; ++i)
	{
		char bTmp[3];
		bTmp[0] = ciphertext[6+i*2];
		bTmp[1] = ciphertext[6+i*2+1];
		bTmp[2] = 0;
		val = strtoul(bTmp, 0, 16);
		sprintf(bTmp, "%c", (unsigned char)val);
		strcat(Buf, bTmp);
	}
	return Buf;
}

static char *our_split(char *ciphertext, int index, struct fmt_main *self)
{
	if (!strncmp(ciphertext, dyna_hash_type, dyna_hash_type_len)) {
		// convert back into $PHPS$ format
		static char Buf[128];
		char *cp;

		strcpy(Buf, "$PHPS$");
		cp = strchr(&ciphertext[11], '$');
		++cp;
		if (!strncmp(cp, "HEX$", 4)) {
			cp += 4;
			strcat(Buf, cp);
		} else {
			int i, len = strlen(cp);
			char *cp2 = &Buf[strlen(Buf)];
			for (i = 0; i < len; ++i)
				cp2 += sprintf(cp2, "%02x", *cp++);
		}
		strcat(Buf, "$");
		sprintf(&Buf[strlen(Buf)], "%32.32s", &ciphertext[11]);
		strlwr(&Buf[6]);
		return Buf;
	}
	if (!strncmp(ciphertext, "$PHPS$", 6)) {
		static char Buf[128];
		strnzcpy(Buf, ciphertext, sizeof(Buf));
		strlwr(&Buf[6]);
		return Buf;
	}
	return ciphertext;
}

static int phps_valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	if (!ciphertext ) // || strlen(ciphertext) < CIPHERTEXT_LENGTH)
		return 0;

	get_ptr();
	if (strncmp(ciphertext, "$PHPS$", 6) != 0)
		return 0;

	if (ciphertext[12] != '$')
		return 0;

	for (i = 0;i < SALT_SIZE*2; ++i)
		if (atoi16[ARCH_INDEX(ciphertext[i+6])] == 0x7F)
			return 0;

	for (i = 0;i < BINARY_SIZE*2; ++i)
		if (atoi16[ARCH_INDEX(ciphertext[i+6+1+SALT_SIZE*2])] == 0x7F)
			return 0;

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

struct fmt_main fmt_PHPS2 =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		0, PLAINTEXT_LENGTH, BINARY_SIZE, BINARY_ALIGN, DYNA_SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_DYNAMIC | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ NULL },
		phps_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		phps_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		phps_valid,
		our_split
	}
};

static void link_funcs() {
	fmt_PHPS2.methods.salt   = our_salt;
	fmt_PHPS2.methods.binary = our_binary;
	fmt_PHPS2.methods.split = our_split;
	fmt_PHPS2.methods.prepare = fmt_default_prepare;
}

static void phps_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		get_ptr();
		pDynamic->methods.init(pDynamic);
		self->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pDynamic) {
		dynamic_LOCAL_FMT_FROM_PARSER_FUNCTIONS(dyna_script, &dyna_type, &fmt_PHPS2, Convert);
		sprintf(dyna_hash_type, "$dynamic_%d$", dyna_type);
		dyna_hash_type_len = strlen(dyna_hash_type);

		pDynamic = dynamic_THIN_FORMAT_LINK(&fmt_PHPS2, Convert(Conv_Buf, phps_tests[0].ciphertext, 0), "phps", 0);
		link_funcs();
	}
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */

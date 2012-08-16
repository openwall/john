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

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"
#include "options.h"

#define FORMAT_LABEL		"formspring"
#define FORMAT_NAME		"FormSpring sha256($salt.$pass)"

#define ALGORITHM_NAME		"?" /* filled in by dynamic */
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

#define BINARY_SIZE		    32
#define HEX_SIZE		    (BINARY_SIZE * 2)

#define SALT_SIZE			2
#define PROCESSED_SALT_SIZE	SALT_SIZE

#define PLAINTEXT_LENGTH	32
#define CIPHERTEXT_LENGTH	(SALT_SIZE + 1 + HEX_SIZE)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests formspring_tests[] = {
	{"2a4fa0bf8c6a01dd625d3141746451ba51e07f99dc9143f1e25a37f65cb02eb4$RA", "test1"},
	//{"b06b5c132bb1adf421ce6ac406bfabba380546deaab92bd20c3d56baaa70b6cf$  ", "test1"},
	//{"cdefb423bad94e3abfe5fc4044bb315a2b875220eb8c8b840849df7ef45bdcef$  ", "test3"},
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

	sprintf(Buf, "$dynamic_61$%s", ciphertext);
	return Buf;
}

static char *our_split(char *ciphertext, int index)
{
	return Convert(Conv_Buf, ciphertext);
}

static char *our_prepare(char *split_fields[10], struct fmt_main *self)
{
	int i = strlen(split_fields[1]);
	get_ptr();
	/* this 'special' code added to do a 'DEEP' test of hashes which have lost their salts */
	/* in this type run, we load the passwords, then run EVERY salt against them, as though*/
	/* all of the hashes were available for ALL salts. We also only want 1 salt            */
	if (options.regen_lost_salts == 6 && i == 64) {
		char *Ex = mem_alloc_tiny(CIPHERTEXT_LENGTH+1, MEM_ALIGN_NONE);
		// add a 'garbage' placeholder salt to this candidate. However, we want ALL of them to
		// be setup as the exact same salt (so that all candidate get dumped into one salt block.
		// We use '  ' as the salt (2 spaces).
		sprintf(Ex, "%s$  ", split_fields[1]);
		return Ex;
	}
	return pDynamic_61->methods.prepare(split_fields, self);
}

static int formspring_valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	if (!ciphertext ) // || strlen(ciphertext) < CIPHERTEXT_LENGTH)
		return 0;

	get_ptr();
	i = strlen(ciphertext);
	/* this 'special' code added to do a 'DEEP' test of hashes which have lost their salts */
	/* in this type run, we load the passwords, then run EVERY salt against them, as though*/
	/* all of the hashes were available for ALL salts. We also only want 1 salt            */
	if (options.regen_lost_salts == 6 && i == 64) {
		static char Ex[CIPHERTEXT_LENGTH+1];
		sprintf(Ex, "%s$  ", ciphertext);
		ciphertext = Ex;
		i = CIPHERTEXT_LENGTH;
	}

	if (i != CIPHERTEXT_LENGTH)
		return pDynamic_61->methods.valid(ciphertext, pDynamic_61);
	return pDynamic_61->methods.valid(Convert(Conv_Buf, ciphertext), pDynamic_61);
}


static void * our_salt(char *ciphertext)
{
	get_ptr();
	return pDynamic_61->methods.salt(Convert(Conv_Buf, ciphertext));
}
static void * our_binary(char *ciphertext)
{
	return pDynamic_61->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_FORMSPRING =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH, BINARY_SIZE, SALT_SIZE+1, 1, 1, FMT_CASE | FMT_8_BIT, formspring_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		formspring_init,
		our_prepare,
		formspring_valid
	}
};

static void formspring_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		pDynamic_61 = dynamic_THIN_FORMAT_LINK(&fmt_FORMSPRING, Convert(Conv_Buf, formspring_tests[0].ciphertext), "formspring", 1);
		fmt_FORMSPRING.methods.salt   = our_salt;
		fmt_FORMSPRING.methods.binary = our_binary;
		fmt_FORMSPRING.methods.split = our_split;
		fmt_FORMSPRING.methods.prepare = our_prepare;
		fmt_FORMSPRING.params.algorithm_name = pDynamic_61->params.algorithm_name;
		self->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pDynamic_61) {
		pDynamic_61 = dynamic_THIN_FORMAT_LINK(&fmt_FORMSPRING, Convert(Conv_Buf, formspring_tests[0].ciphertext), "formspring", 0);
		fmt_FORMSPRING.methods.salt   = our_salt;
		fmt_FORMSPRING.methods.binary = our_binary;
		fmt_FORMSPRING.methods.split = our_split;
		fmt_FORMSPRING.methods.prepare = our_prepare;
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

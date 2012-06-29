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

#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"
#include "options.h"

#define FORMAT_LABEL		"osc"
#define FORMAT_NAME		"osCommerce md5($salt.$pass)"

#define ALGORITHM_NAME		"?" /* filled in by md5-gen */
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

#define MD5_BINARY_SIZE		16
#define MD5_HEX_SIZE		(MD5_BINARY_SIZE * 2)

#define BINARY_SIZE			MD5_BINARY_SIZE

#define SALT_SIZE			2
#define PROCESSED_SALT_SIZE	SALT_SIZE

#define PLAINTEXT_LENGTH	32
#define CIPHERTEXT_LENGTH	(1 + 3 + 1 + SALT_SIZE * 2 + 1 + MD5_HEX_SIZE)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests osc_tests[] = {
	{"$OSC$2020$05de5c963ee6234dc7d52f7589a1922b", "welcome"},
	{NULL}
};

extern struct options_main options;

static char Conv_Buf[80];
static struct fmt_main *pFmt_Dynamic_4;
static void osc_init(struct fmt_main *pFmt);
static void get_ptr();

/* this function converts a 'native' phps signature string into a $dynamic_6$ syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	unsigned long val, i;
	char *cp;

	if (text_in_dynamic_format_already(pFmt_Dynamic_4, ciphertext))
		return ciphertext;

	cp = strchr(&ciphertext[7], '$');
	if (!cp)
		return "*";

	sprintf(Buf, "$dynamic_4$%s$", &cp[1]);
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

static char *our_split(char *ciphertext, int index)
{
	return Convert(Conv_Buf, ciphertext);
}

static char *our_prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	int i = strlen(split_fields[1]);
	get_ptr();
	/* this 'special' code added to do a 'DEEP' test of hashes which have lost their salts */
	/* in this type run, we load the passwords, then run EVERY salt against them, as though*/
	/* all of the hashes were available for ALL salts. We also only want 1 salt            */
	if (options.regen_lost_salts == 2 && i == 32) {
		char *Ex = mem_alloc_tiny(CIPHERTEXT_LENGTH+1, MEM_ALIGN_NONE);
		// add a 'garbage' placeholder salt to this candidate. However, we want ALL of them to
		// be setup as the exact same salt (so that all candidate get dumped into one salt block.
		// We use '   ' as the salt (3 spaces).
		sprintf(Ex, "$OSC$2020$%s", split_fields[1]);
		return Ex;
	}
	return pFmt_Dynamic_4->methods.prepare(split_fields, pFmt);
}

static int osc_valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;
	if (!ciphertext ) // || strlen(ciphertext) < CIPHERTEXT_LENGTH)
		return 0;

	get_ptr();
	i = strlen(ciphertext);
	/* this 'special' code added to do a 'DEEP' test of hashes which have lost their salts */
	/* in this type run, we load the passwords, then run EVERY salt against them, as though*/
	/* all of the hashes were available for ALL salts. We also only want 1 salt            */
	if (options.regen_lost_salts == 2 && i == 32) {
		static char Ex[CIPHERTEXT_LENGTH+1];
		sprintf(Ex, "$OSC$2020$%s", ciphertext);
		ciphertext = Ex;
		i = CIPHERTEXT_LENGTH;
	}

	if (i != CIPHERTEXT_LENGTH) {
		return pFmt_Dynamic_4->methods.valid(ciphertext, pFmt_Dynamic_4);
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

	return pFmt_Dynamic_4->methods.valid(Convert(Conv_Buf, ciphertext), pFmt_Dynamic_4);
}


static void * our_salt(char *ciphertext)
{
	get_ptr();
	return pFmt_Dynamic_4->methods.salt(Convert(Conv_Buf, ciphertext));
}
static void * our_binary(char *ciphertext)
{
	return pFmt_Dynamic_4->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_OSC =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH, BINARY_SIZE, SALT_SIZE+1, 1, 1, FMT_CASE | FMT_8_BIT, osc_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		osc_init,
		fmt_default_prepare,
		osc_valid
	}
};

static void osc_init(struct fmt_main *pFmt)
{
	if (pFmt->private.initialized == 0) {
		pFmt_Dynamic_4 = dynamic_THIN_FORMAT_LINK(&fmt_OSC, Convert(Conv_Buf, osc_tests[0].ciphertext), "osc", 1);
		fmt_OSC.methods.salt   = our_salt;
		fmt_OSC.methods.binary = our_binary;
		fmt_OSC.methods.split = our_split;
		fmt_OSC.methods.prepare = our_prepare;
		fmt_OSC.params.algorithm_name = pFmt_Dynamic_4->params.algorithm_name;
		pFmt->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pFmt_Dynamic_4) {
		pFmt_Dynamic_4 = dynamic_THIN_FORMAT_LINK(&fmt_OSC, Convert(Conv_Buf, osc_tests[0].ciphertext), "osc", 0);
		fmt_OSC.methods.salt   = our_salt;
		fmt_OSC.methods.binary = our_binary;
		fmt_OSC.methods.split = our_split;
		fmt_OSC.methods.prepare = our_prepare;
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

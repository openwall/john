/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2011. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2011 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Media-wiki salted-MD5 hashes cracker
 *
 * info about this format is found here:
 *   http://www.mediawiki.org/wiki/Manual:User_table
 *
 *  there are 2 formats. Format 1 is simple raw md5.  It is easier
 *  to do a 1 time edit of the format string, removing the :A: from
 *  the md5 hash string, and then simply using raw-md5.  This format
 *  will NOT do that for you.
 *
 *  This format is for the :B: type.
 *
 *  Here is a SQL statement for MySQL which will convert the database
 *  records into proper input lines for this format:
 *
 SELECT CONCAT_WS(':',user_name,REPLACE(user_password,':','$'),user_id,'0',user_real_name,user_email)
   FROM `dw_user` where user_password like ':B:%';
 *
 *  This will return data in this format:
userName1:$B$5ae58e0c$e5fe3ec9a8c4e3e9baa30e462adbfbd6:1551:0:RealName:emailaddress@yahoo.com
userName2:$B$107$dd494cb03ac1c5b8f8d2dddafca2f7a6:1552:0::emailaddress@gmail.com
 *
 * This thin format will change the above line into this, for hooking
 * into $dynamic_9$  (NOTE the '-' char is appended to the salt)
 *
 *  $dynamic_9$dd494cb03ac1c5b8f8d2dddafca2f7a6$107-
 *
 */


#include <string.h>

#include "common.h"
#include "formats.h"
#include "dynamic.h"
#include "options.h"

#define FORMAT_LABEL		"mediawiki"
#define FORMAT_NAME		"MediaWiki md5($s.'-'.md5($p))"

#define ALGORITHM_NAME		"?" /* filled in by md5-gen */
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

#define MD5_BINARY_SIZE		16
#define MD5_HEX_SIZE		(MD5_BINARY_SIZE * 2)

#define BINARY_SIZE			MD5_BINARY_SIZE

#define SALT_SIZE			9
#define PROCESSED_SALT_SIZE	SALT_SIZE

#define PLAINTEXT_LENGTH	32

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests mediawiki_tests[] = {
	{"$B$113$de2874e33da25313d808d2a8cbf31485",      "qwerty"},
	{"$B$bca6c557$8d187736f828e4cb032bd6c7a268cd95", "abc123"},
	{"$B$6$70b3e0907f028877ea47c16496d6df6d",        ""},
	{"$B$761$3ae7c8e25addfd82544c0c0b1ca8f5e4",      "password"},
	{"$B$23a0884a$99b4afc91cba24529a9c16ff20e56621", "artist"},
	{NULL}
};

static char Conv_Buf[80];
static struct fmt_main *pDynamic_9;
static void mediawiki_init(struct fmt_main *self);
static void get_ptr();

/* this utility function is used by cracker.c AND loader.c.  Since media-wiki has a variable width salt, of which
   in regen_lost_salts mode, we only handle 0 to 99999 as salts, we built a function that will assign the salt from
   one buffer into another */
void mediawiki_fix_salt(char *Buf, char *source_to_fix, char *salt_rec, int max_salt_len) {
	char *cp = source_to_fix;
	char *cp2 = salt_rec;
	int i = 0;

	strncpy(Buf, cp, 11+32+1);
	Buf += (11+32+1);
	cp += (11+32+1);
	cp2 += 6;
	while (++i < max_salt_len && *cp2 != '-') {
		*Buf++ = *cp2++;
		++cp;
	}
	++cp;
	*Buf++ = *cp2++;
	*Buf = 0;
}

/* this function converts a 'native' mediawiki signature string into a Dynamic_9 syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	int i;
	char *cp;

	if (text_in_dynamic_format_already(pDynamic_9, ciphertext))
		return ciphertext;

	cp = strchr(&ciphertext[3], '$');
	if (!cp)
		return "*";
	i = sprintf(Buf, "$dynamic_9$%s$", &cp[1]);
	ciphertext += 3;
	// now append salt, and the '-' char
	while (*ciphertext != '$')
		Buf[i++] = *ciphertext++;
	Buf[i++] = '-';
	Buf[i] = 0;
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
	if ( (options.regen_lost_salts >= 3 && options.regen_lost_salts <= 5) && i == 32) {
		char *Ex = mem_alloc_tiny((3+options.regen_lost_salts+1+MD5_HEX_SIZE)+1, MEM_ALIGN_NONE);
		// add a 'garbage' placeholder salt that is the proper 'max' size for salt.  NOTE
		// the real saltlen is not known at this time. We are simply making sure there is ENOUGH room.
		sprintf(Ex, "$B$000%s%s$%s", options.regen_lost_salts>3?"0":"", options.regen_lost_salts>4?"0":"", split_fields[1]);
		return Ex;
	}
	return pDynamic_9->methods.prepare(split_fields, self);
}

static int mediawiki_valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	char *cp;

	if (!ciphertext)
		return 0;
	get_ptr();


	i = strlen(ciphertext);
	/* this 'special' code added to do a 'DEEP' test of hashes which have lost their salts */
	/* in this type run, we load the passwords, then run EVERY salt against them, as though*/
	/* all of the hashes were available for ALL salts. We also only want 1 salt            */

	if ( (options.regen_lost_salts >= 3 && options.regen_lost_salts <= 5) && i == 32) {
		static char Ex[(1+1+1+5+1+MD5_HEX_SIZE)+1];
		sprintf(Ex, "$B$000%s%s$%s", options.regen_lost_salts>3?"0":"", options.regen_lost_salts>4?"0":"", ciphertext);
		ciphertext = Ex;
	}

	if (strncmp(ciphertext, "$B$", 3) != 0) {
		return pDynamic_9->methods.valid(ciphertext, pDynamic_9);
	}

	cp = strchr(&ciphertext[3], '$');
	if (!cp)
		return 0;

	++cp;
	for (i = 0;i < MD5_HEX_SIZE; ++i)
		if (atoi16[ARCH_INDEX(cp[i])] == 0x7F)
			return 0;

	return pDynamic_9->methods.valid(Convert(Conv_Buf, ciphertext), pDynamic_9);
}


static void * our_salt(char *ciphertext)
{
	get_ptr();
	return pDynamic_9->methods.salt(Convert(Conv_Buf, ciphertext));
}
static void * our_binary(char *ciphertext)
{
	return pDynamic_9->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_mediawiki =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH, BINARY_SIZE, SALT_SIZE+1, 1, 1, FMT_CASE | FMT_8_BIT, mediawiki_tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		mediawiki_init,
		our_prepare,
		mediawiki_valid
	}
};


static void mediawiki_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		pDynamic_9 = dynamic_THIN_FORMAT_LINK(&fmt_mediawiki, Convert(Conv_Buf, mediawiki_tests[0].ciphertext), "mediawiki", 1);
		self->private.initialized = 1;
		fmt_mediawiki.methods.salt   = our_salt;
		fmt_mediawiki.methods.binary = our_binary;
		fmt_mediawiki.methods.split = our_split;
		fmt_mediawiki.methods.prepare = our_prepare;
		fmt_mediawiki.params.algorithm_name = pDynamic_9->params.algorithm_name;
	}
}

static void get_ptr() {
	if (!pDynamic_9) {
		pDynamic_9 = dynamic_THIN_FORMAT_LINK(&fmt_mediawiki, Convert(Conv_Buf, mediawiki_tests[0].ciphertext), "mediawiki", 0);
		fmt_mediawiki.methods.salt   = our_salt;
		fmt_mediawiki.methods.binary = our_binary;
		fmt_mediawiki.methods.split = our_split;
		fmt_mediawiki.methods.prepare = our_prepare;
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

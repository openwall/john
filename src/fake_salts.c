/*
 * This software was written by JimF jfoug AT cox dot net
 * in 2012-2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2012-2013 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Salt finder. This will allow JtR to process a few salted type
 * hashes, if the original salt has been lost.  The only 2 types
 * done at this time, are PHPS (VB), and osCommerce. PHPS is dynamic_6
 * which is md5(md5($p).$s) with a 3 byte salt.  osCommerce is dynamic_4
 * of md5($s.$p) with a 2 type salt.
 *
 */


#include <stdio.h>
#include "misc.h"	// error()
#include "config.h"
#include "john.h"
#include "memory.h"
#include "options.h"
#include "fake_salts.h"
#include "memdbg.h"

// global data  (Options loading uses this variable).
char *regen_salts_options;

static char *regen_schema, DynaType[2048], FirstSalt[11];
static int  hash_len, DynaTypeLen;
static int  salt_len, total_regen_salts_count;
static int  loc_cnt[10] = {0};  /* how many chars are used for each location */
static int  cur_cnt[10] = {0};  /* this is a complex number, we use to permute all values. */
static char *candi[10] = {0};   /* This is the valid chars, for each salt character position. */

static void bailout(const char *str) {
	if (john_main_process)
		fprintf(stderr, "%s\n", str);
	error();
}

/* this has been made 'generic', and not built for a set of specific formats */
void build_fake_salts_for_regen_lost(struct db_salt *salts) {
	struct db_salt *sp, *fake_salts;
	int i;
	char dyna_salt_header[7], *buf, *cp;
	unsigned long *ptr;

	fake_salts = mem_calloc_tiny(sizeof(struct db_salt) * (total_regen_salts_count+1), MEM_ALIGN_WORD);

	// Find the 'real' salt. We loaded ALL of the file into 1 salt.
	// we then take THAT salt record, and build a list pointing to these fake salts,
	// AND build 'proper' dynamic salts for all of our data.
	sp = salts;
	while (sp->next) {
		sp = sp->next;
	}

	// a dynamic salt is 0x0000[salt_len-byte-salt] for ALL of the salts.
	buf = mem_alloc_tiny(total_regen_salts_count*(6+salt_len)+1, MEM_ALIGN_NONE);
	cp = buf;

	sprintf(dyna_salt_header, "%02d0000", salt_len);
	// we start from salt 1, (all hashes should already be salted to salt0)
	for (i = 1; i < total_regen_salts_count; ++i) {
		int j = 0;
		char *cp2 = cp;

		// Now compute next salt  NOTE, we start from salt1 not salt0, so we first need
		// to increment out 'complex' number, prior to using it.
		cur_cnt[j=0]++;
		while (cur_cnt[j] >= loc_cnt[j]) {
			cur_cnt[j++] = 0;
			if (j==10)
				break; // done, but we should never get here (i should be == total_regen_salts_count before we hit this)
			++cur_cnt[j];
		}

		strcpy(cp2, dyna_salt_header);
		cp2 += 6;
		for (j = 0; j < salt_len; ++j)
			*cp2++ = candi[j][cur_cnt[j]];
		// now link in this salt struct
		sp->next = &fake_salts[i];
		fake_salts[i].next = NULL;
		fake_salts[i].count = sp->count;
		fake_salts[i].hash = sp->hash;
		fake_salts[i].hash_size = sp->hash_size;
		fake_salts[i].index = sp->index;
		fake_salts[i].keys = sp->keys;
		fake_salts[i].list = sp->list;
		fake_salts[i].bitmap = sp->bitmap;	// 'bug' fix when we went to bitmap. Old code was not copying this.
		ptr=mem_alloc_tiny(sizeof(char*), MEM_ALIGN_WORD);
		*ptr = (size_t) (buf + (cp-buf));
		fake_salts[i].salt = ptr;
		cp = cp2;
		sp = sp->next;
	}
}

/* this is called from dynamic prepare() function, whenever we have a 'raw' hash, and when we are in re-gen salts mode */
char *load_regen_lost_salt_Prepare(char *split_fields1) {
	char *cp = split_fields1, *Prep, *pPrep;
	int len;

	if (cp && *cp == '$' && !strncmp(cp, DynaType, DynaTypeLen))
		cp += DynaTypeLen;
	if (!cp)
		return NULL;

	len = strlen(cp);
	if (len != hash_len)
		return NULL;

	Prep = mem_alloc_tiny(DynaTypeLen+hash_len+1+salt_len+1, MEM_ALIGN_NONE);
	pPrep = Prep;
	// add a the 'first' salt that is the proper.  So, once loaded, there will
	// be only ONE salt, but ALL candidates will use this salt.  We then load
	// all possible salt structures, and link all input candidates to ALL of them.
	pPrep += sprintf(Prep, "%s%s$%s", DynaType, cp, FirstSalt);

	return Prep;
}

/* this is called from cracker.c crk_process_guess() function, and here we FIX the crack with the */
/* proper found salt.  When the data was loaded, it was assigned the 'first' salt, but likely we  */
/* cracked this hash with a different salt (the real one).  Here we fix it before writing to .pot */
void crk_guess_fixup_salt(char *source, char *salt) {
	// salt is :  0N0000REAL_SALT_STRING  (real salt string is N bytes long).
	int real_salt_len = salt[1]-'0';
	memcpy(source+DynaTypeLen+hash_len+1, &salt[6], real_salt_len);
	source[DynaTypeLen+hash_len+1+real_salt_len] = 0;
}

/* this is called from loader.c ldr_load_pot_line() function. During loading of the .pot file,  */
/* the prepare has lost the proper salt.  We now need to fix that to the 'correct' salt.        */
void ldr_pot_possible_fixup_salt(char *source, char *ciphertext) {
	if (!strncmp(source, DynaType, DynaTypeLen)) {
		memcpy(&(source[DynaTypeLen+hash_len+1]), &(ciphertext[DynaTypeLen+hash_len+1]), salt_len);
	}
}

/* Load a custom user class string from john.pot from the [Regen_Salts_UserClasses] section.  */
/* NOTE, we have to init the config file, since this will be called within option loading     */
static char *LoadUserClass(char which, int i) {
	// Load user-defined character classes ?0 .. ?9 from john.conf
	char user_class_num[2];
	char *user_class;
	static int loaded=0;
	user_class_num[0] = which;
	user_class_num[1] = 0;

	// The config has not been loaded, so we have to load it now, if we want to 'check'
	// and show any user set md5-generic functions.
	if (!loaded) {
#if JOHN_SYSTEMWIDE
		cfg_init(CFG_PRIVATE_FULL_NAME, 1);
#endif
		cfg_init(CFG_FULL_NAME, 1);
		loaded = 1;
	}

	if ((user_class = cfg_get_param("Regen_Salts_UserClasses", NULL, user_class_num))) {
		extern char *userclass_expand(const char *src); /* found in rules.c */
		return userclass_expand(user_class);
	}
	return NULL;
}

/* at the end of options loading, this function is called.  It will return 0 or 1.  If the user did NOT     */
/* use the --regen-lost-salts option or not. If the user used it, but it was not valid, then we abort with  */
/* an error message.  Once this function is done, and returns a 1, then all data should be setup and ready  */
int regen_lost_salt_parse_options() {
	char *cp;
	int i, regen_salts_dyna_num;

	if (regen_salts_options==NULL) return 0;
	if (!strcmp(regen_salts_options, "1")) regen_salts_options="dynamic_6:32:?y?y?y";
	else if (!strcmp(regen_salts_options, "2")) regen_salts_options="dynamic_4:32:?y?y";
	// NOTE mediawiki 3 here is not doing ?d- or ?d?d-  I am not implementing 'variable' length regen
	// var length would add a LOT of complexity and may reduce speed a little.
	else if (!strcmp(regen_salts_options, "3")) regen_salts_options="dynamic_9:32:?d?d?d-";
	else if (!strcmp(regen_salts_options, "4")) regen_salts_options="dynamic_9:32:?d?d?d?d-";
	else if (!strcmp(regen_salts_options, "5")) regen_salts_options="dynamic_9:32:?d?d?d?d?d-";
	else if (!strcmp(regen_salts_options, "6")) regen_salts_options="dynamic_61:64:?d?d";

	if (!strncmp(regen_salts_options, "@dynamic=", 9)) {
		char *cp = strrchr(regen_salts_options, '@');
		int len;
		if (!cp)
			bailout("Error, invalid @dynamic= signature in the -salt-regen section");
		++cp;
		len = cp-regen_salts_options;
		if (len > sizeof(DynaType) - 1)
			len = sizeof(DynaType) - 1;
		regen_salts_dyna_num=6000;
		if (sscanf(cp, ":%d:", &hash_len) != 1)
			bailout("Error, invalid regen-lost-salts argument. Must start with @dynamic=EXPR:hash_len: value\nSee docs/REGEN-LOST-SALTS document");
		// at this point in the JtR loading, we do not know if $dynamic_`regen_salts_dyna_num`$ is valid.  We have to check later.
		sprintf(DynaType, "%*.*s", len, len, regen_salts_options);
	} else {
		if (strncmp(regen_salts_options, "dynamic_", 8))
			bailout("Error, invalid regen-lost-salts argument. Must start with dynamic_# value\nSee docs/REGEN-LOST-SALTS document");
		if (sscanf(regen_salts_options, "dynamic_%d:%d:", &regen_salts_dyna_num, &hash_len) != 2)
			bailout("Error, invalid regen-lost-salts argument. Must start with dynamic_#:hash_len: value\nSee docs/REGEN-LOST-SALTS document");
		// at this point in the JtR loading, we do not know if $dynamic_`regen_salts_dyna_num`$ is valid.  We have to check later.
		sprintf(DynaType, "$dynamic_%d$", regen_salts_dyna_num);
	}
	DynaTypeLen = strlen(DynaType);

	// do 'some' sanity checking on input length.  Only known valid input lengths for raw hashes are:
	// (we are only handling hex at this time) 2 times: 16, 20, 24, 28, 32, 40, 48, 64 bytes.
	switch(hash_len) {
		case 32: case 40: case 48: case 56: case 64:
		case 80: case 96: case 128:
			break;
		default:
			bailout("Error, invalid regen-lost-salts argument. Hash_length not valid\nSee docs/REGEN-LOST-SALTS document");
	}

	// Ok, now parse the string, making sure it is valid.  NOTE, since the sscanf gave us a 2 above,
	// we know the string has 2 : in it, so we do not need NULL pointer checking here.
	cp = strchr(regen_salts_options, ':');
	cp = strchr(&cp[1], ':');
	++cp;
	regen_schema = cp;

	i = 0;
	while (*cp) {
		// d=dec h=hex H=HEX x=hHeExX b=binary o=oct a=a-zA-Z l=a-z u=A-Z n=a-zA-Z0-9 y=' '-~  (95 chars)
		if (*cp == '?') {
			switch(cp[1]) {
				case 'd':
					loc_cnt[i] = 10;
					candi[i] = "0123456789";
					break;
				case 'h':
					candi[i] = "0123456789abcdef";
					loc_cnt[i] = 16;
					break;
				case 'H':
					candi[i] = "0123456789ABCDEF";
					loc_cnt[i] = 16;
					break;
				case 'x':
					candi[i] = "0123456789abcdefABCDEF";
					loc_cnt[i] = 22;
					break;
				case 'b':
					candi[i] = "01";
					loc_cnt[i] =  2;
					break;
				case 'o':
					candi[i] = "012345678";
					loc_cnt[i] =  8;
					break;
				case 'a':
					candi[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
					loc_cnt[i] = 52;
					break;
				case 'l':
					candi[i] = "abcdefghijklmnopqrstuvwxyz";
					loc_cnt[i] = 26;
					break;
				case 'u':
					candi[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
					loc_cnt[i] = 26;
					break;
				case 'n':
					candi[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
					loc_cnt[i] = 62;
					break;
				case 'y':
					candi[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 `~!@#$%^&*()_-+=[{]};:,<.>/?|\\'\"";
					loc_cnt[i] = 95;
					break;
				case '?':
					loc_cnt[i] = 1;
					candi[i] = mem_alloc_tiny(2,1);
					candi[i][0] = cp[1];
					candi[i][1] = 0;
					break;
				// need to handle user types also.
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
				{
					char *classData = LoadUserClass(cp[1], i);
					if (!classData)
						bailout("Error, invalid regen-lost-salts argument. Invalid class character in salt schema\nSee docs/REGEN-LOST-SALTS document");
					candi[i] = classData;
					loc_cnt[i] = strlen(classData);
					break;
				}
				default:
					bailout("Error, invalid regen-lost-salts argument. Invalid class character in salt schema\nSee docs/REGEN-LOST-SALTS document");
			}
			++cp;
		} else {
			loc_cnt[i] = 1;
			candi[i] = mem_alloc_tiny(2,1);
			candi[i][0] = cp[0];
			candi[i][1] = 0;
		}
		++cp;
		++salt_len;
		FirstSalt[i] = candi[i][0];
		++i;
	}
	FirstSalt[i] = 0;
	if (salt_len > 9) {
		bailout("Error, invalid regen-lost-salts argument. The max length salt can only be 99 bytes long\nSee docs/REGEN-LOST-SALTS document");
	}
	total_regen_salts_count = 1;
	for (i = 0; i < salt_len; ++i) {
		if (total_regen_salts_count * loc_cnt[i] < total_regen_salts_count)
			bailout("too many re-gen salt values requested to be able to allocate them\n");
		total_regen_salts_count *= loc_cnt[i];
	}
	return 1;
}

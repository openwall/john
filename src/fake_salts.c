/*
 * This software is Copyright (c) 2012-2013 JimF <jfoug AT cox dot net>
 * and Copyright (c) 2021 magnum,
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 *
 * Salt brute-force. This will allow JtR to process dynamic type hashes
 * if the original salt has been lost.
 */

#include <stdio.h>
#include "misc.h"	// error()
#include "config.h"
#include "john.h"
#include "memory.h"
#include "options.h"
#include "fake_salts.h"

char *regen_salts_options;
int regen_salts_count;

static char *regen_schema, DynaType[2048], FirstSalt[11];
static int  hash_len, DynaTypeLen;
static int  salt_len;
static int  loc_cnt[10] = { 0 };  /* How many chars are used for each location */
static int  cur_cnt[10] = { 0 };  /* This is a complex number, we use to permute all values. */
static char *candi[10] = { 0 };   /* This is the valid chars, for each salt character position. */

#define REGEN_OPTION "--regen-lost-salts: "
#define REGEN_DOCS "See doc/Regen-Lost-Salts.txt\n"

void build_fake_salts_for_regen_lost(struct db_main *database)
{
	struct db_salt *sp, *fake_salts, *salts = database->salts;
	int i;
	char dyna_salt_header[7], *buf, *cp;
	size_t *ptr;

	fake_salts = mem_calloc_tiny(sizeof(struct db_salt) * regen_salts_count, MEM_ALIGN_WORD);

	/*
	 * Find the original salt. We loaded all of the hashes into the first possible salt (eg. "0" or "aa").
	 * We now duplicate that salt record, pointing them to all other possible salts.
	 */
	sp = salts;

	if (sp->next)
		error_msg(REGEN_OPTION "More salts loaded than expected; Something's not right!\n");

	if (memcmp(*((char**)sp->salt) + 6, FirstSalt, salt_len))
		error_msg(REGEN_OPTION "Database not looking like expected; Something's not right!\n"
		          "Please only use this option with bare hashes. " REGEN_DOCS);

	/* Salt is :  0N0000REAL_SALT_STRING  (real salt string is N bytes long). */
	buf = mem_alloc_tiny(regen_salts_count * (6 + salt_len) + 1, MEM_ALIGN_NONE);
	cp = buf;

	sprintf(dyna_salt_header, "%02d0000", salt_len);
	/* We start from salt 1. Salt 0 was already written by dynamic prepare function. */
	for (i = 1; i < regen_salts_count; ++i) {
		int j = 0;
		char *cp2 = cp;

		cur_cnt[j = 0]++;
		while (cur_cnt[j] >= loc_cnt[j]) {
			cur_cnt[j++] = 0;
			if (j == 10)
				break; /* Safety, but we should never get here */
			++cur_cnt[j];
		}

		strcpy(cp2, dyna_salt_header);
		cp2 += 6;
		for (j = 0; j < salt_len; ++j)
			*cp2++ = candi[j][cur_cnt[j]];
		database->salt_count++;
		sp->next = &fake_salts[i];

		/* Copy the whole salt as-is, then change the few members that differs */
		fake_salts[i] = *sp; /* Note this is a full struct copy, akin to memcpy */
		fake_salts[i].next = NULL;
		ptr = mem_alloc_tiny(sizeof(char*), MEM_ALIGN_WORD);
		*ptr = (size_t) (buf + (cp - buf));
		fake_salts[i].salt = ptr;
		fake_salts[i].sequential_id++;

		cp = cp2;
		sp = sp->next;
	}
}

/* This is called from dynamic prepare() function when we are in regen salts mode */
char *load_regen_lost_salt_Prepare(char *split_fields1)
{
	char *cp = split_fields1, *Prep;
	int len;

	if (options.flags & FLG_SHOW_CHK)
		return split_fields1;
	if (cp && *cp == '$' && !strncmp(cp, DynaType, DynaTypeLen))
		cp += DynaTypeLen;
	if (!cp)
		return NULL;

	len = strlen(cp);
	if (len != hash_len)
		return NULL;

	Prep = mem_alloc_tiny(DynaTypeLen+hash_len+1+salt_len+1, MEM_ALIGN_NONE);

	/*
	 * Add a the first possible salt.  So, once loaded, there will be only one salt,
	 * but all candidates will use this salt.  We then load all remaining possible
	 * salts and link all input candidates to all of them.
	 */
	sprintf(Prep, "%s%s$%s", DynaType, cp, FirstSalt);

	return Prep;
}

/*
 * This is called from crk_process_guess(), and here we fixup the crack with the found working
 * salt.  When the data was loaded, it was assigned the 'first' salt, but likely we cracked
 * this hash with a different salt.  Here we fix it before writing to .pot
 * Salt is :  0N0000REAL_SALT_STRING  (real salt string is N bytes long).
 */
void crk_guess_fixup_salt(char *source, char *salt)
{
	int real_salt_len = salt[1] - '0';

	memcpy(source + DynaTypeLen + hash_len + 1, &salt[6], real_salt_len);
	source[DynaTypeLen + hash_len + 1 + real_salt_len] = 0;
}

/*
 * This is called from ldr_load_pot_line(). During loading of the .pot file, the prepare
 * has lost the proper salt.  We now need to fix that to the 'correct' salt.
 */
void ldr_pot_possible_fixup_salt(char *source, char *ciphertext)
{
	if (!strncmp(source, DynaType, DynaTypeLen)) {
		memcpy(&(source[DynaTypeLen + hash_len + 1]), &(ciphertext[DynaTypeLen + hash_len + 1]), salt_len);
	}
}

/*
 * Load user-defined character classes ?0 .. ?9 from john.conf
 */
static char *LoadUserClass(char which, int i)
{
	char user_class_num[2];
	const char *user_class;
	static int loaded=0;
	user_class_num[0] = which;
	user_class_num[1] = 0;

	/*
	 * The config has not yet been loaded, so we have to load it now
	 */
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

/*
 * At the end of options loading, this function is called.  It will return 0 if the user didn't use
 * the --regen-lost-salts option at all.  If the user used it but it wasn't valid, we abort with a
 * message.  Once this function is done and returns a 1, then all data should be setup and ready.
 */
int regen_lost_salt_parse_options()
{
	char *cp;
	int i, regen_salts_dyna_num;

	if (regen_salts_options == NULL)
		return 0;

	if (!strcmp(regen_salts_options, "1")) regen_salts_options = "dynamic_6:32:?y?y?y";
	else if (!strcmp(regen_salts_options, "2")) regen_salts_options = "dynamic_4:32:?y?y";
	/*
	 * mediawiki 3 here is not doing ?d- or ?d?d-  I am not implementing 'variable' length regen
	 * var length would add a lot of complexity and may reduce speed a little.
	 */
	else if (!strcmp(regen_salts_options, "3")) regen_salts_options = "dynamic_9:32:?d?d?d-";
	else if (!strcmp(regen_salts_options, "4")) regen_salts_options = "dynamic_9:32:?d?d?d?d-";
	else if (!strcmp(regen_salts_options, "5")) regen_salts_options = "dynamic_9:32:?d?d?d?d?d-";
	else if (!strcmp(regen_salts_options, "6")) regen_salts_options = "dynamic_61:64:?d?d";

	if (!strncmp(regen_salts_options, "@dynamic=", 9)) {
		char *cp = strrchr(regen_salts_options, '@');
		int len;
		if (!cp)
			error_msg(REGEN_OPTION "Invalid @dynamic= signature in parameter");
		++cp;
		len = cp-regen_salts_options;
		if (len > sizeof(DynaType) - 1)
			len = sizeof(DynaType) - 1;
		regen_salts_dyna_num = 6000;
		if (sscanf(cp, ":%d:", &hash_len) != 1)
			error_msg(REGEN_OPTION "Invalid argument. Must start with @dynamic=EXPR:hash_len: value.\n" REGEN_DOCS);
		/* At this point we don't know if $dynamic_`regen_salts_dyna_num`$ is valid. We have to check later. */
		sprintf(DynaType, "%*.*s", len, len, regen_salts_options);
	} else {
		if (strncmp(regen_salts_options, "dynamic_", 8))
			error_msg(REGEN_OPTION "Invalid argument. Must start with dynamic_# value.\n" REGEN_DOCS);
		if (sscanf(regen_salts_options, "dynamic_%d:%d:", &regen_salts_dyna_num, &hash_len) != 2)
			error_msg(REGEN_OPTION "Invalid argument. Must start with dynamic_#:hash_len: value.\n" REGEN_DOCS);
		/* At this point we don't know if $dynamic_`regen_salts_dyna_num`$ is valid. We have to check later. */
		sprintf(DynaType, "$dynamic_%d$", regen_salts_dyna_num);
	}
	DynaTypeLen = strlen(DynaType);

	/*
	 * Do some sanity checking on input length.  Only known valid input lengths for raw hashes are:
	 * (we are only handling hex at this time) 2 times: 16, 20, 24, 28, 32, 40, 48, 64 bytes.
	 */
	switch(hash_len) {
		case 32: case 40: case 48: case 56: case 64:
		case 80: case 96: case 128:
			break;
		default:
			error_msg(REGEN_OPTION "Invalid hash length\n" REGEN_DOCS);
	}

	/*
	 * Now parse the string, making sure it is valid. Since the sscanf gave us a 2 above,
	 * we know the string has 2 : in it, so we don't need NULL pointer checking here.
	 */
	cp = strchr(regen_salts_options, ':');
	cp = strchr(&cp[1], ':');
	++cp;
	regen_schema = cp;

	i = 0;
	while (*cp) {
		/* d=dec h=hex H=HEX x=hHeExX b=binary o=oct a=a-zA-Z l=a-z u=A-Z n=a-zA-Z0-9 y=' '-~  (95 chars) */
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
				candi[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
					" `~!@#$%^&*()_-+=[{]};:,<.>/?|\\'\"";
				loc_cnt[i] = 95;
				break;
			case '?':
				loc_cnt[i] = 1;
				candi[i] = mem_alloc_tiny(2, MEM_ALIGN_NONE);
				candi[i][0] = cp[1];
				candi[i][1] = 0;
				break;
				/* User types */
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
					error_msg(REGEN_OPTION "Invalid argument. Invalid class character in salt schema.\n" REGEN_DOCS);
				candi[i] = classData;
				loc_cnt[i] = strlen(classData);
				break;
			}
			default:
				error_msg(REGEN_OPTION "Invalid argument. Invalid class character in salt schema.\n" REGEN_DOCS);
			}
			++cp;
		} else {
			loc_cnt[i] = 1;
			candi[i] = mem_alloc_tiny(2, MEM_ALIGN_NONE);
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
		error_msg(REGEN_OPTION "Invalid argument. The max length salt can only be 99 bytes long.\n" REGEN_DOCS);
	}
	regen_salts_count = 1;
	for (i = 0; i < salt_len; ++i) {
		if (regen_salts_count * loc_cnt[i] < regen_salts_count)
			error_msg(REGEN_OPTION "Unsupported number of salt values\n");
		regen_salts_count *= loc_cnt[i];
	}
	return 1;
}

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2006,2009,2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 * Author if this file is Jan Starke <jan.starke@outofbed.org>
 */

#include "regex.h"

#if HAVE_REXGEN

#include "loader.h"
#include "logger.h"
#include "status.h"
#include "os.h"
#include "signals.h"
#include "recovery.h"
#include "options.h"
#include "config.h"
#include "cracker.h"
#include "john.h"
#include "external.h"
#if !AC_BUILT || HAVE_LOCALE_H
#include <locale.h>
#endif
#include <ctype.h>
#include "memdbg.h"

#define UNICODE
#define _UNICODE

char *rexgen_alphabets[256];
static const size_t WORDSIZE=1024;

static void fix_state(void) {}
static double get_progress(void) { return -1; }
static void save_state(FILE *file) {}
static int restore_state(FILE *file) { return 0; }

static void rexgen_setlocale() {
	const char* defaultLocale = "en_US.UTF8";
	const char* sysLocale = NULL;

	if ((sysLocale = getenv("LC_CTYPE")) != NULL) {
		setlocale(LC_CTYPE, sysLocale);
	}
	if ((sysLocale = getenv("LC_MESSAGES")) != NULL) {
		setlocale(LC_MESSAGES, sysLocale);
	}
	if ((sysLocale = getenv("LC_ALL")) != NULL) {
		setlocale(LC_ALL, sysLocale);
	}
	if (sysLocale == NULL) {
		setlocale(LC_ALL, defaultLocale);
	}
}

static char BaseWord[1024];

const char *callback() {
	static char Buf[1024];
	if (!BaseWord[0]) *Buf = 0;
	strcpy(Buf, BaseWord);
	*BaseWord = 0;
	if (*Buf)	return Buf;
	//printf ("Returning %s\n", Buf);
	return NULL;
}

void SetupAlpha(const char *regex_alpha)
{
	int i;
	struct cfg_list *list;

	// first off, set 'normal' strings for each char (i.e. 'a' outputs "a")
	for (i = 0; i < 256; ++i) {
		char *cp = (char*)mem_alloc_tiny(2,1);
		*cp = i;
		cp[1] = 0;
		rexgen_alphabets[i] = cp;
	}
	// we have to escape these (they are regex 'special' chars), so when we SEE them in code, we output them exactly as we see them
	rexgen_alphabets[(unsigned char)('[')] = str_alloc_copy("(\\[)");
	rexgen_alphabets[(unsigned char)(']')] = str_alloc_copy("(\\])");
	rexgen_alphabets[(unsigned char)('(')] = str_alloc_copy("(\\()");
	rexgen_alphabets[(unsigned char)(')')] = str_alloc_copy("(\\))");
	rexgen_alphabets[(unsigned char)('{')] = str_alloc_copy("(\\{)");
	rexgen_alphabets[(unsigned char)('}')] = str_alloc_copy("(\\})");
	rexgen_alphabets[(unsigned char)('|')] = str_alloc_copy("(\\|)");
	rexgen_alphabets[(unsigned char)('.')] = str_alloc_copy("(\\.)");
	rexgen_alphabets[(unsigned char)('?')] = str_alloc_copy("(\\?)");
	rexgen_alphabets[(unsigned char)('\\')] = str_alloc_copy("(\\\\)");
	// Now add the replacements from john.conf file.
	if ((list = cfg_get_list("list.rexgen.alpha", (char*) (&regex_alpha[5])))) {
		struct cfg_line *x = list->head;
		while (x) {
			if (x->data && x->data[1] == '=')
				rexgen_alphabets[(unsigned char)(x->data[0])] = str_alloc_copy(&(x->data[2]));
			x = x->next;
		}
	}
}

int do_regex_crack_as_rules(const char *regex, const char *base_word, int regex_case, const char *regex_alpha) {
	c_simplestring_ptr buffer = c_simplestring_new();
	c_iterator_ptr iter = NULL;
	charset encoding = CHARSET_UTF8;
	char word[WORDSIZE];
	static int bFirst=1;
	static int bALPHA=0;

	if (bFirst) {
		bFirst = 0;
		rexgen_setlocale();
		if (regex_alpha && !strncmp(regex_alpha, "alpha", 5)) {
			bALPHA = 1;
			SetupAlpha(regex_alpha);
		}
	}

	if (bALPHA) {
		// Ok, we do our own elete of the word,
		static char Buf[4096];
		char *cp = Buf;
		const char *cpi = base_word;
		while (*cpi) {
			cp += strnzcpyn (cp, rexgen_alphabets[(unsigned char)(*cpi)], 100);
			++cpi;
			if (cp - Buf > sizeof(Buf)-101)
				break;
		}
		*cp = 0;
		printf ("buf=%s\n", Buf);
		if (*regex == 0)
			regex = Buf;
		else {
			static char final_Buf[16384];
			int len = strlen(Buf)+1;
			cpi = regex;
			cp = final_Buf;
			while (*cpi) {
				if (*cpi == '\\' && cpi[1] == '0') {
					cp += strnzcpyn (cp, Buf, len);
					cpi += 2;
				} else
					*cp++ = *cpi++;

			}
			regex = final_Buf;
		}
	}

	strcpy(BaseWord, base_word);
	if (!regex[0]) {
		if (ext_filter("")) {
			if (crk_process_key(""))
				return 1;
		}
		return 0;
	}
	iter = c_regex_iterator_cb(regex, regex_case, encoding, callback);
	if (!iter) {
		fprintf(stderr, "Error, invalid regex expression.  John exiting now  base_word=%s  Regex= %s\n", base_word, regex);
		exit(1);
	}
	while (c_iterator_next(iter)) {
		c_iterator_value(iter, buffer);
		c_simplestring_to_binary_string(buffer, &word[0], sizeof(word));
		c_simplestring_clear(buffer);
		if (ext_filter((char*)word)) {
			if (crk_process_key((char*)word)) {
				c_simplestring_delete(buffer);
				c_iterator_delete(iter);
				return 1;
			}
		}
	}
	c_simplestring_delete(buffer);
	c_iterator_delete(iter);
	return 0;
}

void do_regex_crack(struct db_main *db, const char *regex) {
	c_simplestring_ptr buffer = c_simplestring_new();
	c_iterator_ptr iter = NULL;
	charset encoding = CHARSET_UTF8;
	int ignore_case = 0;
	char word[WORDSIZE];

	if (john_main_process)
		fprintf(stderr, "Warning: regex mode currently can't be "
		        "resumed if aborted\n");

	rexgen_setlocale();
	status_init(&get_progress, 0);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);
	crk_init(db, fix_state, NULL);
	iter = c_regex_iterator_cb(regex, ignore_case, encoding, callback);
	if (!iter) {
		fprintf(stderr, "Error, invalid regex expression.  John exiting now\n");
		exit(1);
	}
	while (c_iterator_next(iter)) {
		c_iterator_value(iter, buffer);
		c_simplestring_to_binary_string(buffer, &word[0], sizeof(word));
		c_simplestring_clear(buffer);
		if (ext_filter((char*)word)) {
			if (crk_process_key((char*)word))
				break;
		}
	}
	c_simplestring_delete(buffer);
	c_iterator_delete(iter);
	crk_done();
	rec_done(event_abort);
}


char *prepare_regex(char *regex, int *bCase, char **regex_alpha) {
	char *cp, *cp2;
	if (!regex || !bCase || !regex_alpha) {
		if (options.verbosity >= 4)
			log_event("- NO Rexgen used");
		return 0;
	}
	cp = str_alloc_copy(regex);
	cp2 = cp;
	while (*cp2) {
		if (isupper((unsigned char)(*cp2)))
			*cp2 = tolower((unsigned char)(*cp2));
		++cp2;
	}
	*bCase = 0;
	*regex_alpha = NULL;

	if ((cp2 = strstr(cp, "case=")) != NULL) {
		// found case option.  Set case and remove it.
		*bCase = 1;
		memmove(&regex[cp2-cp], &regex[cp2-cp+5], strlen(&regex[cp2-cp+4]));
		memmove(cp2, &cp2[5], strlen(&cp2[4]));
	}

	cp2 = strstr(cp, "alpha:");
	if (!cp2)
		cp2 = strstr(cp, "alpha=");
	if (cp2 != NULL) {
		// found case option.  Set case and remove it.
		int i;
		*regex_alpha =  str_alloc_copy(cp2);
		for (i = 1; (*regex_alpha)[i] && (*regex_alpha)[i] != '='; ++i)
		{
		}
		if ((*regex_alpha)[i] == '=') {
			(*regex_alpha)[i] = 0;
		}
		memmove(&regex[cp2-cp], &regex[cp2-cp+i], strlen(&regex[cp2-cp+i-1]));
		memmove(cp2, &cp2[i], strlen(&cp2[i-1]));
	}

	if (*regex == '=')
		++regex;
	if (!strstr(regex, "\\0") && !(*regex_alpha)) {
		fprintf(stderr,
		        "--regex need to contain \"\\0\" in combination"
		        " with wordist, or an alpha option\n");
		error();
	} else {
		log_event("- Rexgen (after rules): %s", regex);
	}
	return regex;
}

#endif /* HAVE_REXGEN */

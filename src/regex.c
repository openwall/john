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

#ifdef HAVE_REXGEN

#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "cracker.h"
#include "john.h"
#include "external.h"
#include <locale.h>

#define UNICODE
#define _UNICODE

#include <librexgen/api/c/librexgen.h>
#include <librexgen/version.h>

static void fix_state(void) {
}


static void rexgen_setlocale() {
	const char* defaultLocale = "en_US.UTF8";
	const char* sysLocale = NULL;

	if ((sysLocale = getenv("LC_CTYPE")) != NULL) {
		setlocale(LC_CTYPE, sysLocale);
	}
	if ((sysLocale = getenv("LC_MESSAGES")) != NULL) {
		setlocale(LC_CTYPE, sysLocale);
	}
	if ((sysLocale = getenv("LC_ALL")) != NULL) {
		setlocale(LC_CTYPE, sysLocale);
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

int do_regex_crack_as_rules(const char *regex, const char *base_word) {
	c_simplestring_ptr buffer = c_simplestring_new();
	c_iterator_ptr iter = NULL;
	charset encoding = CHARSET_UTF8;
	int ignore_case = 0;
	int randomize = 0;
	const char* word;
	static int bFirst=1;

	if (bFirst) {
		bFirst = 0;
		rexgen_setlocale();
	}
	strcpy(BaseWord, base_word);
	iter = c_regex_iterator_cb(regex, ignore_case, encoding, randomize, callback);
	while (c_iterator_next(iter)) {
		c_iterator_value(iter, buffer);
		word = c_simplestring_getptr(buffer);
		if (ext_filter((char*)word)) {
			if (crk_process_key((char*)word)) {
				c_simplestring_delete(buffer);
				c_iterator_delete(iter);
				return 1;
			}
		}
		c_simplestring_clear(buffer);
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
	int randomize = 0;
	const char* word;

	rexgen_setlocale();
	crk_init(db, fix_state, NULL);
	iter = c_regex_iterator_cb(regex, ignore_case, encoding, randomize, callback);
	while (c_iterator_next(iter)) {
		c_iterator_value(iter, buffer);
		word = c_simplestring_getptr(buffer);
		if (ext_filter((char*)word)) {
			crk_process_key((char*)word);
		}
		c_simplestring_clear(buffer);
	}
	c_simplestring_delete(buffer);
	c_iterator_delete(iter);
	crk_done();
}

#else
#warning Notice: rexgen cracking mode disabled, uncomment HAVE_REXGEN in Makefile if you have the rexgen library installed.
#endif /* HAVE_REXGEN */

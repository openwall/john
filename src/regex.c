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

enum {
  display_syntax_tree,
  generate_values
} rexgen_operation;

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

const char *callback() {
//	static char Buf[512];
//	if (feof(infile)) return NULL;
//	if (fgets(Buf, sizeof(Buf)-1, infile) == 0)  return NULL;
//	unsigned int idx = 0;
//	while (idx < sizeof(Buf)-2 && Buf[idx] != '\r' && Buf[idx] != '\n')
//		++idx;
//	Buf[idx] = 0;
//	return Buf;
	static char Buf[512];
	strcpy(Buf, " ");
	return Buf;
}

void do_regex_crack(struct db_main *db, char *regex) {
	/*
	SimpleString buffer;
	RexgenOptions rexgen_options;
	Iterator* iter = nullptr;
	char* word;

	rexgen_options.encoding = CHARSET_UTF8;
	rexgen_options.ignore_case = false;
	rexgen_options.randomize = false;

	crk_init(db, fix_state, NULL);

	iter = regex_iterator(regex, rexgen_options);
	while (iter->next()) {
		buffer.clear();
		iter->value(buffer);
		buffer.terminate();
		word = (char*) buffer.__get_buffer_address();
		if (ext_filter(word)) {
			crk_process_key(word);
		}
	}

	delete iter;
	crk_done();
	*/
	c_simplestring_ptr buffer = c_simplestring_new();
	c_iterator_ptr iter = NULL;
	charset encoding = CHARSET_UTF8;
	int ignore_case = 0;
	int randomize = 0;
	const char* word;

	rexgen_operation = generate_values;
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

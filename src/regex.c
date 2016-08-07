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

#include "misc.h" // error()
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
#include "mask.h"
#include "external.h"
#if !AC_BUILT || HAVE_LOCALE_H
#include <locale.h>
#endif
#include <ctype.h>
#include "memdbg.h"

#define UNICODE
#define _UNICODE

char *rexgen_alphabets[256];

static void fix_state(void)
{
}

static double get_progress(void)
{
	return -1;
}

static void save_state(FILE *file)
{
}

static int restore_state(FILE *file)
{
	return 0;
}

static void rexgen_setlocale()
{
	const char *defaultLocale = "en_US.UTF8";
	const char *sysLocale = NULL;

	if ((sysLocale = getenv("LC_CTYPE")) != NULL) {
		setlocale(LC_CTYPE, sysLocale);
	}
#if !defined _MSC_VER
	if ((sysLocale = getenv("LC_MESSAGES")) != NULL) {
		setlocale(LC_MESSAGES, sysLocale);
	}
#endif
	if ((sysLocale = getenv("LC_ALL")) != NULL) {
		setlocale(LC_ALL, sysLocale);
	}
	if (sysLocale == NULL) {
		setlocale(LC_ALL, defaultLocale);
	}
}

static char BaseWord[1024];

size_t callback(char* dst, const size_t buffer_size)
{
	int len;

	if (!BaseWord[0]) {
		*dst = 0;
	}
	len =  strnzcpyn(dst, BaseWord, 1024);
	*BaseWord = 0;
	if (*dst) {
		return len;
	}
	return 0;
}

void SetupAlpha(const char *regex_alpha)
{
	int i;
	struct cfg_list *list;

	// first off, set 'normal' strings for each char (i.e. 'a' outputs "a")
	for (i = 0; i < 256; ++i) {
		char *cp = (char *)mem_alloc_tiny(2, 1);

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
	if ((list = cfg_get_list("list.rexgen.alpha", (char *)(&regex_alpha[5])))) {
		struct cfg_line *x = list->head;

		while (x) {
			if (x->data && x->data[1] == '=')
				rexgen_alphabets[(unsigned char)(x->data[0])] =
					str_alloc_copy(&(x->data[2]));
			x = x->next;
		}
	}
}

extern void(*crk_fix_state)(void);
static void(*saved_crk_fix_state)(void);
static void save_fix_state(void(*new_crk_fix_state)(void))
{
	saved_crk_fix_state = crk_fix_state;
	crk_fix_state = new_crk_fix_state;
}
static void restore_fix_state(void)
{
	crk_fix_state = saved_crk_fix_state;
}

int do_regex_hybrid_crack(struct db_main *db, const char *regex,
                          const char *base_word, int regex_case, const char *regex_alpha)
{
	c_simplestring_ptr buffer = c_simplestring_new();
	c_iterator_ptr iter = NULL;
	c_regex_ptr regex_ptr = NULL;
	char word[PLAINTEXT_BUFFER_SIZE];
	static int bFirst = 1;
	static int bALPHA = 0;
	int max_len = db->format->params.plaintext_length;
	int retval;

	/* Save off fix_state to use hybrid fix state */
	save_fix_state(fix_state);

	if (options.req_maxlength)
		max_len = options.req_maxlength;

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
			cp += strnzcpyn(cp, rexgen_alphabets[(unsigned char)(*cpi)], 100);
			++cpi;
			if (cp - Buf > sizeof(Buf) - 101)
				break;
		}
		*cp = 0;
#if DEBUG
		fprintf(stderr, "buf=%s\n", Buf);
#endif
		if (*regex == 0)
			regex = Buf;
		else {
			static char final_Buf[16384];
			int len = strlen(Buf) + 1;

			cpi = regex;
			cp = final_Buf;
			while (*cpi) {
				if (*cpi == '\\' && cpi[1] == '0') {
					cp += strnzcpyn(cp, Buf, len);
					cpi += 2;
				} else
					*cp++ = *cpi++;

			}
			regex = final_Buf;
		}
	}

	strcpy(BaseWord, base_word);
	if (!regex[0]) {
		if (options.mask) {
			if (do_mask_crack(fmt_null_key)) {
				retval = 1;
				goto out;
			}
			fix_state();
		} else
		if (ext_filter(fmt_null_key)) {
			if (crk_process_key(fmt_null_key)) {
				retval = 1;
				goto out;
			}
		}
		retval = 0;
		goto out;
	}

	regex_ptr = c_regex_cb(regex, callback);
	if (!regex_ptr) {
		c_simplestring_delete(buffer);
		fprintf(stderr,
		        "Error, invalid regex expression.  John exiting now  base_word=%s  Regex= %s\n",
		        base_word, regex);
		error();
	}
	iter = c_regex_iterator(regex_ptr);
	while (c_iterator_next(iter)) {
		c_iterator_value(iter, buffer);
		c_simplestring_to_utf8_string(buffer, &word[0], sizeof(word));
		c_simplestring_clear(buffer);
		if (options.mask) {
			if (do_mask_crack(word)) {
				retval = 1;
				goto out;
			}
			fix_state();
		} else
		if (ext_filter((char *)word)) {
			word[max_len] = 0;
			if (crk_process_key((char *)word)) {
				retval = 1;
				goto out;
			}
		}
	}
	retval = 0;
	goto out;

out:
	restore_fix_state();
	c_simplestring_delete(buffer);
	c_regex_delete(regex_ptr);
	c_iterator_delete(iter);
	return retval;
}

void do_regex_crack(struct db_main *db, const char *regex)
{
	c_simplestring_ptr buffer = c_simplestring_new();
	c_iterator_ptr iter = NULL;
	c_regex_ptr regex_ptr = NULL;
	char word[PLAINTEXT_BUFFER_SIZE];
	int max_len = db->format->params.plaintext_length;

	if (options.req_maxlength)
		max_len = options.req_maxlength;

	if (john_main_process)
		fprintf(stderr, "Warning: regex mode currently can't be "
		        "resumed if aborted\n");

	rexgen_setlocale();
	status_init(&get_progress, 0);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);
	crk_init(db, fix_state, NULL);
	regex_ptr = c_regex_cb(regex, callback);
	if (!regex_ptr) {
		fprintf(stderr,
		        "Error, invalid regex expression.  John exiting now\n");
		error();
	}
	iter = c_regex_iterator(regex_ptr);
	while (c_iterator_next(iter)) {
		c_iterator_value(iter, buffer);
		c_simplestring_to_utf8_string(buffer, &word[0], sizeof(word));
		c_simplestring_clear(buffer);
		if (options.mask) {
			if (do_mask_crack(word))
				break;
			fix_state();
		} else
		if (ext_filter((char *)word)) {
			word[max_len] = 0;
			if (crk_process_key((char *)word))
				break;
		}
	}
	c_simplestring_delete(buffer);
	c_iterator_delete(iter);
	crk_done();
	rec_done(event_abort);
}


char *prepare_regex(char *regex, int *bCase, char **regex_alpha)
{
	char *cp, *cp2;

	if (!(options.flags & FLG_REGEX_STACKED))
		return NULL;

	if (!regex || !bCase || !regex_alpha) {
		if (options.verbosity == VERB_MAX)
			log_event("- No Rexgen used");
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
		memmove(&regex[cp2 - cp], &regex[cp2 - cp + 5],
		        strlen(&regex[cp2 - cp + 4]));
		memmove(cp2, &cp2[5], strlen(&cp2[4]));
	}

	cp2 = strstr(cp, "alpha:");
	if (!cp2)
		cp2 = strstr(cp, "alpha=");
	if (cp2 != NULL) {
		// found case option.  Set case and remove it.
		int i;

		*regex_alpha = str_alloc_copy(cp2);
		for (i = 1; (*regex_alpha)[i] && (*regex_alpha)[i] != '='; ++i) {
		}
		if ((*regex_alpha)[i] == '=') {
			(*regex_alpha)[i] = 0;
		}
		memmove(&regex[cp2 - cp], &regex[cp2 - cp + i],
		        strlen(&regex[cp2 - cp + i - 1]));
		memmove(cp2, &cp2[i], strlen(&cp2[i - 1]));
	}

	if (*regex == '=')
		++regex;
	if (!strstr(regex, "\\0") && !(*regex_alpha)) {
		fprintf(stderr,
		        "--regex need to contain \"\\0\" in hybrid mode (or an alpha option)\n");
		error();
	} else {
		log_event("- Rexgen (after rules): %s", regex);
	}
	return regex;
}

#endif                          /* HAVE_REXGEN */

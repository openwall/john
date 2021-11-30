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

#if !AC_BUILT || HAVE_LOCALE_H
#include <locale.h>
#endif
#include <ctype.h>

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
#include "unicode.h"

#define UNICODE
#define _UNICODE

#ifdef _MSC_VER
char *stpcpy(char *dst, const char *src) {
	strcpy(dst, src);
	return dst + strlen(dst);
}
#endif

char *rexgen_alphabets[256];
static c_iterator_ptr iter = c_iterator_none;
static c_regex_ptr regex_ptr = c_regex_none;
static char *save_str;
static const char *cur_regex, *save_regex;
static char *restore_str, *restore_regex;
static int save_str_len;

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

int rexgen_restore_state_hybrid(const char *sig, FILE *file)
{
	if (!strncmp(sig, "rex-v1", 6))
	{
		int len, ret;
		ret = fscanf(file, "%d\n", &len);
		if (ret != 1) return 1;
		restore_regex = mem_alloc_tiny(len+2, 8);
		fgetl(restore_regex, len+1, file);
		ret = fscanf(file, "%d\n", &len);
		if (ret != 1) return 1;
		restore_str = mem_alloc_tiny(len+2, 8);
		fgetl(restore_str, len+1, file);
		log_event("resuming a regex expr or %s and state of %s\n", restore_regex, restore_str);
		return 0;
	}
	return 1;
}

static void save_state_hybrid(FILE *file)
{
	if (save_str && strlen(save_str)) {
		fprintf(file, "rex-v1\n");
		fprintf(file, "%d\n", (int)strlen(save_regex));
		fprintf(file, "%s\n", save_regex);
		fprintf(file, "%d\n", (int)strlen(save_str));
		fprintf(file, "%s\n", save_str);
	}
}

static void rex_hybrid_fix_state()
{
	char *dstptr=0;
	if (iter)
		c_iterator_get_state(iter, &dstptr);
	if (dstptr) {
		if (strlen(dstptr) > save_str_len) {
			save_str_len = strlen(dstptr)+256;
			MEM_FREE(save_str);
			save_str = mem_alloc(save_str_len+1);
		}
		strcpy(save_str, dstptr);
		save_regex = cur_regex;
	}
}

static int restore_state(FILE *file)
{
	return 0;
}

static void rexgen_setlocale()
{
	char *john_locale;
	const char *ret;

	if (options.internal_cp == UTF_8)
		john_locale = "en_US.UTF-8";
	else
		john_locale = "C";

	ret = setlocale(LC_CTYPE, john_locale);

	if (options.verbosity >= VERB_MAX) {
		if (ret)
			fprintf(stderr, "regex: Locale set to %s\n", ret);
		else
			fprintf(stderr, "regex: Failed to set locale \"%s\"\n", john_locale);
	}
}

// Would be nice to have SOME way to be thread safe!!!
static char BaseWord[LINE_BUFFER_SIZE];

size_t callback(char* dst, const size_t buffer_size)
{
	size_t len = strlen(BaseWord);

	memcpy(dst, BaseWord, (len + 1) * sizeof(BaseWord[0]));
	*BaseWord = 0;
	return len;
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

void parser_error(const char* msg) {
	fprintf(stderr, "%s\n", msg);
}

int do_regex_hybrid_crack(struct db_main *db, const char *regex,
                          const char *base_word, int regex_case,
                          const char *regex_alpha)
{
	c_simplestring_ptr buffer = c_simplestring_new();
	const char* word;
	static int bFirst = 1;
	static int bALPHA = 0;
	int max_len = db->format->params.plaintext_length;
	int retval;

	cur_regex = regex;
	if (options.req_maxlength)
		max_len = options.eff_maxlength;

	if (bFirst)
		rexgen_setlocale();

	//if (options.internal_cp != UTF_8)
	//	cp_to_wcs(BaseWord, sizeof(BaseWord), base_word);
	//else /* options.internal_cp == UTF_8 */
	//	enc_to_wcs(BaseWord, sizeof(BaseWord), base_word);
	strcpy(BaseWord, base_word);

	if (bFirst) {
		bFirst = 0;

		if (regex_alpha && !strncmp(regex_alpha, "alpha", 5)) {
			bALPHA = 1;
			SetupAlpha(regex_alpha);
		}
		rec_init_hybrid(save_state_hybrid);
		crk_set_hybrid_fix_state_func_ptr(rex_hybrid_fix_state);

		regex_ptr = c_regex_cb_mb(regex, callback, parser_error);
		if (!regex_ptr) {
			c_simplestring_delete(buffer);
			fprintf(stderr,
				"Error, invalid regex expression.  John exiting now  base_word=%s  Regex= %s\n",
				base_word, regex);
			error();
		}
		iter = c_regex_iterator(regex_ptr);

		if (restore_str)
			c_iterator_set_state(iter, restore_str);
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

	if (!regex[0]) {
		if (options.flags & FLG_MASK_CHK) {
			if (do_mask_crack(fmt_null_key)) {
				retval = 1;
				goto out;
			}
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

	while (c_iterator_next(iter)) {
		c_simplestring_clear(buffer);
		c_iterator_value(iter, buffer);
		word = c_simplestring_to_string(buffer);
		/**
		  * rexgen already creates the correct encoding
		  */
		//if (options.internal_cp != UTF_8)
		//	utf8_to_cp_r(word, word, sizeof(word));
		if (options.flags & FLG_MASK_CHK) {
			if (do_mask_crack(word)) {
				retval = 1;
				goto out;
			}
		} else
		if (ext_filter((char *)word)) {
			c_simplestring_truncate_bytes(buffer, max_len);
			if (crk_process_key((char *)word)) {
				retval = 1;
				goto out;
			}
		}
	}
	retval = 0;
	goto out;

out:
	c_simplestring_delete(buffer);
	return retval;
}

void do_regex_crack(struct db_main *db, const char *regex)
{
	c_simplestring_ptr buffer = c_simplestring_new();
	const char* word;
	int max_len = db->format->params.plaintext_length;

	if (options.req_maxlength)
		max_len = options.eff_maxlength;

	cur_regex = regex;
	rexgen_setlocale();
	status_init(&get_progress, 0);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);
	crk_init(db, fix_state, NULL);
	rec_init_hybrid(save_state_hybrid);

	regex_ptr = c_regex_cb_mb(regex, callback, parser_error);
	if (!regex_ptr) {
		fprintf(stderr,
		        "Error, invalid regex expression.  John exiting now\n");
		error();
	}

	if (rec_restored && john_main_process) {
		fprintf(stderr, "Proceeding with regex:%s", regex);
		if (options.flags & FLG_MASK_CHK)
			fprintf(stderr, ", hybrid mask:%s", options.mask ?
			        options.mask : options.eff_mask);
		if (options.rule_stack)
			fprintf(stderr, ", rules-stack:%s", options.rule_stack);
		if (options.req_minlength >= 0 || options.req_maxlength)
			fprintf(stderr, ", lengths: %d-%d",
			        options.eff_minlength + mask_add_len,
			        options.eff_maxlength + mask_add_len);
		fprintf(stderr, "\n");
	}

	iter = c_regex_iterator(regex_ptr);
	if (restore_str) {
		c_iterator_set_state(iter, restore_str);
		restore_str = 0;
	}
	while (c_iterator_next(iter)) {
		c_simplestring_clear(buffer);
		c_iterator_value(iter, buffer);
		word = c_simplestring_to_string(buffer);
		if (options.flags & FLG_MASK_CHK) {
			if (do_mask_crack(word))
				break;
		} else
		if (ext_filter((char *)word)) {
			c_simplestring_truncate_bytes(buffer, max_len);
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
		if (options.verbosity >= VERB_MAX)
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

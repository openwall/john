/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2003 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <string.h>

#include "misc.h"
#include "memory.h"
#include "list.h"
#include "getopt.h"
#include "john.h"

static char *opt_errors[] = {
	NULL,	/* No error */
	"Unknown option",
	"Option requires a parameter",
	"Invalid option parameter",
	"Extra parameter for option",
	"Invalid options combination",
	"Duplicate option"
};

/* These are used for argument expansion to the session file. */
static char *completed, *completed_param;
static int completed_negated;

/* Magics for tri-states with optional params */
void *opt_tri_negated = "* prefixed with no- *";
void *opt_tri_noparam = "* no param given *";

static char *opt_find(struct opt_entry *list, char *opt, struct opt_entry **entry)
{
	char *name, *param;
	size_t length;
	struct opt_entry *found;
	int negated = 0;

	if (opt[0] == '-') {
		if (*(name = opt + 1) == '-')
			name++;
		if (!strncmp(name, "no-", 3)) {
			negated = 1;
			name += 3;
		}
		if (!(param = strchr(name, '=')))
			param = strchr(name, ':');
		if (param) {
			char *c = strchr(name, ':');
			/* Arg may contain '=' if delimiter is ':' */
			if (c && param > c)
				param = c;
			length = param - name;
			if (!*++param)
				param = NULL;
		} else
			length = strlen(name);

		found = NULL;
		do {
			/* Cludge for --no-foo options that aren't OPT_BOOL or OPT_TRISTATE */
			if (negated && !strncmp("no-", list->name, 3) && !strncmp(name - 3, list->name, length + 3)) {
				name -= 3;
				length += 3;
				negated = 0;
			}

			if (length <= strlen(list->name))
			if (!strncmp(name, list->name, length)) {
				if (!found) {
					found = list;
					if (length == strlen(list->name))
						break;
				} else {
/*
 * An abbreviated option is not considered ambiguous if first defined
 * alternative is a prefix of all others.  Eg.  --si is parsed as --single
 * even though we also have options --single-seed and --single-wordlist.
 */
					if (strncmp(found->name, list->name, strlen(found->name))) {
						*entry = NULL;
						return NULL;
					}
				}
			}
		} while ((++list)->name);

		if ((*entry = found)) {
			completed_negated = negated;
			completed = found->name;
			completed_param = param;
			return param;
		}
		else
			return NULL;
	} else {
		*entry = list;
		return opt;
	}
}

static int opt_process_param(char *param, char *format, void *buffer)
{
	if (format[0] == OPT_FMT_STR_ALLOC[0]) {
		*(char **)buffer = str_alloc_copy(param);
		return 0;
	} else
	if (format[0] == OPT_FMT_ADD_LIST[0]) {
		list_add(*(struct list_main **)buffer, param);
		return 0;
	} else
	if (format[0] == OPT_FMT_ADD_LIST_MULTI[0]) {
		if (*(struct list_main **)buffer == NULL)
			list_init((struct list_main **)buffer);
		list_add_multi(*(struct list_main **)buffer, param);
		return 0;
	} else
		return sscanf(param, format, buffer) != 1;
}

static int opt_process_one(struct opt_entry *list, opt_flags *flg, char *opt)
{
	char *param, *format;
	struct opt_entry *entry;

	completed = NULL;
	completed_negated = 0;

	param = opt_find(list, opt, &entry);
	if (!entry)
		return OPT_ERROR_UNKNOWN;

	if (entry->seen++ && entry->name[0] && !(entry->flg_set & FLG_MULTI))
		return OPT_ERROR_DUPE;

	if (*flg & entry->flg_set & entry->flg_clr)
		return OPT_ERROR_COMB;

	*flg &= ~entry->flg_clr;
	*flg |= entry->flg_set;

	if (!entry->format && (entry->req_clr & (OPT_TRISTATE | OPT_BOOL))) {
		if (param)
			return OPT_ERROR_PARAM_EXT;
		else
			format = "%d";
	} else
		format = entry->format;

	if (format) {
		if (param && completed_negated) /* Do not allow --no-foo=bar */
			return OPT_ERROR_PARAM_EXT;

		if (!param) {
			if ((entry->req_clr & OPT_TRISTATE) && format[0] == OPT_FMT_STR_ALLOC[0])
				*(char **)entry->param = completed_negated ? OPT_TRISTATE_NEGATED : OPT_TRISTATE_NO_PARAM;
			else
			if (entry->req_clr & (OPT_TRISTATE | OPT_BOOL))
			    param = completed_negated ? "0" : "1";
			else
			if (entry->req_clr & OPT_REQ_PARAM)
				return OPT_ERROR_PARAM_REQ;
		}
		if (param && opt_process_param(param, format, entry->param))
			return OPT_ERROR_PARAM_INV;
	} else
	if (param)
		return OPT_ERROR_PARAM_EXT;

	return OPT_ERROR_NONE;
}

static int opt_check_one(struct opt_entry *list, opt_flags flg, char *opt)
{
	struct opt_entry *entry;

	opt_find(list, opt, &entry);
	if (!entry)
		return OPT_ERROR_UNKNOWN;

	if ((flg & entry->req_set) != entry->req_set || (flg & entry->req_clr))
		return OPT_ERROR_COMB;

	return OPT_ERROR_NONE;
}

void opt_process(struct opt_entry *list, opt_flags *flg, char **argv)
{
	struct opt_entry *entry;
	char **opt;
	int res;

	/* Clear this in case we're resuming */
	if ((entry = list))
	while (entry->name)
		entry++->seen = 0;

	if (*(opt = argv))
	while (*++opt)
	if ((res = opt_process_one(list, flg, *opt))) {
		if (john_main_process)
			fprintf(stderr, "%s: \"%s\"\n", opt_errors[res], *opt);
		error();
	}
}

void opt_check(struct opt_entry *list, opt_flags flg, char **argv)
{
	struct opt_entry *entry;
	char **opt;
	int res;

	if (*(opt = argv))
	while (*++opt) {
		if ((res = opt_check_one(list, flg, *opt))) {
			if (john_main_process)
				fprintf(stderr, "%s: \"%s\"\n", opt_errors[res], *opt);
			error();
		}
		/* Expand **argv to reflect the full option names */
		else if (*opt[0] == '-') {
			int len = strlen(completed) + 2 + 1;

			if (completed_negated)
				len += 3;
			if (completed_param)
				len += strlen(completed_param) + 1;
			*opt = mem_alloc_tiny(len, MEM_ALIGN_NONE);
			sprintf(*opt, "--%s%s%s%s",
			        completed_negated ? "no-" : "",
			        completed,
			        completed_param ? "=" : "",
			        completed_param ? completed_param : "");
		}
	}

	/* Set unseen tri-states to -1 (except OPT_FMT_* which remain NULL) */
	if ((entry = list))
	while (entry->name) {
		if (!entry->seen && (entry->req_clr & OPT_TRISTATE) && entry->param) {
			if (!entry->format)
				*(int*)entry->param = -1;
			else if (entry->format[0] == '%')
				opt_process_param("-1", entry->format, entry->param);
		}
		entry++;
	}
}

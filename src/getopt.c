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
	"Invalid options combination or duplicate option"
};

/*
 * These are used for argument expansion to the session file.
 * Note that three-state option --foobar given abbreviated as --no-fo will
 * have `completed` as "foobar" and `completed_negated` set to true.
 */
static char *completed, *completed_param;
static int completed_negated;

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
			if (c && param > c)
				param = c;
			length = param - name;
			if (!*++param)
				param = NULL;
		} else
			length = strlen(name);

		found = NULL;
		do {
			if (length <= strlen(list->name))
			if (!strncmp(name, list->name, length)) {
				if (!found) {
					found = list;
					if (length == strlen(list->name))
						break;
				} else {
					if (strncmp(found->name, list->name, strlen(found->name))) {
						*entry = NULL;
						return NULL;
					}
				}
			}
		} while ((++list)->name);

		if ((*entry = found)) {
			found->threestate_bool = !(completed_negated = negated);
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
		list_add_multi(*(struct list_main **)buffer, param);
		return 0;
	} else
		return sscanf(param, format, buffer) != 1;
}

static int opt_process_one(struct opt_entry *list, opt_flags *flg, char *opt)
{
	char *param;
	struct opt_entry *entry;

	completed = NULL;
	completed_negated = 0;

	param = opt_find(list, opt, &entry);
	if (!entry)
		return OPT_ERROR_UNKNOWN;

	if (*flg & entry->flg_set & entry->flg_clr)
		return OPT_ERROR_COMB;

	/* Dupe checking just by keeping track of seen */
	if (entry->flg_set == FLG_ONCE && entry->seen++)
		return OPT_ERROR_COMB;

	*flg &= ~entry->flg_clr;
	*flg |= entry->flg_set;

	if (entry->format) {
		if (!param) {
			if (entry->req_clr & OPT_REQ_PARAM)
				return OPT_ERROR_PARAM_REQ;
		} else
		if (opt_process_param(param, entry->format, entry->param))
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

	/* Clear Jumbo dupe-check in case we're resuming */
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

	/* Set all three-states */
	if ((entry = list))
	while (entry->name) {
		if (entry->req_clr & OPT_THREESTATE)
			*(int*)entry->param = entry->seen ? entry->threestate_bool : -1;
		entry++;
	}
}

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

static char *opt_errors[] = {
	NULL,	/* No error */
	"Unknown option",
	"Option requires a parameter",
	"Invalid option parameter",
	"Extra parameter for option",
	"Invalid options combination or duplicate option"
};

static char *opt_find(struct opt_entry *list, char *opt,
	struct opt_entry **entry)
{
	char *name, *param;
	size_t length;
	struct opt_entry *found;

	if (opt[0] == '-') {
		if (*(name = opt + 1) == '-') name++;
		if (!(param = strchr(name, '=')))
			param = strchr(name, ':');
		if (param) {
			length = param - name;
			if (!*++param) param = NULL;
		} else
			length = strlen(name);

		found = NULL;
		do {
			if (length <= strlen(list->name))
			if (!strncmp(name, list->name, length)) {
				if (!found)
					found = list;
				else {
					*entry = NULL;
					return NULL;
				}
			}
		} while ((++list)->name);

		if ((*entry = found))
			return param;
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

	param = opt_find(list, opt, &entry);
	if (!entry) return OPT_ERROR_UNKNOWN;

	if (*flg & entry->flg_set & entry->flg_clr) return OPT_ERROR_COMB;

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
	if (param) return OPT_ERROR_PARAM_EXT;

	return OPT_ERROR_NONE;
}

static int opt_check_one(struct opt_entry *list, opt_flags flg, char *opt)
{
	struct opt_entry *entry;

	opt_find(list, opt, &entry);
	if (!entry) return OPT_ERROR_UNKNOWN;

	if ((flg & entry->req_set) != entry->req_set || (flg & entry->req_clr))
		return OPT_ERROR_COMB;

	return OPT_ERROR_NONE;
}

void opt_process(struct opt_entry *list, opt_flags *flg, char **argv)
{
	char **opt;
	int res;

	if (*(opt = argv))
	while (*++opt)
	if ((res = opt_process_one(list, flg, *opt))) {
		fprintf(stderr, "%s: \"%s\"\n", opt_errors[res], *opt);
		error();
	}
}

void opt_check(struct opt_entry *list, opt_flags flg, char **argv)
{
	char **opt;
	int res;

	if (*(opt = argv))
	while (*++opt)
	if ((res = opt_check_one(list, flg, *opt))) {
		fprintf(stderr, "%s: \"%s\"\n", opt_errors[res], *opt);
		error();
	}
}

/*
 * This file is part of John the Ripper password cracker,
 *
 * Plugin module support.
 *
 * Author:  David Jones
 * Date:     5-SEP-2011
 *
 * Copyright (c) 2011 by David L. Jones <jonesd/at/columbus.rr.com>, and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 */

#ifdef HAVE_DL

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dlfcn.h>
#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#endif

#include "plugin.h"
#include "memdbg.h"

/*
 * Scan fmt_list and look for duplicate format name, which confuses --test.
 * Return 1 if duplicate.
 */
static int duplicate_format_name(struct fmt_main * candidate)
{
	struct fmt_main *fmt;
	for (fmt = fmt_list; fmt; fmt = fmt->next) {
		if (strcmp(fmt->params.label, candidate->params.label) == 0) {
			fprintf(stderr, "Duplicate instance of %s format!\n",
				candidate->params.label);
			return 1;	/* IS a duplicate */
		}
	}
	return 0;
}
/*
 * Keep a list of the handles returned by our dlopen() calls in case we
 * have need to do cleanup in the future.
 */
static void   **dll_handle;

/*
 * Load format modules from DLLs specified by using  the --plugin=dllfile
 * command line option or Dynamic-fmt config file option.  The DLL must
 * define a function FMT_LOADER with the prototype:
 *    struct fmt_main *FMT_LOADER ( int fmt_version );
 *
 * fmt_version is the version number of the fmt_main structure.  It must be
 * changed whenever the fmt_main layout or semantics change.  The FMT_LOADER
 * function returns the address of a fmt_main structure or NULL if a version
 * mismatch or other error occurs.
 */
void register_dlls(
	struct list_main * dll_list,
	char *config_param,
	format_register register_one)
{
	struct list_entry *le;
	struct fmt_main *(*loader) (int fmt_version);
	struct fmt_main *fmt;
	struct list_main *cfg_list;
	int             ndx;
	char           *dll_name, *cfg_names;
	/*
         * Convert config_param string into list structure and chain it
         * and dll_list together temporarily.  Set le to the list head.
         */
	list_init(&cfg_list);
	if (config_param) {
		cfg_names = strdup(config_param);	/* so strtok can modify */
		for (dll_name = strtok(strdup(cfg_names), ","); dll_name;
			dll_name = strtok(0, ",")) {
			dll_name += strspn(dll_name, " \t");	/* skip whitespace */
			if (*dll_name)
				list_add(cfg_list, dll_name);
		}
	}
	le = NULL;
	if (cfg_list->count > 0) {
		le = cfg_list->head;	/* Start with config_param files */
		if (!dll_list)
			printf("Missing options.fmt_dlls!\n");
		else if (dll_list->count > 0)
			cfg_list->tail->next = dll_list->head;
	} else if (!dll_list) {
		printf("/bugcheck/ options.fmt_dlls did not intialize\n");
	} else if (dll_list->count > 0) {
		le = dll_list->head;	/* config_param empty, start with
					 * dll_list */
	} else {
		return;		/* both lists empty, bail out */
	}
	/*
         * Step through combined list and load files named.
         */
	dll_handle = malloc(sizeof(void *) * (cfg_list->count + dll_list->count));
	ndx = 0;
	for (; le; le = le->next) {

		dll_name = le->data;
		dll_handle[ndx] = dlopen(dll_name, RTLD_NOW | RTLD_LOCAL);
		if (dll_handle[ndx]) {
			loader = dlsym(dll_handle[ndx], "FMT_LOADER");
			if (loader) {
				fmt = loader(FMT_MAIN_VERSION);
				if (duplicate_format_name(fmt)) {
					fprintf(stderr, "Plugin %s not registered.\n",
						fmt->params.format_name);
				} else if (fmt)
					register_one(fmt);
				else {
					fprintf(stderr, "Unsupported version for DLL FMT\n");
				}
			} else {
				fprintf(stderr, "Failed to load symbol '%s'\n", "FMT_LOADER");
				fprintf(stderr, "%s\n", dlerror());
			}
		} else {
			fprintf(stderr, "Failed to open DLL '%s'\n", dll_name);
			fprintf(stderr, "%s\n", dlerror());
		}
	}
	if (cfg_list->count > 0)
		cfg_list->tail->next = 0;
}

#endif

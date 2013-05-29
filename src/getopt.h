/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Command line option processing.
 */

#ifndef _JOHN_GETOPT_H
#define _JOHN_GETOPT_H

/*
 * Option flags bitmask type.
 */
typedef unsigned int opt_flags;

/*
 * Supported options list entry, the list ends with a NULL name field.
 * First list entry should have an empty name, and is used for non-options.
 */
struct opt_entry {
/* Option name, as specified on the command line */
	char *name;

/* Option flags to set and clear, respectively. If a bit is set in both
 * flg_set and flg_clr, that flag is set, and required not to be set by
 * the time the option appeared (used to detect duplicate options). */
	opt_flags flg_set, flg_clr;

/* Required option flags to be set and clear, respectively. In req_clr, if
 * OPT_REQ_PARAM is set, the option's parameter is required (by default
 * the parameters are optional). */
	opt_flags req_set, req_clr;

/* Parameter format for sscanf(), should contain one conversion specifier.
 * Some additional formats are supported, see OPT_FMT_* defines below. */
	char *format;

/* Pointer to buffer where the parameter is to be stored */
	void *param;
};

/*
 * Special flag for req_clr.
 */
#define OPT_REQ_PARAM			0x80000000

/*
 * Additional parameter formats.
 */
#define OPT_FMT_STR_ALLOC		"S"	/* str_alloc_copy() */
#define OPT_FMT_ADD_LIST		"L"	/* add_list() */
#define OPT_FMT_ADD_LIST_MULTI		"M"	/* add_list_multi() */

/*
 * Error codes.
 */
#define OPT_ERROR_NONE			0	/* No error */
#define OPT_ERROR_UNKNOWN		1	/* Unknown option */
#define OPT_ERROR_PARAM_REQ		2	/* Parameter required */
#define OPT_ERROR_PARAM_INV		3	/* Invalid parameter */
#define OPT_ERROR_PARAM_EXT		4	/* Extra parameter */
#define OPT_ERROR_COMB			5	/* Invalid combination */

/*
 * Processes all the command line options. Updates the supplied flags and
 * parameters specified in the options list.
 */
extern void opt_process(struct opt_entry *list, opt_flags *flg, char **argv);

/*
 * Checks option dependencies.
 */
extern void opt_check(struct opt_entry *list, opt_flags flg, char **argv);

#endif

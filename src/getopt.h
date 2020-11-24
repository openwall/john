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
 * Spec. for OPT_TRISTATE:
 *
 * For format NULL (implies %d):
 *   option not given      Set options.foobar to -1
 *   --foobar              Set options.foobar to 1
 *   --no-foobar           Set options.foobar to 0
 *   --[no-]foobar=123     OPT_ERROR_PARAM_EXT
 *
 * OPT_BOOL is just a special case of the above, which doesn't touch
 * options.foobar if the option was not given (so will be 0).
 *
 * For format %d:
 *   option not given      Set options.foobar to -1
 *   --foobar              Set options.foobar to 1
 *   --no-foobar           Set options.foobar to 0
 *   --foobar=123          Set options.foobar to 123 (or OPT_ERROR_PARAM_REQ)
 *   --no-foobar=123       OPT_ERROR_PARAM_EXT
 *
 * For format OPT_FMT_STR_ALLOC:
 *   option not given      options.foobar is NULL (is not touched)
 *   --foobar              if OPT_REQ_PARAM: OPT_ERROR_PARAM_REQ,
 *                         otherwise set options.foobar to OPT_TRISTATE_NO_PARAM
 *   --no-foobar           Set options.foobar to OPT_TRISTATE_NEGATED
 *   --foobar=filename     Alloc options.foobar and copy "filename" to it
 *   --no-foobar=filename  OPT_ERROR_PARAM_EXT
 */

/*
 * Command line option processing.
 */

#ifndef _JOHN_GETOPT_H
#define _JOHN_GETOPT_H

#include "common.h"

/* Re-usable flag for an option that can only be used once but can't be
 * distinguished from others using this flag */
#define FLG_ONCE			0x0

/* Re-usable flag for an option that is specifically allowed to be given
 * more than once but can't be distinguished from others using this flag */
#define FLG_MULTI			0x0000000000000010ULL

/*
 * Option flags bitmask type.
 */
typedef uint64_t opt_flags;

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

/* Used to detect dupe options, unless flg_set includes FLG_MULTI. */
	int seen;
};

extern void *opt_tri_negated;
extern void *opt_tri_noparam;

/*
 * Special flags for req_clr.
 */
#define OPT_BOOL			0x0000000020000000ULL
#define OPT_TRISTATE			0x0000000040000000ULL
#define OPT_REQ_PARAM			0x0000000080000000ULL
#define GETOPT_FLAGS			(OPT_BOOL | OPT_TRISTATE | OPT_REQ_PARAM)

/*
 * Tri-state OPT_FMT_STR_ALLOC with optional argument
 */
#define OPT_TRISTATE_NEGATED		opt_tri_negated
#define OPT_TRISTATE_NO_PARAM		opt_tri_noparam

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
#define OPT_ERROR_DUPE			6	/* Duplicate option */

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

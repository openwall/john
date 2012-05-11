/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2011 by Solar Designer
 *
 * ...with changes in the jumbo patch, by magnum
 */

/*
 * External mode support.
 */

#ifndef _JOHN_EXTERNAL_H
#define _JOHN_EXTERNAL_H

#include "compiler.h"
#include "loader.h"

#define EXT_REQ_GENERATE		0x00000001
#define EXT_REQ_FILTER			0x00000002
#define EXT_USES_GENERATE		0x00010000
#define EXT_USES_FILTER			0x00020000

extern unsigned int ext_flags;

extern c_int ext_abort, ext_status;

/*
 * Defined for use in the ext_filter() macro, below.
 */
extern void *f_filter;

/*
 * Returns true if the external mode has function()
 * Used for list=ext-filter and list=ext-mode
 */
int ext_has_function(char *mode, char *function);

/*
 * Initializes an external mode.
 */
extern void ext_init(char *mode, struct db_main *db);

/*
 * Calls an external word filter. Returns 0 if the word is rejected.
 */
#define ext_filter(word) \
	(!f_filter || ext_filter_body(word, word))

/*
 * The actual implementation of ext_filter(); use the macro instead.
 */
extern int ext_filter_body(char *in, char *out);

/*
 * Runs the external mode cracker.
 */
extern void do_external_crack(struct db_main *db);

#endif

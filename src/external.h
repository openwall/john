/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
 */

/*
 * External mode support.
 */

#ifndef _JOHN_EXTERNAL_H
#define _JOHN_EXTERNAL_H

#include "loader.h"

/*
 * Defined for use in the ext_filter() macro, below.
 */
extern char *ext_mode;
extern struct c_ident *f_filter;

/*
 * Initializes an external mode.
 */
extern void ext_init(char *mode);

/*
 * Calls an external word filter. Returns 0 if the word is rejected.
 */
#define ext_filter(word) \
	(!ext_mode || !f_filter || ext_filter_body(word, word))

/*
 * The actual implementation of ext_filter(); use the macro instead.
 */
extern int ext_filter_body(char *in, char *out);

/*
 * Runs the external mode cracker.
 */
extern void do_external_crack(struct db_main *db);

#endif

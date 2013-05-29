/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2011 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
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
 * Initializes an external mode.
 */
extern void ext_init(char *mode);

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

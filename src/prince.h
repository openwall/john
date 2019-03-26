/*
 * Copyright (c) 2015, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#ifndef _JOHN_PRINCE_H
#define _JOHN_PRINCE_H

#include "loader.h"

/*
 * Runs the prince cracker reading words from the supplied file name
 */
extern void do_prince_crack(struct db_main *db, const char *name, int rules);

/* Minimum number of elements per chain */
extern int prince_elem_cnt_min;

/* Maximum number of elements per chain */
extern int prince_elem_cnt_max;

/* Skip, in a string since it may overflow a 64 bit */
extern char *prince_skip_str;

/* Limit, in a string since it may overflow a 64 bit */
extern char *prince_limit_str;

/* If non-zero, only load this many words from wordlist */
extern int prince_wl_max;

#endif /* _JOHN_PRINCE_H */

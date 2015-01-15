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
extern void do_prince_crack(struct db_main *db, char *name);

/* Minimum number of elements per chain */
extern int prince_elem_cnt_min;

/* Maximum number of elements per chain */
extern int prince_elem_cnt_max;

/* Calculate output length distribution from wordlist */
extern int prince_wl_dist_len;

/* Skip, in a string since it may overflow a 64 bit */
extern char *prince_skip_str;

/* Limit, in a string since it may overflow a 64 bit */
extern char *prince_limit_str;

#endif /* _JOHN_PRINCE_H */

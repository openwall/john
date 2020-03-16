/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 */

/*
 * "Single crack" mode.
 */

#ifndef _JOHN_SINGLE_H
#define _JOHN_SINGLE_H

#include "loader.h"

/*
 * Global list of single mode words, from --single-seed or --single-wordlist.
 */
extern struct list_main *single_seed;

/*
 * Runs the cracker.
 */
extern char* do_single_crack(struct db_main *db);

#endif

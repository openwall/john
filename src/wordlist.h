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
 * Wordlist cracker.
 */

#ifndef _JOHN_WORDLIST_H
#define _JOHN_WORDLIST_H

#include "loader.h"

/*
 * Runs the wordlist cracker reading words from the supplied file name, or
 * stdin if name is NULL.
 */
extern void do_wordlist_crack(struct db_main *db, char *name, int rules);

#endif

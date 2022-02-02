/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2022 by Solar Designer
 */

/*
 * Opportunistic duplicate candidate password suppressor.
 */

#ifndef _JOHN_SUPPRESSOR_H
#define _JOHN_SUPPRESSOR_H

/*
 * Initializes the suppressor.  Must be called after crk_init(), first with
 * "update" set, then possibly (by a next cracking mode that does not produce
 * duplicates itself) without.  Does nothing if only called without "update".
 */
extern void suppressor_init(int update);

#endif

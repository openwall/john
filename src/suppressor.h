/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2022 by Solar Designer
 */

/*
 * Opportunistic duplicate candidate password suppressor.
 */

#ifndef _JOHN_SUPPRESSOR_H
#define _JOHN_SUPPRESSOR_H

#define SUPPRESSOR_OFF		0
#define SUPPRESSOR_UPDATE	1
#define SUPPRESSOR_CHECK	2
#define SUPPRESSOR_FORCE	4

/*
 * Initializes the suppressor.  Must be called after crk_init(), first with
 * SUPPRESSOR_UPDATE set, then possibly (by a next cracking mode that does not
 * produce duplicates itself) with only SUPPRESSOR_CHECK.  Does nothing if only
 * ever called without SUPPRESSOR_UPDATE.  The suppressor auto-disables itself
 * when its efficiency becomes low, but SUPPRESSOR_FORCE prevents that.
 */
extern void suppressor_init(unsigned int flags);

#endif

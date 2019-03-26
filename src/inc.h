/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 */

/*
 * Incremental mode cracker.
 */

#ifndef _JOHN_INC_H
#define _JOHN_INC_H

#include "loader.h"

/*
 * Runs the incremental mode cracker.
 */
extern void do_incremental_crack(struct db_main *db, const char *mode);

#endif

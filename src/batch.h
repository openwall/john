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
 * Batch cracker.
 */

#ifndef _JOHN_BATCH_H
#define _JOHN_BATCH_H

#include "loader.h"

/*
 * Runs the cracker.
 */
extern void do_batch_crack(struct db_main *db);

#endif

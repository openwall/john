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
 * Regular expression cracker.
 */

#ifndef _JOHN_REGEX_H
#define _JOHN_REGEX_H

#include "loader.h"

/*
 * Runs the Regular expression cracker
 */
void do_regex_crack(struct db_main *db, char *regex);

#endif
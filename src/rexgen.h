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
#ifndef HAVE_REXGEN
#define do_rexgen_crack_as_rules(a,word) crk_process_key(word)
#else
void do_rexgen_crack(struct db_main *db, const char *rexgen);
int do_rexgen_crack_as_rules(const char *rexgen, const char *base_word);
#endif



#endif

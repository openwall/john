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
#define do_regex_crack_as_rules(a,word) crk_process_key(word)
#else
void do_regex_crack(struct db_main *db, const char *regex);
int do_regex_crack_as_rules(const char *regex, const char *base_word);
#endif



#endif

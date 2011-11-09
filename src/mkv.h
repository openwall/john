/*
 * This software is Copyright © 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#ifndef _JOHN_MKV_H
#define _JOHN_MKV_H

#include "loader.h"
#include "mkvlib.h"

/*
 * Runs the markov mode cracker.
 */
extern void do_markov_crack(struct db_main *db, unsigned int mkv_level, unsigned long long mkv_start, unsigned long long mkv_end, unsigned int mkv_maxlen, unsigned int mkv_minlevel, unsigned int mkv_minlen);

#endif

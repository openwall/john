/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#ifndef _JOHN_MKV_H
#define _JOHN_MKV_H

#include "loader.h"
#include "mkvlib.h"

/*
 * Runs the markov mode cracker.
 */
extern void do_markov_crack(struct db_main *db, char *mkv_param);

#endif

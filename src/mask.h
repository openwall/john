/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * This software is Copyright (c) 2013 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Mask mode cracker.
 */

#ifndef _JOHN_MASK_H
#define _JOHN_MASK_H
#include "opencl_shared_mask.h"
/*
 * Some format methods accept pointers to these, yet we can't just include
 * loader.h here because that would be a circular dependency.
 */
struct db_main;

extern unsigned char *mask_offset_buffer;

/*
 * Runs the mask mode cracker.
 */
extern void do_mask_crack(struct db_main *db, char *mask, char *wordlist);

#endif

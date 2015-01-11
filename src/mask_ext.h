/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2014 by Sayantan Datta
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _JOHN_MASK_EXT_H
#define _JOHN_MASK_EXT_H

#include "mask.h"

#define MASK_FMT_INT_PLHDR 		3

extern void mask_calc_combination(cpu_mask_context *);
extern int *mask_skip_ranges;
extern int mask_max_skip_loc;
extern int mask_int_cand_target;

#endif
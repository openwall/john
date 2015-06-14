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
#include "opencl_mask.h"

typedef union {
	unsigned char x[4];
	unsigned int i;
} mask_char4;

typedef struct {
	mask_char4 *int_cand;
	cpu_mask_context *int_cpu_mask_ctx;
	int num_int_cand;
} mask_int_cand_ctx;

extern void mask_calc_combination(cpu_mask_context *, int);
extern int *mask_skip_ranges;
extern int mask_max_skip_loc;
extern int mask_int_cand_target;
extern int is_static_gpu_mask;
extern mask_int_cand_ctx mask_int_cand;

#endif

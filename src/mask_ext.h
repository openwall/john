/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013-2018 by magnum
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

typedef union {
	unsigned char x[4];
	unsigned int i;
} mask_char4;

typedef struct {
	mask_char4 *int_cand;
	mask_cpu_context *int_cpu_mask_ctx;
	int num_int_cand;
} mask_int_cand_ctx;

extern void mask_ext_calc_combination(mask_cpu_context *, int);

/*
 * Mask ranges that are generated on GPU (and skipped on CPU, which
 * may explain the unintuitive name).
 * Note that if mask_skip_ranges[n] is eg. 0, it doesn't mean pos. 0 in
 * the key, but the first pos of key that is a mask range/placeholder.
 */
extern int *mask_skip_ranges;

/*
 * Max. mask pos that are generated on GPU.
 */
extern int mask_max_skip_loc;

/*
 * Format's requested number of internal candidates. Should be based on
 * actual GPU speed.
 */
extern int mask_int_cand_target;

/*
 * Masks like ?d?d or ?d?w are "static" on GPU, as in "positions are static".
 * ?w?d is not static (base word length may vary), but ?d?w?d may be static
 * as long as last ?d is not GPU-side.
 */
extern int mask_gpu_is_static;

extern mask_int_cand_ctx mask_int_cand;

#endif

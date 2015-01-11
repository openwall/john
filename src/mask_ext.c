/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2014 by Sayantan Datta
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "mask_ext.h"
#include "memory.h"

int *mask_skip_ranges = NULL;
int mask_max_skip_loc = -1;
int mask_int_cand_target = 0;

static void combination_util(int *, int, int, int, int,
			     cpu_mask_context *, int *);

void mask_calc_combination(cpu_mask_context *ptr) {
	int *data, i, n;
	int delta_to_target = 0x7fffffff;
	if (!mask_int_cand_target) return;

	n = ptr->count;
	data = (int*) malloc(n * sizeof(int));
	mask_skip_ranges = (int*) malloc (MASK_FMT_INT_PLHDR * sizeof(int));

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		mask_skip_ranges[i] = -1;

	/* Fix the maximum number of ranges that can be calculated on GPU to 3 */
	for (i = 1; i <= MASK_FMT_INT_PLHDR; i++)
		combination_util(data, 0, n - 1, 0, i, ptr,
				 &delta_to_target);

	MEM_FREE(data);
}

static void combination_util(int *data, int start, int end, int index,
                             int r, cpu_mask_context *ptr, int *delta) {
	int i;

	if (index == r) {
		int tmp = 1;
		for (i = 0; i < r; i++)
			tmp *= ptr->ranges[data[i]].count;

		tmp -= mask_int_cand_target;
		tmp = tmp < 0 ? -tmp : tmp;

		if (tmp < *delta) {
			for (i = 0; i < r; i++)
				mask_skip_ranges[i] = data[i];

			mask_max_skip_loc = mask_skip_ranges[i-1];
			*delta = tmp;
		}

		return;
	}

	for (i = start; i <= end && end - i + 1 >= r - index; i++) {
		data[index] = i;
		combination_util(data, i + 1, end, index + 1,
				 r, ptr, delta);
	}
}

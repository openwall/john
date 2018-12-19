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

#include "mask_ext.h"
#include "misc.h"	// error()
#include "options.h"
#include "memory.h"

//#define MASK_DEBUG

int *mask_skip_ranges = NULL;
int mask_max_skip_loc = -1;
int mask_int_cand_target = 0;
int mask_gpu_is_static = 0;
mask_int_cand_ctx mask_int_cand = { NULL, NULL, 1 };

static void combination_util(int *data, int start, int end, int index,
                             int r, mask_cpu_context *ptr, int *delta)
{
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

static void generate_int_keys(mask_cpu_context *ptr)
{
	int i, repeat = 1, modulo;

#ifdef MASK_DEBUG
	fprintf(stderr, "%s()\n", __FUNCTION__);
#endif

#define fill_cand(t) \
	for (i = 0; i < mask_int_cand.num_int_cand; i++) \
		mask_int_cand.int_cand[i].x[t] =	 \
			ptr->ranges[mask_skip_ranges[t]].chars \
			[(i/repeat) % modulo]

#define cond(t) t < MASK_FMT_INT_PLHDR && mask_skip_ranges[t] != -1

	for (i = 1; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
		repeat *= ptr->ranges[mask_skip_ranges[i]].count;
	modulo = ptr->ranges[mask_skip_ranges[0]].count;

	for (i = 0; i < mask_int_cand.num_int_cand; i++)
		mask_int_cand.int_cand[i].i = 0;

	fill_cand(0);

	if (cond(1)) {
		modulo = ptr->ranges[mask_skip_ranges[1]].count;
		repeat /= modulo;
		fill_cand(1);
	}
	if (cond(2)) {
		modulo = ptr->ranges[mask_skip_ranges[2]].count;
		repeat /= modulo;
		fill_cand(2);
	}
	if (cond(3)) {
		repeat = 1;
		modulo = ptr->ranges[mask_skip_ranges[3]].count;
		fill_cand(3);
	}
#undef fill_cand
#undef cond
}

static void check_static_gpu_mask(int max_static_range)
{
	unsigned int i;
	mask_gpu_is_static = 1;

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (max_static_range <= mask_skip_ranges[i]) {
			mask_gpu_is_static = 0;
			break;
		}

	mask_gpu_is_static |= !(options.flags & FLG_MASK_STACKED);

#ifdef MASK_DEBUG
	fprintf(stderr, "%s() return: mask is%s static\n", __FUNCTION__, mask_gpu_is_static ? "" : "n't");
#endif
}

void mask_ext_calc_combination(mask_cpu_context *ptr, int max_static_range)
{
	int *data, i, n;
	int delta_to_target = 0x7fffffff;

#ifdef MASK_DEBUG
	fprintf(stderr, "%s()\n", __FUNCTION__);
#endif

	mask_int_cand.num_int_cand = 1;
	mask_int_cand.int_cpu_mask_ctx = NULL;
	mask_int_cand.int_cand = NULL;

	if (!mask_int_cand_target)
		return;

	if (MASK_FMT_INT_PLHDR > 4) {
		fprintf(stderr, "MASK_FMT_INT_PLHDR value must not exceed 4.\n");
		error();
	}

	n = ptr->count;
	data = (int*) mem_alloc(n * sizeof(int));
	mask_skip_ranges = (int*) mem_alloc(MASK_FMT_INT_PLHDR * sizeof(int));

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		mask_skip_ranges[i] = -1;

	/* Fix the maximum number of ranges that can be calculated on GPU to 3 */
	for (i = 1; i <= MASK_FMT_INT_PLHDR; i++)
		combination_util(data, 0, n - 1, 0, i, ptr,
				 &delta_to_target);

	if (mask_skip_ranges[0] != -1) {
		mask_int_cand.num_int_cand = 1;
		for (i = 0; i < MASK_FMT_INT_PLHDR &&
		     mask_skip_ranges[i] != -1; i++)
			mask_int_cand.num_int_cand *= ptr->
				ranges[mask_skip_ranges[i]].count;
	}

	if (mask_int_cand.num_int_cand > 1) {
		mask_int_cand.int_cpu_mask_ctx = ptr;
		mask_int_cand.int_cand = (mask_char4 *)
			mem_alloc(mask_int_cand.num_int_cand * sizeof(mask_char4));
		generate_int_keys(ptr);
	}

	check_static_gpu_mask(max_static_range);

#if 0
	for (i = 0; i < mask_int_cand.num_int_cand && mask_int_cand.int_cand; i++)
		fprintf(stderr, "%c%c%c%c\n", mask_int_cand.int_cand[i].x[0], mask_int_cand.int_cand[i].x[1], mask_int_cand.int_cand[i].x[2], mask_int_cand.int_cand[i].x[3]);
#endif
	MEM_FREE(data);
}

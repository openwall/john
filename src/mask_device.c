/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2014 by Sayantan Datta
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */
#include "mask.h"
#include "mask_device.h"

static void combination_util(int data[], int start, int end, int index, int r);

void calc_combination(int n) {
	int data[n], i;

	/* Fix the maximum number of ranges that can be calculated on GPU to 3 */
	for (i = 1; i <= 3; i++)
		combination_util(data, 0, n - 1, 0, i);

}

static void combination_util(int data[], int start, int end, int index,
                             int r) {
	int i;

	if (index == r) {
	  for (i = 0; i < r; i++)
		fprintf(stderr, "%d", data[i]);
		fprintf(stderr, "\n");

		return;
	}

	for (i = start; i <= end && end - i + 1 >= r - index; i++) {
		data[index] = i;
		combination_util(data, i + 1, end, index + 1, r);
	}
}

/*
 * This software is Copyright (c) 2013 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _JOHN_OPENCL_SHARED_MASK_H
#define _JOHN_OPENCL_SHARED_MASK_H

#define MASK_RANGES_MAX		16
#define MAX_GPU_CHARS		64
#define MAX_GPU_RANGES		3

  /* Range of charcters for a placeholder in the mask */
struct mask_range {
  /* Charchters in the range */
	unsigned char chars[0x100];

  /* Set to zero when the characters in the range are not consecutive,
   * otherwise start is set to the minumum value in range. Minimum
   * value cannot be a null character which has a value zero.*/
  	unsigned char start;

  /* Number of charchters in the range */
	int count;

  /* Postion of the charcters in mask */
	int pos;
};

  /* Simplified mask structure for processing the mask inside a format for password generation */
struct mask_context {
  /* Set of mask pacholders selected for processing inside the format */
	struct mask_range ranges[MASK_RANGES_MAX];

  /* Positions in mask for overwriting in the format */
	int activeRangePos[MASK_RANGES_MAX];

  /* Number of postions for overwriting in the format */
	int count;

  /* Wordlist mode flag, set to 1 when used with wordlist else set to 0 */
	unsigned char flg_wrd;
};

#endif
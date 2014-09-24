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
 * Mask mode cracker.
 */

#ifndef _JOHN_MASK_H
#define _JOHN_MASK_H

#include "loader.h"

#define MAX_NUM_MASK_PLHDR 127 // Maximum number of placeholders in a mask.

typedef struct {
	/* store locations of op braces in mask */
	int stack_op_br[MAX_NUM_MASK_PLHDR + 1];
	/* store locations of cl braces in mask */
	int stack_cl_br[MAX_NUM_MASK_PLHDR + 1];
	/* store locations of valid ? in mask */
	int stack_qtn[MAX_NUM_MASK_PLHDR + 1];
	/* 1 if parse is successful, otherwise 0 */
	int parse_ok;
} parsed_ctx;

 /* Range of characters for a placeholder in the mask */
 /* Rearranging the structure could affect performance */
typedef struct {
	/* Characters in the range */
	unsigned char chars[0xF8];
	/* next active range */
	unsigned char next;
	/* current postion in chars[] while iterating */
	unsigned char iter;
	/* Number of characters in the range */
	unsigned char count;
	/*
	 * Set to zero when the characters in the range are not consecutive,
	 * otherwise start is set to the minumum value in range. Minimum
	 * value cannot be a null character which has a value zero.
	 */
	unsigned char start;
	/* Postion of the characters in key */
	int pos;
} mask_range;

/* Processed mask structure for password generation on CPU */
typedef struct {
	/* Set of mask placeholders for generating password */
	mask_range ranges[MAX_NUM_MASK_PLHDR + 1];
	/* Positions in mask for iteration on CPU */
	int active_positions[MAX_NUM_MASK_PLHDR + 1];
	/* Number of postions for iterating on CPU */
	int count;
	/* offset at which mask starts in the key */
	int offset;
} cpu_mask_context;

/*
 * Runs the mask mode cracker.
 */
extern void do_mask_crack(struct db_main *db, char *mask);

#endif

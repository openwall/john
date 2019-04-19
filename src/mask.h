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

/*
 * Mask mode cracker.
 */

#ifndef _JOHN_MASK_H
#define _JOHN_MASK_H

#include "loader.h"

// See also opencl_mask.h.
#define MASK_FMT_INT_PLHDR 4

// Maximum number of placeholders in a mask.
#define MAX_NUM_MASK_PLHDR 125

//#define MASK_DEBUG

typedef struct {
	/* store locations of op braces in mask */
	int stack_op_br[MAX_NUM_MASK_PLHDR + 1];
	/* store locations of cl braces in mask */
	int stack_cl_br[MAX_NUM_MASK_PLHDR + 1];
	/* store locations of valid ? in mask */
	int stack_qtn[MAX_NUM_MASK_PLHDR + 1];
} mask_parsed_ctx;

 /* Range of characters for a placeholder in the mask */
 /* Rearranging the structure could affect performance */
typedef struct {
	/* Characters in the range */
	unsigned char chars[0xFF];
	/* next active range */
	unsigned char next;
	/* current postion in chars[] while iterating */
	unsigned char iter;
	/* Number of characters in the range */
	unsigned char count;
	/*
	 * Set to zero when the characters in the range are not consecutive,
	 * otherwise start is set to the minimum value in range. Minimum
	 * value cannot be a null character which has a value zero.
	 */
	unsigned char start;
	/* Base postion of the characters in key */
	int pos;
	/* offset when a key is inserted from other mode */
	int offset;
} mask_range;

/* Processed mask structure for password generation on CPU */
typedef struct {
	/* Set of mask placeholders for generating password */
	mask_range ranges[MAX_NUM_MASK_PLHDR + 1];
	/* Positions in mask for iteration on CPU */
	int active_positions[MAX_NUM_MASK_PLHDR + 1];
	/* Postion of the first active range */
	int ps1;
	/* Total number of placeholders, cpu + gpu */
	int count;
	/* Number of placeholders active for iteration on CPU */
	int cpu_count;
	/* offset at which mask starts in the key */
	int offset;
} mask_cpu_context;

/*
 * Initialize mask mode cracker.
 */
extern void mask_init(struct db_main *db, char *unprocessed_mask);

/*
 * Initialize cracker database.
 */
extern void mask_crk_init(struct db_main *db);

/*
 * Runs the mask mode cracker.
 */
extern int do_mask_crack(const char *key);

extern void mask_done(void);
extern void mask_destroy(void);

/*
 * These are exported for stacked modes (eg. hybrid mask)
 */
extern void mask_fix_state(void);
extern void mask_save_state(FILE *file);
extern int mask_restore_state(FILE *file);

/* Evaluate mask_add_len from a given mask string without calling mask_init */
extern int mask_calc_len(const char *mask);

/*
 * Total number of candidates (per node) to begin with. Remains unchanged
 * throughout one call to do_mask_crack but may vary with hybrid parent key
 * length.  The number includes the part that is processed on GPU, and is
 * used as a multiplier in native mask mode's and parent modes' get_progress().
 */
extern uint64_t mask_tot_cand;

/* Hybrid mask's contribution to key length. Eg. for bc?l?d?w this will be 4. */
extern int mask_add_len;

/* Number of ?w in hybrid mask */
extern int mask_num_qw;

/* Number of times parent mode called hybrid mask. */
extern uint64_t mask_parent_keys;

/* Current length when pure mask mode iterates over lengths */
extern int mask_cur_len;

/* Incremental mask iteration started at this length (contrary to options) */
extern int mask_iter_warn;

/* Mask mode is incrementing mask length */
extern int mask_increments_len;

#endif

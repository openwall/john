/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 */

/*
 * Rules preprocessor.
 */

#ifndef _JOHN_RPP_H
#define _JOHN_RPP_H

#include "arch.h"
#include "params.h"
#include "config.h"

/*
 * Character range.
 */
struct rpp_range {
/* Character position in output rule */
	char *pos;

/* Number of character values */
	int count;

/* Current character value index */
	int index;

/* Present characters bitmask for dupe checking */
	ARCH_WORD mask[0x100 / ARCH_BITS];

/* Character values */
	char chars[0x100];
};

/*
 * Preprocessor context.
 */
struct rpp_context {
/* Current rule before preprocessing */
	struct cfg_line *input;

/* Current rule after preprocessing */
	char output[RULE_BUFFER_SIZE];

/* Number of character ranges in this rule */
	int count;

/* Character ranges. I really hate to do it this way, but otherwise context
 * management would be far more complicated. */
	struct rpp_range ranges[RULE_RANGES_MAX];
};

/*
 * Initializes the preprocessor's context for the supplied configuration file
 * rules subsection. Returns a non-zero value on error (no rules found).
 */
extern int rpp_init(struct rpp_context *ctx, char *subsection);

/*
 * Returns a preprocessed rule and moves to the next one.
 */
extern char *rpp_next(struct rpp_context *ctx);

#endif

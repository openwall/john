/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2009,2010 by Solar Designer
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

/* Whether the range should be processed "in parallel" with preceding ranges */
	int flag_p;

/* Whether repeated characters should be added or discarded */
	int flag_r;

/* Present characters bitmask for dupe checking */
	ARCH_WORD mask[0x100 / ARCH_BITS];

/* Character values */
	char chars[0x100];
};

/*
 * Reference to a character range.
 */
struct rpp_ref {
/* Character position in output rule */
	char *pos;

/* Range being referenced (by number) */
	int range;
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

/* Number of references to ranges in this rule */
	int refs_count;

/* References to ranges (mapping of reference number to range number) */
	struct rpp_ref refs[RULE_RANGES_MAX];

/* Character ranges */
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

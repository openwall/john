/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 */

/*
 * Rules support routines.
 */

#ifndef _JOHN_RULES_H
#define _JOHN_RULES_H

#include "loader.h"
#include "rpp.h"

/*
 * Error codes.
 */
#define RULES_ERROR_NONE		0
#define RULES_ERROR_END			1
#define RULES_ERROR_UNKNOWN		2
#define RULES_ERROR_POSITION		3
#define RULES_ERROR_CLASS		4
#define RULES_ERROR_REJECT		5

/*
 * Error names.
 */
extern char *rules_errors[];

/*
 * Last error code.
 */
extern int rules_errno;

/*
 * Configuration file line number, only set after a rules_check() call if
 * rules_errno indicates an error.
 */
extern int rules_line;

/*
 * Initializes the rules support.
 */
extern void rules_init(int max_length);

/*
 * Processes rule reject flags, based on information from the database.
 * Returns a pointer to the first command in the rule if it's accepted,
 * or NULL if rejected or an error occured. Also sets rules_errno on
 * error. If the database is NULL, all rules are accepted (to be used
 * for syntax checking).
 */
extern char *rules_reject(char *rule, struct db_main *db);

/*
 * Applies rule to a word. Returns the updated word, or NULL if rejected or
 * an error occured. Also sets rules_errno on error.
 *
 * split > 0	"single crack" mode, split is the second word's position
 * split == 0	"single crack" mode, only one word
 * split < 0	other cracking modes, "single crack" mode rules are invalid
 */
extern char *rules_apply(char *word, char *rule, int split);

/*
 * Checks if all the rules for context are valid. Returns the number of rules,
 * or returns zero and sets rules_errno on error.
 *
 * split == 0	"single crack" mode rules allowed
 * split < 0	"single crack" mode rules are invalid
 */
extern int rules_check(struct rpp_context *start, int split);

/*
 * Similar to rules_check(), but displays a message and does not return on
 * error.
 */
extern int rules_count(struct rpp_context *start, int split);

#endif

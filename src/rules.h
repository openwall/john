/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2009 by Solar Designer
 */

/*
 * Rules support routines.
 */

#ifndef _JOHN_RULES_H
#define _JOHN_RULES_H

#include "loader.h"
#include "list.h"
#include "rpp.h"

/*
 * If rules are used with "-pipe" and there's a large number of them,
 * some rules logging will be muted unless verbosity is bumped.
 * Similar will happen when running stacked rules, after rewinding
 * either ruleset.
 * This is for not creating gigabytes of logs since we'll go through
 * all rules over and over again.
 */
extern int rules_mute, stack_rules_mute;

/*
 * If this is set, our result will be passed to later rules. This may
 * mean, for example, that we could want to consider max_length as
 * PLAINTEXT_BUFFER_SIZE so we don't truncate or reject a word that will
 * later become valid. It's not fully settled though.
 */
extern unsigned int rules_stacked_after;

/*
 * Line number of stacked rule in use.
 */
extern int rules_stacked_number;

/*
 * Stacked rules context.
 */
typedef struct {
	struct list_main *stack_rule;
	struct list_entry *rule;
	int done;
} rule_stack;

/*
 * Initializes the rules support.
 */
extern void rules_init(struct db_main *db, int max_length);

/*
 * Processes rule reject flags, based on information from the database.
 * Returns a pointer to the first command in the rule if it's accepted,
 * or NULL if rejected or an error occurred. Also sets rules_errno on
 * error. If the database is NULL, almost all rules are accepted (to be
 * used for syntax checking).
 *
 * split == 0	"single crack" mode rules allowed
 * split < 0	"single crack" mode rules are invalid
 *
 * last may specify which internal buffer must not be touched.
 */
extern char *rules_reject(char *rule, int split, char *last,
	struct db_main *db);

/*
 * Applies rule to a word. Returns the updated word, or NULL if rejected or
 * an error occurred. Also sets rules_errno on error.
 *
 * split > 0	"single crack" mode, split is the second word's position
 * split == 0	"single crack" mode, only one word
 * split < 0	other cracking modes, "single crack" mode rules are invalid
 *
 * If last is non-NULL, it should be the previous mangled word and it is
 * assumed to be properly aligned for ARCH_WORD accesses (pointers returned by
 * rules_apply() are properly aligned).  If the new mangled word matches the
 * previous one, it will be rejected (rules_apply() will return NULL).
 */
extern char *rules_apply(char *word, char *rule, int split, char *last);

/*
 * Similar to rules_check(), but displays a message and does not return on
 * error.  Also performs 'dupe' rule removal, and lists if any rules were removed.
 */
extern int rules_count(struct rpp_context *start, int split);

/*
 * The data lines (linked list), of rules are passed in, and any duplicate
 * rules are removed. The rules are first copied to a temp array, and there
 * they get 'reduced', by dropping the no-op information (calling rules_reject
 * with split==-1 and the db==NULL).  If log is true then any rules that are
 * removed get logged.  The return count is the number of rules removed.
 * 0 return means no dupes found.  NOTE the pLines list can be modified by this
 * function, simply by manipulating the linked list pointers.
 */
extern int rules_remove_dups(struct cfg_line *pLines, int log);

/*
 * Initialize a stacked rule contect using the named ruleset.
 */
extern int rules_init_stack(char *ruleset, rule_stack *stack_ctx,
                            struct db_main *db);

/*
 * Advance stacked rules. We iterate main rules first and only then we
 * advance the stacked rules (and rewind the main rules). Repeat until
 * main rules are done with the last stacked rule.
 */
extern int rules_advance_stack(rule_stack *ctx, int quiet);

/*
 * Return next word from stacked rules, or NULL if it was rejected. The
 * next rule will not be loaded unless caller calls rules_advance_stack().
 */
extern char *rules_process_stack(char *key, rule_stack *ctx);

/*
 * Return next word from stacked rules, calling rules_advance_stack() as
 * necessary. Once there's no rules left in stack, return NULL-
 */
extern char *rules_process_stack_all(char *key, rule_stack *ctx);

#endif

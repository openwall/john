/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 * Copyright (c) 2013 by magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h> /* for fprintf(stderr, ...) */

#include "misc.h" /* for error() */
#include "logger.h"
#include "recovery.h"
#include "os.h"
#include "signals.h"
#include "status.h"
#include "options.h"
#include "rpp.h"
#include "external.h"
#include "cracker.h"
#include "john.h"
#include "mask.h"

#include "memdbg.h"

static struct rpp_context ctx, rec_ctx;

/*
 * A "sequence number" for distributing the candidate passwords across nodes.
 * It is OK if this number overflows once in a while, as long as this happens
 * in the same way for all nodes (must be same size unsigned integer type).
 */
static unsigned int seq, rec_seq;
static unsigned long long cand;

static int get_progress(int *hundth_perc)
{
	int hundredXpercent, percent;
	unsigned long long try;

	try = ((unsigned long long)status.cands.hi << 32) + status.cands.lo;

	if (!try) {
		hundredXpercent = percent = 0;
		return percent;
	}

	if (!cand)
		return -1;

	if (try > 1844674407370955ULL) {
		*hundth_perc = percent = 99;
	} else {
		hundredXpercent = (int)((unsigned long long)(10000 * (try)) / (unsigned long long)cand);
		percent = hundredXpercent / 100;
		*hundth_perc = hundredXpercent - (percent*100);
	}

	return percent;
}

static void save_state(FILE *file)
{
	int i;

	fprintf(file, "%u\n", rec_seq);
	fprintf(file, "%s\n", rec_ctx.output);
	fprintf(file, "%d\n", rec_ctx.count);
	for (i = 0; i < rec_ctx.count; i++)
		fprintf(file, "%d\n", rec_ctx.ranges[i].index);
}

static int restore_state(FILE *file)
{
	int i;

	if (fscanf(file, "%u\n", &seq) != 1)
		return 1;
	if (fscanf(file, "%128[^\n]\n", ctx.output) != 1)
		return 1;
	if (fscanf(file, "%d\n", &ctx.count) != 1)
		return 1;
	for (i = 0; i < ctx.count; i++)
		if (fscanf(file, "%d\n", &ctx.ranges[i].index) != 1)
			return 1;
	return 0;
}

static void fix_state(void)
{
	rec_seq = seq;
	rec_ctx = ctx;
}

void do_mask_crack(struct db_main *db, char *mask)
{
	char *word;
	int my_words, their_words;
	int i;

	/* We do not yet support min/max-len */
	if (options.force_minlength >= 0 || options.force_maxlength) {
		fprintf(stderr, "Mask mode: --min-length and --max-length currently not supported\n");
		error();
	}

	log_event("Proceeding with mask mode");

	rpp_init_mask(&ctx, mask);

	seq = 0;

	status_init(&get_progress, 0);

	rpp_process_rule(&ctx);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);

	my_words = options.node_max - options.node_min + 1;
	their_words = options.node_min - 1;

	if (seq) {
/* Restored session.  seq is right after a word we've actually used. */
		int for_node = seq % options.node_count + 1;
		if (for_node < options.node_min ||
		        for_node > options.node_max) {
/* We assume that seq is at the beginning of other nodes' block */
			their_words = options.node_count - my_words;
		} else {
			my_words = options.node_max - for_node + 1;
			their_words = 0;
		}
	}

	cand = 1;
	for (i = 0; i < ctx.count; i++)
		cand *= ctx.ranges[i].count;
	if (options.node_count) {
		cand *= options.node_max - options.node_min + 1;
		cand /= options.node_count;
	}

	while ((word = rpp_next(&ctx))) {
		if (options.node_count) {
			seq++;
			if (their_words) {
				their_words--;
				continue;
			}
			if (--my_words == 0) {
				my_words =
					options.node_max - options.node_min + 1;
				their_words = options.node_count - my_words;
			}
		}
		if (ext_filter(word))
			if (crk_process_key(word))
				break;
	}

	// Ensure we report DONE
	if (!event_abort)
		cand = ((unsigned long long)status.cands.hi << 32) +
			status.cands.lo;

	crk_done();

	rec_done(event_abort);
}

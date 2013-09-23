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

static struct rpp_context ctx, rec_ctx;

/* TODO: the fork/node/MPI splitting is very inefficient */
static unsigned int seq, rec_seq;

static int get_progress(int *hundth_perc)
{
	int hundredXpercent, percent;
	unsigned long long try, cand;
	int i;

	i = 0; cand = 1;
	while (ctx.ranges[i].count)
		cand *= ctx.ranges[i++].count;

	if (options.node_count) {
		cand /= options.node_count;
	}

	try = ((unsigned long long)status.cands.hi << 32) + status.cands.lo;

	if (!try) {
		hundredXpercent = percent = 0;
		return percent;
	}

	if (!cand)
		return -1;

	if (try > 1844674407370955LL) {
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
	if (fscanf(file, "%s\n", ctx.output) != 1)
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

	log_event("Proceeding with mask mode");

	rpp_init_mask(&ctx, mask);

	status_init(&get_progress, 0);

#if 1
	rpp_process_rule(&ctx);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);
#else
	crk_init(db, NULL, NULL);
#endif

	while ((word = rpp_next(&ctx))) {
		if (options.node_count) {
			int for_node = seq++ % options.node_count + 1;
			if (for_node < options.node_min ||
			    for_node > options.node_max)
				continue;
		}
		if (ext_filter(word))
			if (crk_process_key(word))
				break;
	}

	crk_done();

#if 1
	rec_done(event_abort);
#endif
}

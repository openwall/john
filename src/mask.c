/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h> /* for fprintf(stderr, ...) */

#include "misc.h" /* for error() */
#include "logger.h"
#include "status.h"
#include "options.h"
#include "rpp.h"
#include "external.h"
#include "cracker.h"
#include "john.h"
#include "mask.h"

void do_mask_crack(struct db_main *db, char *mask)
{
	struct rpp_context ctx;
	char *word;

	if (options.node_count) {
		if (john_main_process)
			fprintf(stderr, "--mask is not yet compatible with --node and --fork\n");
		error();
	}

	log_event("Proceeding with mask mode");

	rpp_init_mask(&ctx, mask);

	status_init(NULL, 0);

#if 0
	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);
#else
	crk_init(db, NULL, NULL);
#endif

	while ((word = rpp_next(&ctx))) {
		if (ext_filter(word))
			if (crk_process_key(word))
				break;
	}

	crk_done();

#if 0
	rec_done(event_abort);
#endif
}

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2003,2004 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>

#include "params.h"
#include "os.h"
#include "signals.h"
#include "loader.h"
#include "status.h"
#include "config.h"
#include "options.h"
#include "single.h"
#include "wordlist.h"
#include "inc.h"

static void do_single_pass(struct db_main *db)
{
	options.flags |= FLG_SINGLE_CHK; /* Make tests elsewhere easier/safer */
	do_single_crack(db);
	db->options->flags &= ~DB_WORDS; /* Might speed up pot sync */
	options.flags &= ~FLG_SINGLE_CHK;
}

static void do_wordlist_pass(struct db_main *db)
{
	const char *name;

	if (!(name = cfg_get_param(SECTION_OPTIONS, NULL, "Wordlist")))
	if (!(name = cfg_get_param(SECTION_OPTIONS, NULL, "Wordfile")))
		name = WORDLIST_NAME;

	do_wordlist_crack(db, name, 1);
}

static void do_incremental_pass(struct db_main *db)
{
	do_incremental_crack(db, NULL);
}

void do_batch_crack(struct db_main *db)
{
	switch (status.pass) {
	case 0:
	case 1:
		status.pass = 1;
		do_single_pass(db);
		if (event_abort || !db->salts) break;
		event_reload = 1;
		if (status.cands)
			status_print(0);

	case 2:
		status.pass = 2;
		do_wordlist_pass(db);
		if (event_abort || !db->salts) break;
		event_reload = 1;
		status_print(0);

	case 3:
		status.pass = 3;
		do_incremental_pass(db);
	}
}

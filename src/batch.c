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
#include "signals.h"
#include "loader.h"
#include "status.h"
#include "config.h"
#include "single.h"
#include "wordlist.h"
#include "inc.h"

static void do_single_pass(struct db_main *db)
{
	do_single_crack(db);
}

static void do_wordlist_pass(struct db_main *db)
{
	char *name;

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

	case 2:
		status.pass = 2;
		do_wordlist_pass(db);
		if (event_abort || !db->salts) break;

	case 3:
		status.pass = 3;
		do_incremental_pass(db);
	}
}

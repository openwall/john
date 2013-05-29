/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2011,2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Status information management routines.
 */

#ifndef _JOHN_STATUS_H
#define _JOHN_STATUS_H

#include <time.h>

#include "math.h"

/*
 * Current status.
 */
struct status_main {
	clock_t start_time;
	unsigned int guess_count;
	int64 combs, crypts, cands;
	unsigned int combs_ehi;
	int compat;
	int pass;
	int progress;
};

extern struct status_main status;

extern int (*status_get_progress)(void);

/*
 * Elapsed time of previous sessions and excess ticks (if any), in seconds.
 */
extern unsigned int status_restored_time;

/*
 * If start is non-zero, sets start_time to current time and the rest of
 * fields to zero. Always initializes the get_progress() handler (can be
 * NULL).
 */
extern void status_init(int (*get_progress)(void), int start);

/*
 * Checks the number of ticks elapsed since start_time and moves some excess
 * ticks onto status_restored_time (by increasing both it and start_time)
 * such that the difference between the current system time in ticks (which
 * may overflow) and start_time always correctly represents the number of
 * ticks elapsed since status_restored_time.
 */
extern void status_ticks_overflow_safety(void);

/*
 * Updates the combinations and crypts counters by adding the supplied numbers
 * to them.
 * Calls status_ticks_overflow_safety() once in a while.
 */
extern void status_update_crypts(int64 *combs, unsigned int crypts);

/*
 * Updates the candidates counter by adding the supplied number to it.
 * Calls status_ticks_overflow_safety() once in a while.
 */
extern void status_update_cands(unsigned int cands);

/*
 * Returns the elapsed time in seconds.
 */
extern unsigned int status_get_time(void);

/*
 * Prints current status to stdout.
 */
extern void status_print(void);

#endif

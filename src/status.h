/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006 by Solar Designer
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
	int64 crypts;
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
 * Updates the crypts count.
 */
extern void status_update_crypts(unsigned int count);

/*
 * Returns the elapsed time in seconds.
 */
extern unsigned int status_get_time(void);

/*
 * Prints current status to stdout.
 */
extern void status_print(void);

#endif

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
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
 * Elapsed time of previous sessions, in seconds.
 */
extern unsigned int status_restored_time;

/*
 * If start is non-zero, sets start_time to current time and the rest of
 * fields to zero. Always initializes the get_progress() handler (can be
 * NULL).
 */
extern void status_init(int (*get_progress)(void), int start);

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

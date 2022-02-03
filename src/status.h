/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2011,2013,2017 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum.
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

#include <stdint.h>
#include <time.h>

#if CPU_REQ && defined(__GNUC__) && defined(__i386__)
/* ETA reporting would be wrong when cracking some hash types at least on a
 * Pentium 3 without this... */
#define emms() \
	__asm__ __volatile__("emms");
#else
#define emms()
#endif

/*
 * Current status.
 */
struct status_main {
	clock_t start_time;
	unsigned int guess_count;
	uint64_t combs, crypts, cands;
	unsigned int combs_ehi;
	int compat;
	int pass;
	int progress;
	int resume_salt;
	uint32_t *resume_salt_md5;
	unsigned int salt_count, password_count;
	unsigned long long suppressor_start, suppressor_end;
	unsigned int suppressor_start_time, suppressor_end_time;
	unsigned long long suppressor_hit, suppressor_miss;
};

extern struct status_main status;

extern double (*status_get_progress)(void);

/*
 * Elapsed time of previous sessions and excess ticks (if any), in seconds.
 */
extern unsigned int status_restored_time;

/*
 * If start is non-zero, sets start_time to current time and the rest of
 * fields to zero. Always initializes the get_progress() handler (can be
 * NULL).
 */
extern void status_init(double (*get_progress)(void), int start);

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
extern void status_update_crypts(uint64_t combs, unsigned int crypts);

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
 * Returns "now" in ticks.
 */
extern clock_t status_get_raw_time(void);

/*
 * Prints current status to stdout.  The requested detail level can be 1 or 2,
 * or the special value of 0 to use and reset event_status.
 */
extern void status_print(int level);

/*
 * Keep tracks of what "Remaining" figures we've already printed.
 */
extern void status_update_counts(void);
#endif

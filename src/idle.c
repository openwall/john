/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2009,2011 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#define _XOPEN_SOURCE /* for nice(2) */
#include <unistd.h>
#include <stdio.h>

#ifdef _POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#include <time.h>
#include <sys/times.h>

static int use_yield = 0;
#endif

#ifdef __CYGWIN32__
extern int nice(int);
#endif

#ifdef __BEOS__
#include <OS.h>
#endif

#ifdef _OPENMP
#include <omp.h>
#endif

#include "params.h"
#include "config.h"
#include "options.h"
#include "signals.h"
#include "bench.h"
#include "formats.h"

int idle_requested(struct fmt_main *format)
{
	if (!cfg_get_bool(SECTION_OPTIONS, NULL, "Idle", 1))
		return 0;

#ifdef _OPENMP
	if ((format->params.flags & FMT_OMP) && omp_get_max_threads() > 1)
		return 0;
#endif

	return 1;
}

void idle_init(struct fmt_main *format)
{
#if defined(_POSIX_PRIORITY_SCHEDULING) && defined(SCHED_IDLE)
	struct sched_param param = {0};
#endif

	if (!idle_requested(format) || (options.flags & FLG_STDOUT))
		return;

	clk_tck_init();

#ifndef __BEOS__
/*
 * Normally, the range is -20 to 19, but some systems can do 20 as well (at
 * least some versions of Linux on Alpha), so we try 20.  We assume that we're
 * started with a non-negative nice value (so no need to increment it by more
 * than 20).
 */
	if (nice(20) == -1)
		perror("nice");
#else
	set_thread_priority(getpid(), 1);
#endif

#if defined(_POSIX_PRIORITY_SCHEDULING) && defined(SCHED_IDLE)
	use_yield = sched_setscheduler(getpid(), SCHED_IDLE, &param) != 0;
#elif defined(_POSIX_PRIORITY_SCHEDULING)
	use_yield = 1;
#endif
}

void idle_yield(void)
{
#ifdef _POSIX_PRIORITY_SCHEDULING
	static unsigned int calls_to_skip = 0;
	static unsigned int calls_per_tick = 0;
	static unsigned int calls_since_tick = 0;
	static unsigned int calls_since_adj = 0;
	static int calls_per_tick_known = 0;
	static clock_t last_adj = 0;
	clock_t last_check;
	clock_t current;
	int yield_calls;
	struct tms buf;

	if (!use_yield) return;

	if (++calls_since_tick < calls_to_skip) return;
	calls_since_adj += calls_since_tick;
	calls_since_tick = 0;

	current = times(&buf);
	if (!last_adj) last_adj = current;

	if (current - last_adj >= clk_tck) {
		calls_per_tick = calls_since_adj / (current - last_adj);
		calls_since_adj = 0;
		calls_per_tick_known = 2;
		last_adj = current;
	} else if (calls_per_tick_known < 2) {
		if (current > last_adj) {
			calls_per_tick = calls_since_adj / (current - last_adj);
			calls_per_tick_known = 1;
		} else if (!calls_per_tick_known)
			calls_per_tick++;
	}

	yield_calls = 0;
	do {
		if (event_pending) break;
		last_check = current;
		sched_yield();
		yield_calls++;
		current = times(&buf);
	} while (current - last_check > 1 && current - last_adj < clk_tck);

	if (yield_calls != 1)
		calls_to_skip = 0;
	calls_to_skip += calls_per_tick;

	{
		/* 1/16th of a second */
		unsigned int max_calls_to_skip = calls_per_tick * clk_tck >> 4;
		if (max_calls_to_skip < calls_per_tick)
			max_calls_to_skip = calls_per_tick;
		if (calls_to_skip > max_calls_to_skip)
			calls_to_skip = max_calls_to_skip;
	}
#endif
}

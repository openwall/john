/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006 by Solar Designer
 */

#include <unistd.h>

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

#include "params.h"
#include "config.h"
#include "options.h"
#include "signals.h"
#include "bench.h"

void idle_init(void)
{
#if defined(_POSIX_PRIORITY_SCHEDULING) && defined(SCHED_IDLE)
	struct sched_param param = {0};
#endif

	if (!cfg_get_bool(SECTION_OPTIONS, NULL, "Idle")) return;
	if (options.flags & FLG_STDOUT) return;

	clk_tck_init();

#ifndef __BEOS__
	nice(20);
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
	static int calls_per_tick = 0;
	static int calls_since_tick = 0;
	static int calls_since_adj = 0;
	static clock_t last_adj = 0;
	clock_t last_check;
	clock_t current;
	struct tms buf;

	if (!use_yield) return;

	if (++calls_since_tick < calls_per_tick) return;
	calls_since_adj += calls_since_tick;
	calls_since_tick = 0;

	current = times(&buf);
	if (!last_adj) last_adj = current;

	if (current - last_adj >= clk_tck) {
		calls_per_tick = calls_since_adj / (current - last_adj);
		calls_since_adj = 0;
		last_adj = current;
	}

	do {
		if (event_pending) break;
		last_check = current;
		sched_yield();
		current = times(&buf);
	} while (current - last_check > 1 && current - last_adj < clk_tck);
#endif
}

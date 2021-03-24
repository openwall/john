/*
 * This file is Copyright (c) 2021 by magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <stdint.h>

#include "timer.h"
#include "misc.h"

#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__)

#undef MEM_FREE
#include <windows.h>
#undef MEM_FREE
const char *john_nano_clock = "QueryPerformanceCounter()";

/*
 * QueryPerformanceCounter(LARGE_INTEGER*) gives "counts" (ticks)
 * QueryPerformanceFrequency(LARGE_INTEGER*) gives ticks/s
 */
uint64_t john_get_nano(void)
{
	static uint64_t ticks_per_sec;
	LARGE_INTEGER t;

	if (!ticks_per_sec) {
		QueryPerformanceFrequency(&t);
		ticks_per_sec = t.QuadPart;
	}

	QueryPerformanceCounter(&t);

	return t.QuadPart * 1000000000ULL / ticks_per_sec;
}

#elif __MACH__

#include <mach/mach_time.h>
const char *john_nano_clock = "mach_absolute_time()";

/*
 * mach_absolute_time() gives ticks
 * mach_timebase_info() gives numer/denom to convert ticks to nanoseconds
 */
uint64_t john_get_nano(void)
{
	static mach_timebase_info_data_t timebase;

	if (!timebase.denom)
		if (mach_timebase_info(&timebase) != KERN_SUCCESS)
			pexit("mach_timebase_info()");

	return mach_absolute_time() * timebase.numer / timebase.denom;
}

#else /* Linux, POSIX */

#include <unistd.h>

#if _POSIX_TIMERS && defined(_POSIX_MONOTONIC_CLOCK)

#include <time.h>
const char *john_nano_clock = "clock_gettime()";

/*
 * clock_gettime gives s + ns
 */
uint64_t john_get_nano(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t) == -1)
		pexit("%s", john_nano_clock);

	return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

#else /* Fallback to microsecond non-monotonic clock that should always be available */

#include <sys/time.h>
const char *john_nano_clock = "gettimeofday()";

/*
 * gettimeofday gives s + us
 */
uint64_t john_get_nano(void)
{
	struct timeval t;

	if (gettimeofday(&t, NULL) == -1)
		pexit("%s", john_nano_clock);

	return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_usec * 1000;
}

#endif /* _POSIX_TIMERS && defined(_POSIX_MONOTONIC_CLOCK) */
#endif /* defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__) */

uint64_t john_timer_stats(int *latency)
{
	int num = 0;
	uint64_t start, end;

	john_get_nano();	/* Warm up */

	start = john_get_nano();
	do {
		end = john_get_nano();
		num++;
	} while (end == start);

	if (latency)
		*latency = (num == 1);

	return end - start;
}

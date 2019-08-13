/*
 * This file is
 * Copyright (c) 2009 by Jim Fougeron jfoug AT cox dot net
 * Copyright (c) 2019 by magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Portable hi-res timer.  Was a nice C++ class. Downgraded to C for john.
 */

#ifndef _HAVE_TIMER_H
#define _HAVE_TIMER_H

#include <time.h>

/* Windows - use provided hi-res timer */
#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__)

#include <sys/timeb.h>      /* for ftime(), which is not used */
#undef MEM_FREE
#include <windows.h>
#undef MEM_FREE
typedef LARGE_INTEGER hr_timer;

#define HRZERO(X)             (X).HighPart = (X).LowPart = 0
#define HRSETCURRENT(X)       QueryPerformanceCounter(&(X))
#define HRGETTICKS(X)         ((uint64_t)(X).HighPart * 4294967296ULL + \
                               (uint64_t)(X).LowPart)
#define HRGETTICKS_PER_SEC(X) {	  \
		LARGE_INTEGER large; \
		if (QueryPerformanceFrequency (&large)) \
			(X) = (uint64_t)large.HighPart*4294967296ULL + (uint64_t)large.LowPart; \
		else \
			(X) = 0; \
	}

#elif __MACH__ /* OSX / macOS, monotonic nanosecond */

#include <mach/mach_time.h>

typedef struct timespec hr_timer;
#define HRZERO(X)             (X).tv_sec = (X).tv_nsec = 0
#define HRSETCURRENT(X)       do { int64_t tmp = mach_absolute_time() * sm_timebase; (X).tv_sec = tmp / 1000000000ULL; (X).tv_nsec = tmp - (X).tv_sec * 1000000000ULL; } while (0)
#define HRGETTICKS(X)         ((uint64_t)(X).tv_sec * 1000000000ULL + (uint64_t)(X).tv_nsec)
#define HRGETTICKS_PER_SEC(X) { mach_timebase_info_data_t tb; mach_timebase_info(&tb); sm_timebase = tb.numer; sm_timebase /= tb.denom; (X) = sm_timebase * 1000000000ULL; }

#else /* Linux, POSIX */

#include <unistd.h>

/* Do we seem to have a (hopefully) nanosecond monotonic clock? */
#if _POSIX_TIMERS && defined(_POSIX_MONOTONIC_CLOCK)

#ifdef CLOCK_MONOTONIC_RAW
#define BEST_MONOTONIC CLOCK_MONOTONIC_RAW
#else
#define BEST_MONOTONIC CLOCK_MONOTONIC
#endif

typedef struct timespec hr_timer;
#define HRZERO(X)             (X).tv_sec = (X).tv_nsec = 0
#define HRSETCURRENT(X)       clock_gettime(BEST_MONOTONIC, &(X))
#define HRGETTICKS(X)         ((uint64_t)(X).tv_sec * 1000000000ULL + (uint64_t)(X).tv_nsec)
#define HRGETTICKS_PER_SEC(X) { hr_timer r; clock_getres(BEST_MONOTONIC, &r); if (r.tv_sec < 0) clock_getres(CLOCK_MONOTONIC, &r); (X) = r.tv_sec + 1000000000ULL / r.tv_nsec; }

#else /* Fallback to microsecond non-monotonic clock that should be available */

#include <sys/time.h>

typedef struct timeval hr_timer;
#define HRZERO(X)             (X).tv_sec = (X).tv_usec = 0
#define HRSETCURRENT(X)       gettimeofday(&(X), NULL)
#define HRGETTICKS(X)         ((uint64_t)(X).tv_sec * 1000000 +	\
                               (uint64_t)(X).tv_usec)
#define HRGETTICKS_PER_SEC(X) (X) = 1000000

#endif

#endif /* Windows or Unix */

typedef struct sTimer_s {
	int m_fRunning;     // true if we are running
	clock_t m_cStartTime;
	clock_t m_cEndTime;
	hr_timer m_hrStartTime;
	hr_timer m_hrEndTime;
	uint64_t m_dAccumSeconds;
} sTimer;

extern void sTimer_Init(sTimer *t);      // Init
extern void sTimer_Start(sTimer *t, int bClear /*=true*/);  // Start the timer
extern void sTimer_Stop(sTimer *t);      // Stop the timer
extern void sTimer_ClearTime(sTimer *t); // Clears out the time to 0
extern uint64_t sTimer_GetSecs(sTimer *t); // If timer running returns elapsed;
                                           // if stopped returns timed interval;
                                           // if not started returns 0.

extern uint64_t sm_HRTicksPerSec;  // HR ticks per second (claimed)
extern uint64_t sm_hrPrecision;    // HR ticks per second (observed, guess)
extern uint64_t sm_cPrecision;     // clocks (ticks) per second (observed, guess)

#define sTimer_Start_noclear(t) \
    do { \
    if (sm_HRTicksPerSec) { HRSETCURRENT ((t)->m_hrStartTime); } \
    else { (t)->m_cStartTime = clock(); } \
    (t)->m_fRunning = 1; \
    } while (0)

#define sTimer_Pause(t) \
    do { \
    (t)->m_dAccumSeconds = sTimer_GetSecs(t); \
    (t)->m_fRunning=0; \
    } while (0)

#define sTimer_Resume(t) \
    do { \
    if (!(t)->m_fRunning) \
        sTimer_Start_noclear(t); \
    } while (0)

#endif /* _HAVE_TIMER_H */

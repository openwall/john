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

#include <stdio.h>
#include <stdint.h>

#include "timer.h"

#if __MACH__
static uint64_t sm_timebase;
#endif
static int sm_fGotHRTicksPerSec = 0;   // Set if we have got the above

uint64_t sm_HRTicksPerSec;  // HR ticks per second (claimed)
uint64_t sm_hrPrecision;    // HR ticks per second (observed, guess)
uint64_t sm_cPrecision;     // clocks (ticks) per second (observed, guess)

void sTimer_Init(sTimer *t)
{
	t->m_fRunning = 0;
	t->m_cStartTime = 0;
	t->m_cEndTime = 0;
	t->m_dAccumSeconds = 0;
	HRZERO(t->m_hrStartTime);
	HRZERO(t->m_hrEndTime);
	if (!sm_fGotHRTicksPerSec) {
		// What's the lowest digit set non-zero in a clock() call
		// That's a fair indication what the precision is likely to be.
		// Note - this isn't actually used
		int i;

		sm_fGotHRTicksPerSec = 1;
		sm_cPrecision = 0;
		for (i = 0; i < 10; ++i) {
			clock_t heuristicTimeTest = clock();

			if (heuristicTimeTest % 10) {
				sm_cPrecision = CLOCKS_PER_SEC;
				break;
			}
			else if (heuristicTimeTest % 100) {
				if (!sm_cPrecision || sm_cPrecision < CLOCKS_PER_SEC / 10)
					sm_cPrecision = CLOCKS_PER_SEC / 10;
			}
			else if (heuristicTimeTest % 1000) {
				if (!sm_cPrecision || sm_cPrecision < CLOCKS_PER_SEC / 100)
					sm_cPrecision = CLOCKS_PER_SEC / 100;
			}
			else if (heuristicTimeTest % 10000) {
				if (!sm_cPrecision || sm_cPrecision > CLOCKS_PER_SEC / 1000)
					sm_cPrecision = CLOCKS_PER_SEC / 1000;
			}
			else {
				if (!sm_cPrecision || sm_cPrecision > CLOCKS_PER_SEC / 10000)
					sm_cPrecision = CLOCKS_PER_SEC / 10000;
			}
		}

		// Find the claimed resolution of the high res timer
		// Then find the most likely real rate by waiting for it to change.
		// Note - I've frequently seen missed beats, and therefore a
		// 0.000001 reality gets reported as a 0.000002.
		// Note - this also isn't actually used, all that matters is
		// whether HRTicksPerSec has a non-zero value or not.
		HRGETTICKS_PER_SEC(sm_HRTicksPerSec);

		if (sm_HRTicksPerSec) {
			hr_timer start, end;

			HRSETCURRENT(start);
			do {
				HRSETCURRENT(end);
			} while (HRGETTICKS(end) == HRGETTICKS(start));

			sm_hrPrecision = sm_HRTicksPerSec / (HRGETTICKS(end) -
			                  HRGETTICKS(start));
		}
	}
}


void sTimer_Stop(sTimer *t)
{
	if (t->m_fRunning) {
		if (sm_HRTicksPerSec)
			HRSETCURRENT(t->m_hrEndTime);
		else
			t->m_cEndTime = clock();
	} else
		HRZERO(t->m_hrEndTime);

	t->m_fRunning = 0;
}

void sTimer_Start(sTimer *t, int bClear)
{
	if (bClear)
		sTimer_ClearTime(t);

	if (sm_HRTicksPerSec)
		HRSETCURRENT(t->m_hrStartTime);
	else
		t->m_cStartTime = clock();

	t->m_fRunning = 1;
}

void sTimer_ClearTime(sTimer *t)
{
	t->m_dAccumSeconds = 0;
	HRZERO(t->m_hrStartTime);
	HRZERO(t->m_hrEndTime);

	t->m_fRunning = 0;
}

uint64_t sTimer_GetSecs(sTimer *t)
{
	uint64_t retval;

	if (t->m_fRunning) {
		if (sm_HRTicksPerSec)
			HRSETCURRENT(t->m_hrEndTime);
		else
			t->m_cEndTime = clock();
	}
	if (!sm_HRTicksPerSec) {
		// This is process time
		uint64_t d = (t->m_cEndTime - t->m_cStartTime);

		if (d > 0)
			retval = d / CLOCKS_PER_SEC;
		else
			retval = 0;
	}
	else {
		// This is wall-clock time
		uint64_t d = (HRGETTICKS(t->m_hrEndTime) - HRGETTICKS(t->m_hrStartTime));

		if (d > 0)
			retval = d / sm_HRTicksPerSec;
		else
			retval = 0;
	}

	return retval + t->m_dAccumSeconds;
}

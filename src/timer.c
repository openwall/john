/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2009 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Portable hi-res timer.  Was a nice C++ class.
 * Downgraded to C for project john
 *
 */

#include "timer.h"
#include <stdio.h>

double sm_HRTicksPerSec=0.0;	// HR Ticks per second
int sm_fGotHRTicksPerSec=0;	// Set if we have got the above
double sm_hrPrecision=0.0;
double sm_cPrecision=0.0;

void sTimer_sTimer (sTimer *t)
{
	t->m_fRunning=0;
	t->m_cStartTime=0;
	t->m_cEndTime=0;
	t->m_dAccumSeconds=0;
	HRZERO(t->m_hrStartTime);
	HRZERO(t->m_hrEndTime);
	if (!sm_fGotHRTicksPerSec)
	{
        // What's the lowest digit set non-zero in a clock() call
		// That's a fair indication what the precision is likely to be.
		// Note - this isn't actually used
		clock_t heuristicTimeTest=clock();
		sm_fGotHRTicksPerSec = 1;
		if(heuristicTimeTest%10) sm_cPrecision = 1.0/CLOCKS_PER_SEC;
		else if(heuristicTimeTest%100) sm_cPrecision = 10.0/CLOCKS_PER_SEC;
		else if(heuristicTimeTest%1000) sm_cPrecision = 100.0/CLOCKS_PER_SEC;
		else if(heuristicTimeTest%10000) sm_cPrecision = 1000.0/CLOCKS_PER_SEC;
		else sm_cPrecision = 10000.0/CLOCKS_PER_SEC;

        // Find the claimed resolution of the high res timer
		// Then find the most likely real rate by waiting for it to change.
		// Note - I've frequently seen missed beats, and therefore a
		// 0.000001 reality gets reported as a 0.000002.
		// Note - this also isn't actually used, all that matters is
		// whether HRTicksPerSec has a non-zero value or not.
		HRGETTICKS_PER_SEC (sm_HRTicksPerSec);

		if (sm_HRTicksPerSec != 0.0)
		{
			hr_timer start, end;
			HRSETCURRENT (start);
			do
			{
				HRSETCURRENT (end);
			}	while (HRGETTICKS (end) == HRGETTICKS (start));

			sm_hrPrecision = (HRGETTICKS (end)-HRGETTICKS (start))/sm_HRTicksPerSec;
		}
	}
}


void sTimer_Stop (sTimer *t)
{
	if (t->m_fRunning)
	{
		if (sm_HRTicksPerSec != 0.0) { HRSETCURRENT (t->m_hrEndTime); }
		else { t->m_cEndTime = clock (); }
	}
	else
		HRZERO (t->m_hrEndTime);
	t->m_fRunning = 0;
}

void sTimer_Start (sTimer *t, int bClear)
{
	if (bClear)
		sTimer_ClearTime(t);
	if (sm_HRTicksPerSec != 0.0) { HRSETCURRENT (t->m_hrStartTime); }
	else { t->m_cStartTime = clock (); }
	t->m_fRunning = 1;
}

void sTimer_ClearTime(sTimer *t)
{
	t->m_dAccumSeconds = 0;
	HRZERO (t->m_hrStartTime);
	HRZERO (t->m_hrEndTime);
	t->m_fRunning=0;
}

double sTimer_GetSecs (sTimer *t)
{
	double retval;
	if (t->m_fRunning)
	{
		if (sm_HRTicksPerSec != 0.0) { HRSETCURRENT(t->m_hrEndTime); }
		else { t->m_cEndTime = clock (); }
	}
	if (sm_HRTicksPerSec == 0.0)
	{
		// This is process time
		double d = (t->m_cEndTime-t->m_cStartTime)*1.0;
		if (d > 0)
			retval = d/CLOCKS_PER_SEC;
		else
			retval = 0;
	}
	else
	{
		// This is wall-clock time
		double d = (HRGETTICKS (t->m_hrEndTime) - HRGETTICKS (t->m_hrStartTime));
		retval = 0;
		if (d > 0)
			retval = d/sm_HRTicksPerSec;
		else
			retval = 0;
	}
	return retval+t->m_dAccumSeconds;
}

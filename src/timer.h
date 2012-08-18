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

#ifndef GOT_TIMER_H
#define GOT_TIMER_H

#include <time.h>
#include <sys/timeb.h>

#if defined (_MSC_VER) || defined (__MINGW32__)
#undef MEM_FREE
#include <windows.h>
#undef MEM_FREE
typedef LARGE_INTEGER hr_timer;
#if defined (_MSC_VER)
#define inline _inline
#endif
#define HRZERO(X)				(X).HighPart = (X).LowPart = 0
#define HRSETCURRENT(X)			QueryPerformanceCounter (&(X));
#define HRGETTICKS(X)			((double)(X).HighPart*4294967296.0+(double)(X).LowPart)
#define HRGETTICKS_PER_SEC(X)	{LARGE_INTEGER large;														\
								   if (QueryPerformanceFrequency (&large))									\
								      (X) = (double)large.HighPart*4294967296.0 +	(double)large.LowPart;	\
								   else																		\
								      (X) = 0.0;															\
								}
#else
#include <sys/time.h>
typedef struct timeval hr_timer;
#define HRZERO(X)				(X).tv_sec = (X).tv_usec = 0
#define HRSETCURRENT(X)			{struct timezone tz; gettimeofday (&(X), &tz);}
#define HRGETTICKS(X)			((double)(X).tv_sec*1000000.0+(double)(X).tv_usec)
#define HRGETTICKS_PER_SEC(X)	(X) = 1000000.0
#endif

typedef struct _sTimer
{
	int m_fRunning;				// true if we are running
	clock_t m_cStartTime;
	clock_t m_cEndTime;
	hr_timer m_hrStartTime;
	hr_timer m_hrEndTime;
	double m_dAccumSeconds;
} sTimer;

void sTimer_sTimer(sTimer *t);
void sTimer_Start (sTimer *t, int bClear/*=true*/);	// Start the timer
//inline void sTimer_Start_noclear (sTimer *t);	// Start the timer
void sTimer_Stop (sTimer *t);			// Stop the timer
//inline void sTimer_Pause(sTimer *t);			// Pause the timer
//inline void sTimer_Resume(sTimer *t);			// Resume the timer.
void sTimer_ClearTime(sTimer *t);		// Clears out the time to 0
double sTimer_GetSecs (sTimer *t);		// If timer is running returns elapsed;
										// if stopped returns timed interval;
										// if not started returns 0.0.

extern double sm_HRTicksPerSec;	// HR Ticks per second
extern int sm_fGotHRTicksPerSec;	// Set if we have got the above
extern double sm_hrPrecision;
extern double sm_cPrecision;

//inline void sTimer_Start_noclear (sTimer *t)
//{
//	if (sm_HRTicksPerSec != 0.0) { HRSETCURRENT (t->m_hrStartTime); }
//	else { t->m_cStartTime = clock (); }
//	t->m_fRunning = 1;
//}
#define sTimer_Start_noclear(t) \
	do { \
	if (sm_HRTicksPerSec != 0.0) { HRSETCURRENT ((t)->m_hrStartTime); } \
	else { (t)->m_cStartTime = clock (); } \
	(t)->m_fRunning = 1; \
	} while (0)

//inline void sTimer_Pause (sTimer *t)
//{
//	t->m_dAccumSeconds = sTimer_GetSecs(t);
//	HRZERO (t->m_hrStartTime);
//	HRZERO (t->m_hrEndTime);
//	t->m_fRunning=0;
//}
#define sTimer_Pause(t) \
	do { \
	(t)->m_dAccumSeconds = sTimer_GetSecs(t); \
	(t)->m_fRunning=0; \
	} while (0)


//inline void sTimer_Resume (sTimer *t)
//{
	//HRZERO (t->m_hrEndTime);
//	if (!t->m_fRunning)
//		sTimer_Start_noclear(t);
//}

#define sTimer_Resume(t) \
	do { \
	if (!(t)->m_fRunning) \
		sTimer_Start_noclear(t); \
	} while (0)

#endif

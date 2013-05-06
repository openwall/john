/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer
 */

/*
 * OS-specific parameters.
 */

#ifndef _JOHN_OS_H
#define _JOHN_OS_H

#if defined(__CYGWIN32__) || defined(__BEOS__)
#define OS_TIMER			0
#else
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500 /* for ITIMER_REAL */
#endif
#include <sys/time.h>
#ifdef ITIMER_REAL
#define OS_TIMER			1
#else
#define OS_TIMER			0
#endif
#endif

#define OS_FLOCK			1

#endif

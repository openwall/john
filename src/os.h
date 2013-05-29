/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * OS-specific parameters.
 */

#ifndef _JOHN_OS_H
#define _JOHN_OS_H

#ifdef NEED_OS_TIMER

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
#warning ITIMER_REAL is not available - will emulate timers
#endif
#endif

#endif

#ifdef NEED_OS_FLOCK

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE /* for LOCK_EX */
#endif
#include <sys/file.h>
#ifdef LOCK_EX
#define OS_FLOCK			1
#else
#define OS_FLOCK			0
#warning LOCK_EX is not available - will skip locking
#endif

#endif

#ifdef NEED_OS_FORK

#if defined(__DJGPP__) || defined(__CYGWIN32__)
#define OS_FORK				0
#else
#define OS_FORK				1
#endif

#endif

#endif

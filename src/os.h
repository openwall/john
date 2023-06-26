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

#if AC_BUILT
/* include a stripped down os.h, AFTER it includes autoconf.h */
#include "os-autoconf.h"
#else
/* for non autoconf build (i.e. make -f Makefile.legacy) we use the original os.h code. */

#ifdef NEED_OS_TIMER

#if defined(__CYGWIN__) || defined(__BEOS__) || defined(__MINGW32__) || defined(_MSC_VER)
#define OS_TIMER			0
#else
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500 /* for ITIMER_REAL */
#define _XPG6
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

#ifdef NEED_OS_FORK

#if defined(__DJGPP__) || defined(__CYGWIN__) || defined(_MSC_VER) || defined(__MINGW32__)
#define OS_FORK				0
#else
#define OS_FORK				1
#endif

#endif

#if defined (_MSC_VER)
#define HAVE_UNISTD_H		0
#else
#define HAVE_UNISTD_H		1
#endif

#if defined (_MSC_VER)
#define HAVE_SYS_TIME_H		0
#else
#define HAVE_SYS_TIME_H		1
#endif

#if defined (_MSC_VER)
#define HAVE_SYS_FILE_H		0
#else
#define HAVE_SYS_FILE_H		1
#endif

#if defined (__MINGW32__) || defined (_MSC_VER)
#define HAVE_SYS_TIMES_H	0
#else
#define HAVE_SYS_TIMES_H	1
#endif

#if defined (__DJGPP__)
#define HAVE_DOS_H			1
#else
#define HAVE_DOS_H			0
#endif

#if defined (_MSC_VER) || defined(__CYGWIN32__) || defined(__MINGW32__)
#define HAVE_WINDOWS_H		1
#else
#define HAVE_WINDOWS_H		0
#endif

#if defined (_MSC_VER)
#define HAVE_STRINGS_H		0
#else
#define HAVE_STRINGS_H		1
#endif


#endif

#endif

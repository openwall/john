/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * This is the stripped down os.h file, we use in an autoconf build.
 * os.h will simply include this file, if building with autoconf.
 * We have removed the items from here, which are computed during
 * the call to ./configure.  NOTE, over time, this fill will be
 * reduced more and more, and likely will go away at some time.
 * when that happens, the os.h will simply be used for non autoconf
 * builds (i.e. make -sj4 -f Makefile.legacy )
 */

/*
 * OS-specific parameters.
 */

#ifndef _JOHN_OS_AUTOCONF_H
#define _JOHN_OS_AUTOCONF_H

#ifdef AC_BUILT

#include "autoconfig.h"
#include "jumbo.h"

#ifdef NEED_OS_TIMER

#if defined(__CYGWIN32__) || defined(__BEOS__) || defined(__MINGW32__) || defined(_MSC_VER) /* || (defined(AMDAPPSDK) && defined(HAVE_OPENCL)) */
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

#ifdef NEED_OS_FORK

#ifdef HAVE_WORKING_FORK
#define OS_FORK				1
#else
#define OS_FORK				0
#endif

#endif

/*
 * NOTE, most of these HAVE_HEADER stuff are done in autoconfig.h
 * But we have kept 'some' of this here, mostly due to MSVC not being
 * able to run autoconf or ./configure, so the header file 'may' not
 * be built properly for VC
 */
#if defined (_MSC_VER)
#undef HAVE_UNISTD_H
#define HAVE_UNISTD_H		0
#endif

#if defined (_MSC_VER)
#undef HAVE_SYS_TIME_H
#define HAVE_SYS_TIME_H		0
#endif

#if defined (_MSC_VER)
#undef HAVE_SYS_FILE_H
#define HAVE_SYS_FILE_H		0
#endif

#if defined (__MINGW32__) || defined (_MSC_VER)
#undef HAVE_SYS_TIMES_H
#define HAVE_SYS_TIMES_H	0
#endif

#if defined (__DJGPP__)
#undef HAVE_DOS_H
#define HAVE_DOS_H			1
#endif

#if defined (_MSC_VER)
#undef HAVE_STRINGS_H
#define HAVE_STRINGS_H		0
#endif

#if defined (_MSC_VER) || defined(__CYGWIN32__) || defined(__MINGW32__)
#define HAVE_WINDOWS_H		1
#else
#define HAVE_WINDOWS_H		0
#endif

#endif

#endif

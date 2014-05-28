/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Miscellaneous routines.
 */

#ifndef _JOHN_MISC_H
#define _JOHN_MISC_H

#include <stdio.h>

#if !AC_BUILT
# include <string.h>
# ifndef _MSC_VER
#  include <strings.h>
# endif
#else
# include "autoconfig.h"
# if STRING_WITH_STRINGS
#  include <string.h>
#  include <strings.h>
# elif HAVE_STRING_H
#  include <string.h>
# elif HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif

#ifdef _MSC_VER
#undef inline
#define inline static
#endif

/*
 * Exit on error. Logs the event, closes john.pot and the log file, and
 * terminates the process with non-zero exit status.
 */
extern void error(void);

/*
 * Similar to perror(), but supports formatted output, and calls error().
 */
extern void pexit(char *format, ...)
#ifdef __GNUC__
	__attribute__ ((format (printf, 1, 2)));
#else
	;
#endif

/*
 * Attempts to write all the supplied data. Returns the number of bytes
 * written, or -1 on error.
 */
extern int write_loop(int fd, const char *buffer, int count);

/*
 * Similar to fgets(), but doesn't leave the newline character in the buffer,
 * and skips to the end of long lines. Handles both Unix and DOS style text
 * files correctly.
 */
extern char *fgetl(char *s, int size, FILE *stream);

/*
 * Similar to strncpy(), but terminates with only one NUL if there's room
 * instead of padding to the supplied size like strncpy() does.
 */
extern char *strnfcpy(char *dst, const char *src, int size);

/*
 * Similar to the above, but always NUL terminates the string.
 */
extern char *strnzcpy(char *dst, const char *src, int size);

/*
 * Similar to the strnzcpy, but returns the length of the string.
 */
extern int strnzcpyn(char *dst, const char *src, int size);

/*
 * Similar to strncat(), but total buffer size is supplied, and always NUL
 * terminates the string.
 */
extern char *strnzcat(char *dst, const char *src, int size);

/*
 * Converts a string to lowercase.
 */
#ifndef _MSC_VER
extern char *strlwr(char *s);
extern char *strupr(char *s);
#else
#define bzero(a,b) memset(a,0,b)
#define strlwr _strlwr
#define strupr _strupr
#include "memdbg_defines.h"
#ifndef MEMDBG_ON
#define strdup _strdup
#endif
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#define alloca _alloca
#define unlink _unlink
#define fileno _fileno
#pragma warning (disable : 4018 297 )
#undef inline
#define inline _inline
#undef  snprintf
#define snprintf sprintf_s
#define atoll _atoi64
#endif

#ifndef __has_feature
# define __has_feature(x) 0
#endif

#if /* is ASAN enabled? */ \
    __has_feature(address_sanitizer) /* Clang */ || \
    defined(__SANITIZE_ADDRESS__)  /* GCC 4.8.x */
  #define ATTRIBUTE_NO_ADDRESS_SAFETY_ANALYSIS \
        __attribute__((no_address_safety_analysis)) \
        __attribute__((noinline))
#else
  #define ATTRIBUTE_NO_ADDRESS_SAFETY_ANALYSIS
#endif

#endif

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
#include "jumbo.h"

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
extern void real_error(char *file, int line)
#ifdef __GNUC__
	__attribute__ ((__noreturn__));
#else
	;
#endif

#define error(...) real_error(__FILE__, __LINE__)

/*
 * Similar to perror(), but supports formatted output, and calls error().
 */
extern void real_pexit(char *file, int line, char *format, ...)
#ifdef __GNUC__
	__attribute__ ((__noreturn__))
	__attribute__ ((format (printf, 3, 4)));
#else
	;
#endif
#define pexit(...) real_pexit(__FILE__, __LINE__, __VA_ARGS__)

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
 * Similar to atoi(), but properly handles unsigned int.  Do not use
 * atoi() for unsigned data if the data can EVER be over MAX_INT.
 */
extern unsigned atou(const char *src);

/*
 * Similar to strtok(), but properly handles adjacent delmiters as
 * empty strings.  strtok() in the CRTL merges adjacent delimiters
 * and sort of 'skips' them. This one also returns 'empty' tokens
 * for any leading or trailing delims. strtok() strips those off
 * also.
 */
char *strtokm(char *s1, const char *delimit);

#ifndef __has_feature
# define __has_feature(x) 0
#endif

#if /* is ASAN enabled? */ \
    __has_feature(address_sanitizer) /* Clang */ || \
    defined(__SANITIZE_ADDRESS__)  /* GCC 4.8.x */
  #define ATTRIBUTE_NO_ADDRESS_SAFETY_ANALYSIS \
        __attribute__((no_address_safety_analysis)) \
        __attribute__((noinline))
  #define WITH_ASAN
#else
  #define ATTRIBUTE_NO_ADDRESS_SAFETY_ANALYSIS
#endif

#endif

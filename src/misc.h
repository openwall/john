/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003 by Solar Designer
 *
 * ...with changes in the jumbo patch for MSC, by JimF.
 */

/*
 * Miscellaneous routines.
 */

#ifndef _JOHN_MISC_H
#define _JOHN_MISC_H

#include <stdio.h>

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
#define strdup _strdup
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#define alloca _alloca
#pragma warning (disable : 4018 297 )
#define inline _inline
#endif

#endif

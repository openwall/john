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
 #include <string.h>
 #ifndef _MSC_VER
  #include <strings.h>
 #endif
#else
 #include "autoconfig.h"
 #if STRING_WITH_STRINGS
  #include <string.h>
  #include <strings.h>
 #elif HAVE_STRING_H
  #include <string.h>
 #elif HAVE_STRINGS_H
  #include <strings.h>
 #endif
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
 * Exit on error with message.  Will call real_error to do
 * the final exiting, after printing error message.
 */
extern void real_error_msg(char *file, int line, char *format, ...)
#ifdef __GNUC__
	__attribute__ ((__noreturn__))
	__attribute__ ((format (printf, 3, 4)));
#else
	;
#endif

#define error_msg(...) real_error_msg(__FILE__, __LINE__,  __VA_ARGS__)

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
 * Similar to fgetl(), but handles super long lines (longer than
 * size, by allocating a buffer, and filling it. So, if the return
 * to fgetll is a valid pointer, but NOT pointed to the original
 * s buffer, then the caller MUST call MEM_FREE to that pointer
 * once it is done with it.
 */
#ifndef _JOHN_MISC_NO_LOG
extern char *fgetll(char *s, size_t size, FILE *stream);
#endif

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
 * Similar to the above, but also converts to lowercase in a single pass
 */
extern char *strnzcpylwr(char *dst, const char *src, int size);

/*
 * Similar to the strnzcpy, but returns the length of the string.
 */
extern int strnzcpyn(char *dst, const char *src, int size);

/*
 * Similar to the strnzcpylwr, but returns the length of the string.
 */
extern int strnzcpylwrn(char *dst, const char *src, int size);

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
 * Similar to strtok(), but properly handles adjacent delimiters as
 * empty strings.  strtok() in the CRTL merges adjacent delimiters
 * and sort of 'skips' them. This one also returns 'empty' tokens
 * for any leading or trailing delims. strtok() strips those off
 * also.
 */
char *strtokm(char *s1, const char *delimit);

#ifndef __has_feature
 #define __has_feature(x) 0
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

/*
 * itoa type functions. Thread and buffer safe. Handles base from 2 to 36
 * note if buffer empty (result_len < 1), then a constant "" is returned
 * otherwise all work is done in the result buffer (which should be
 * result_len bytes long). If the buffer is too small, the number returned
 * will be truncated, but the LSB of data will be returned.  Not exactly
 * the right result, BUT buffer safe.
 * A truncated example would be: jtr_itoa(-1234567,b,6,10) returns "-4567"
 * note, itoa and utoa exist on certain systems (even though not stdC funcs)
 * so they have been renamed.
 */
const char *jtr_itoa(int num, char *result, int result_len, int base);
const char *jtr_utoa(unsigned int num, char *result, int result_len, int base);
const char *jtr_lltoa(long long num, char *result, int result_len, int base);
const char *jtr_ulltoa(unsigned long long num, char *result, int result_len, int base);

#endif

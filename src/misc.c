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

#include <stdio.h>
#define NEED_OS_FORK
#include "os.h"
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#ifdef _MSC_VER
#include <io.h>
#pragma warning ( disable : 4996 )
#endif
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>

#include "memory.h"
#include "logger.h"
#include "params.h"
#include "misc.h"
#include "options.h"

#ifdef HAVE_MPI
#include "john-mpi.h"
#endif
#include "memdbg.h"

void real_error(char *file, int line)
{
#ifndef _JOHN_MISC_NO_LOG
	log_event("Terminating on error, %s:%d", file, line);
	log_done();
#endif

	exit(1);
}

void real_error_msg(char *file, int line,  char *format, ...)
{
	va_list args;

#if defined(HAVE_MPI) && !defined(_JOHN_MISC_NO_LOG)
	if (mpi_p > 1)
		fprintf(stderr, "%u@%s: ", mpi_id + 1, mpi_name);
	else
#elif OS_FORK && !defined(_JOHN_MISC_NO_LOG)
	if (options.fork)
		fprintf(stderr, "%u: ", options.node_min);
#endif
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	real_error(file, line);
}

void real_pexit(char *file, int line, char *format, ...)
{
	va_list args;

#if !defined(_JOHN_MISC_NO_LOG)
#if HAVE_MPI
	if (mpi_p > 1)
		fprintf(stderr, "%u@%s: ", mpi_id + 1, mpi_name);
#endif
#if HAVE_MPI && OS_FORK
	else
#endif
#if OS_FORK
	if (options.fork)
		fprintf(stderr, "%u: ", options.node_min);
#endif
#endif

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fprintf(stderr, ": %s\n", strerror(errno));

	real_error(file, line);
}

int write_loop(int fd, const char *buffer, int count)
{
	int offset, block;

	offset = 0;
	while (count > 0) {
		block = write(fd, &buffer[offset], count);

/* If any write(2) fails, we consider that the entire write_loop() has
 * failed to do its job, unless we were interrupted by a signal. */
		if (block < 0) {
			if (errno == EINTR) continue;
			return block;
		}

		offset += block;
		count -= block;
	}

/* Should be equal to the requested size, unless our kernel got crazy. */
	return offset;
}

char *fgetl(char *s, int size, FILE *stream)
{
	char *res, *pos;
	int c;

	if ((res = fgets(s, size, stream))) {
		if (!*res) return res;

		pos = res + strlen(res) - 1;
		if (*pos == '\n') {
			*pos = 0;
			if (pos > res)
			if (*--pos == '\r') *pos = 0;
		} else
		if ((c = getc(stream)) == '\n') {
			if (*pos == '\r') *pos = 0;
		} else
		while (c != EOF && c != '\n')
			c = getc(stream);
	}

	return res;
}

#ifndef _JOHN_MISC_NO_LOG
char *fgetll(char *s, size_t size, FILE *stream)
{
	size_t len;
	int c;
	char *cp;

	/* fgets' size arg is a signed int! */
	assert(size <= INT32_MAX);

	if (!fgets(s, size, stream))
		return NULL;

	len = strlen(s);

	if (!len)
		return s;

	if (s[len-1] == '\n') {
		s[--len] = 0;
		while (len && (s[len-1] == '\n' || s[len-1] == '\r'))
			s[--len] = 0;
		return s;
	}
	else if (s[len-1] == '\r') {
		s[--len] = 0;
		while (len && (s[len-1] == '\n' || s[len-1] == '\r'))
			s[--len] = 0;
		/* we may have gotten the first byte of \r\n */
		c = getc(stream);
		if (c == EOF)
			return s;
		if (c != '\n')
			ungetc(c, stream);
		return s;
	}
	else if ((len + 1) < size) { /* We read a null byte */
		do {
			c = getc(stream);
		} while (c != EOF && c != '\n');
		return s;
	}

	cp = strdup(s);

	while (1) {
		int increase = MIN((((len >> 12) + 1) << 12), 0x40000000);
		size_t chunk_len;
		void *new_cp;

		new_cp = realloc(cp, len + increase);

		while (!new_cp) {
			increase >>= 2;
			if (increase < 0x10000)
				pexit("realloc");
			new_cp = realloc(cp, len + increase);
		}

		cp = new_cp;

		/* We get an EOF if there is no trailing \n on the last line */
		if (!fgets(&cp[len], increase, stream))
			return cp;

		chunk_len = strlen(&cp[len]);
		len += chunk_len;

		if (cp[len-1] == '\n') {
			cp[--len] = 0;
			while (len && (cp[len-1] == '\n' || cp[len-1] == '\r'))
				cp[--len] = 0;
			return cp;
		}
		else if (cp[len-1] == '\r') {
			cp[--len] = 0;
			while (len && (cp[len-1] == '\n' || cp[len-1] == '\r'))
				cp[--len] = 0;
			/* we may have gotten the first byte of \r\n */
			c = getc(stream);
			if (c == EOF)
				return cp;
			if (c != '\n')
				ungetc(c, stream);
			return cp;
		}
		else if ((chunk_len + 1) < increase) { /* We read a null byte */
			do {
				c = getc(stream);
			} while (c != EOF && c != '\n');
			return s;
		}
	}
}
#endif

char *strnfcpy(char *dst, const char *src, int size)
{
	char *dptr = dst;

	while (size--)
		if (!(*dptr++ = *src++)) break;

	return dst;
}

char *strnzcpy(char *dst, const char *src, int size)
{
	char *dptr = dst;

	if (size)
		while (--size)
			if (!(*dptr++ = *src++)) return dst;
	*dptr = 0;

	return dst;
}

char *strnzcpylwr(char *dst, const char *src, int size)
{
	char *dptr = dst;

	if (size)
		while (--size) {
			if (*src >= 'A' && *src <= 'Z') {
				*dptr = *src | 0x20;
			} else {
				*dptr = *src;
				if (!*src) return dst;
			}
			dptr++;
			src++;
		}
	*dptr = 0;

	return dst;
}

int strnzcpyn(char *dst, const char *src, int size)
{
	char *dptr;
	if (!size) return 0;

	dptr = dst;

	while (--size)
		if (!(*dptr++ = *src++)) return (dptr-dst)-1;
	*dptr = 0;

	return (dptr-dst);
}

int strnzcpylwrn(char *dst, const char *src, int size)
{
	char *dptr;
	if (!size) return 0;

	dptr = dst;

	if (size)
		while (--size) {
			if (*src >= 'A' && *src <= 'Z') {
				*dptr = *src | 0x20;
			} else {
				*dptr = *src;
				if (!*src) return (dptr-dst);
			}
			dptr++;
			src++;
		}
	*dptr = 0;

	return (dptr-dst);

}

char *strnzcat(char *dst, const char *src, int size)
{
	char *dptr = dst;

	if (size) {
		while (size && *dptr) {
			size--; dptr++;
		}
		if (size)
			while (--size)
				if (!(*dptr++ = *src++)) break;
	}
	*dptr = 0;

	return dst;
}

/*
 * strtok code, BUT returns empty token "" for adjacent delimiters. It also
 * returns leading and trailing tokens for leading and trailing delimiters
 * (strtok strips them away and does not return them). Several other issues
 * in strtok also impact this code
 *  - static pointer, not thread safe
 *  - mangled input string (requires a copy)
 * These 'bugs' were left in, so that this function is a straight drop in for
 * strtok, with the caveat of returning empty tokens for the 3 conditions.
 * Other than not being able to properly remove multiple adjacent tokens in
 * data such as arbitrary white space removal of text files, this is really
 * is what strtok should have been written to do from the beginning (IMHO).
 * A strtokm_r() should be trivial to write if we need thread safety, or need
 * to have multiple strtokm calls working at the same time, by just passing
 * in the *last pointer.
 * JimF, March 2015.
 */
char *strtokm(char *s1, const char *delims)
{
	static char *last = NULL;
	char *endp;

	if (!s1)
		s1 = last;
	if (!s1 || *s1 == 0)
		return last = NULL;
	endp = strpbrk(s1, delims);
	if (endp) {
		*endp = '\0';
		last = endp + 1;
	} else
		last = NULL;
	return s1;
}

unsigned atou(const char *src) {
	unsigned val;
	sscanf(src, "%u", &val);
	return val;
}

/*
 * atoi replacement(s) but smarter/safer/better. atoi is super useful, BUT
 * not a standard C function.  I have added atoi
 */
MAYBE_INLINE const char *_lltoa(long long num, char *ret, int ret_sz, int base)
{
	char *p = ret, *p1 = ret;
	long long t;
	// first 35 bytes handle neg digits. byte 36 handles 0, and last 35 handle positive digits.
	const char bc[] = "zyxwvutsrqponmlkjihgfedcba987654321"
	                  "0"
	                  "123456789abcdefghijklmnopqrstuvwxyz";

	if (--ret_sz < 1)	// reduce ret_sz by 1 to handle the null
		return "";	// we can not touch ret, it is 0 bytes long.
	*ret = 0;
	// if we can not handle this base, bail.
	if (base < 2 || base > 36) return ret;
	// handle the possible '-' char also. (reduces ret_sz to fit that char)
	if (num < 0 && --ret_sz < 1)
		return ret;
	do {
		// build our string reversed.
		t = num;
		num /= base;
		*p++ = bc[35 + (t - num * base)];
		if (num && p-ret == ret_sz) {
			// truncated but 'safe' of buffer overflow.
			if (t < 0) *p++ = '-'; // Apply negative sign
			*p-- = 0;
			for (; p > p1; ++p1, --p) { // strrev
				*p1 ^= *p; *p ^= *p1; *p1 ^= *p;
			}
			return ret;
		}
	} while (num);

	if (t < 0) *p++ = '-'; // Apply negative sign
	*p-- = 0;
	for (; p > p1; ++p1, --p) { // strrev
		*p1 ^= *p; *p ^= *p1; *p1 ^= *p;
	}
	return ret;
}

// almost same, but for unsigned types. there were enough changes that I did not
// want to make a single 'common' function.  Would have added many more if's to
// and already semi-complex function.
MAYBE_INLINE const char *_ulltoa(unsigned long long num, char *ret, int ret_sz, int base)
{
	char *p = ret, *p1 = ret;
	unsigned long long t;
	const char bc[] = "0123456789abcdefghijklmnopqrstuvwxyz";

	if (--ret_sz < 1)
		return "";
	*ret = 0;
	if (base < 2 || base > 36) return ret;
	do {
		t = num;
		num /= base;
		*p++ = bc[35 + (t - num * base)];
		if (num && p-ret == ret_sz) {
			*p-- = 0;
			for (; p > p1; ++p1, --p) {
				*p1 ^= *p; *p ^= *p1; *p1 ^= *p;
			}
			return ret;
		}
	} while (num);

	*p-- = 0;
	for (; p > p1; ++p1, --p) {
		*p1 ^= *p; *p ^= *p1; *p1 ^= *p;
	}
	return ret;
}
/*
 * these are the functions 'external' that other code in JtR can use. These
 * just call the 'common' code in the 2 inline functions.
 */
const char *jtr_itoa(int val, char *result, int rlen, int base) {
	return _lltoa((long long)val, result, rlen, base);
}
const char *jtr_utoa(unsigned int val, char *result, int rlen, int base) {
	return _ulltoa((long long)val, result, rlen, base);
}
const char *jtr_lltoa(long long val, char *result, int rlen, int base) {
	return _lltoa((long long)val, result, rlen, base);
}
const char *jtr_ulltoa(unsigned long long val, char *result, int rlen, int base) {
	return _ulltoa((long long)val, result, rlen, base);
}

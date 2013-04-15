/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003 by Solar Designer
 *
 * ...with changes in the jumbo patch for MSC, by JimF.
 */

#include <stdio.h>
#ifndef _MSC_VER
#include <unistd.h>
#else
#include <io.h>
#pragma warning ( disable : 4996 )
#endif
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "logger.h"
#include "params.h"

#ifdef HAVE_MPI
#include "john-mpi.h"
#endif

void error(void)
{
#ifndef _JOHN_MISC_NO_LOG
	log_event("Terminating on error");
	log_done();
#if defined(HAVE_MPI) && defined(JOHN_MPI_ABORT)
	if (mpi_p > 1)
		MPI_Abort(MPI_COMM_WORLD,1);
#endif
#endif

	exit(1);
}

void pexit(char *format, ...)
{
	va_list args;

#ifndef _JOHN_MISC_NO_LOG
#ifdef HAVE_MPI
	if (mpi_p > 1)
		fprintf(stderr, "Node %u@%s: ", mpi_id, mpi_name);
#endif
#endif
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fprintf(stderr, ": %s\n", strerror(errno));

	error();
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

int strnzcpyn(char *dst, const char *src, int size)
{
	char *dptr;
	if (!size) return 0;

	dptr = dst;

	while (--size)
		if (!(*dptr++ = *src++)) return (dptr-dst)-1;
	*dptr = 0;

	return (dptr-dst)-1;
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

// NOTE there is an encoding-aware version in unicode.c: enc_strlwr(). That
// one should be used for usernames, plaintexts etc in formats.
#ifndef _MSC_VER
char *strlwr(char *s)
{
	unsigned char *ptr = (unsigned char *)s;

	while (*ptr)
	if (*ptr >= 'A' && *ptr <= 'Z')
		*ptr++ |= 0x20;
	else
		ptr++;

	return s;
}
char *strupr(char *s)
{
	unsigned char *ptr = (unsigned char *)s;

	while (*ptr)
	if (*ptr >= 'a' && *ptr <= 'z')
		*ptr++ ^= 0x20;
	else
		ptr++;

	return s;
}
#endif

// For used in jtr_basename_r function.  We need to handle separator chars differently
// in unix vs Win32(DOS).
#if defined _WIN32 || defined __WIN32__ || defined _MSC_VER || defined __DJGPP__ || defined __CYGWIN32__ || defined __MINGW32__
#define SEP_CHAR(c) ((c)=='/'||(c)=='\\')
#else
#define SEP_CHAR(c) ((c)=='/')
#endif


char *jtr_basename_r(const char *name, char *buf) {
	char *base, *p;
	int something=0;

	// if name was null, or the string was null, then return a '.' char.
	if (!name || name[0]==0) return ".";

	strcpy(buf, name);
	base = buf;

	// deal with 'possible' drive letter in Win32/DOS type systems.
#if defined _WIN32 || defined __WIN32__ || defined _MSC_VER || defined __DJGPP__ || defined __CYGWIN32__ || defined __MINGW32__
	if (strlen(base)>1 &&
	   ((base[0] >= 'A' && base[0] <= 'Z')||(base[0] >= 'a' && base[0] <= 'z')) &&
	   base[1] == ':')
		base += 2;
	if (base[0]==0) return ".";
#endif

	p = base;
	while (*p) {
		if (SEP_CHAR(*p)) {
			if (p[1] && !SEP_CHAR(p[1]))
				base = p+1;
		}
		else
			something = 1;
		++p;
	}
	if (!something) {
		base = &base[strlen(base)-1];
	} else if (strlen(base)) {
		p = &base[strlen(base)-1];
		while (SEP_CHAR(*p) && p >= base) {
			*p = 0;
			--p;
		}
		if (base[0]==0) return ".";
	}
	return (char*)base;
}

char *jtr_basename(const char *name) {
	static char buf[PATH_BUFFER_SIZE+1];
	return jtr_basename_r(name, buf);
}

char *strip_suffixes(const char *src, const char *suffixes[], int count)
{
	int i, suflen, retlen, done;
	static char ret[PATH_BUFFER_SIZE + 1];

	done = ret[0] = 0;
	if (src == NULL)
		return ret;

	strnzcpy(ret, src, sizeof(ret));
	if (suffixes == NULL)
		return ret;

	while (done == 0) {
		done = 1;
		for (i = 0; i < count; i++) {
			if (!suffixes[i] || !*suffixes[i])
				continue;
			retlen = strlen(ret);
			suflen = strlen(suffixes[i]);
			if (retlen >= suflen && !strcmp(&ret[retlen - suflen], suffixes[i])) {
				ret[retlen - suflen] = 0;
				done = 0;
			}
		}
	}
	return ret;
}

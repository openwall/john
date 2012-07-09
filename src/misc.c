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
			if (!(*dptr++ = *src++)) break;
	*dptr = 0;

	return dst;
}

int strnzcpyn(char *dst, const char *src, int size)
{
	char *dptr;
	if (!size) return 0;

	dptr = dst;

	while (--size)
		if (!(*dptr++ = *src++)) break;
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

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "logger.h"

void error(void)
{
#ifndef _JOHN_MISC_NO_LOG
	log_event("Terminating on error");
	log_done();
#endif

	exit(1);
}

void pexit(char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fprintf(stderr, ": %s\n", strerror(errno));

	error();
}

int write_loop(int fd, char *buffer, int count)
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

char *strnfcpy(char *dst, char *src, int size)
{
	char *dptr = dst, *sptr = src;
	int count = size;

	while (count--)
		if (!(*dptr++ = *sptr++)) break;

	return dst;
}

char *strnzcpy(char *dst, char *src, int size)
{
	char *dptr = dst, *sptr = src;
	int count = size;

	if (count)
		while (--count)
			if (!(*dptr++ = *sptr++)) break;
	*dptr = 0;

	return dst;
}

char *strnzcat(char *dst, char *src, int size)
{
	char *dptr = dst, *sptr = src;
	int count = size;

	if (count) {
		while (count && *dptr) {
			count--; dptr++;
		}
		if (count)
			while (--count)
				if (!(*dptr++ = *sptr++)) break;
	}
	*dptr = 0;

	return dst;
}

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

/*
 * This software is Copyright (c) 2025-2026 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#ifndef _JOHN_COLOR_H
#define _JOHN_COLOR_H

#include <stdio.h>
#include <unistd.h> /* isatty */

/*
 * We might need to turn this into a real function that prints the components
 * in a non-interleavable operation (for MPI in particular), but it's not all
 * that trivial.  We'll see how it turns out - worst case is that the color
 * start/end sequences gets misplaced, and the flush helps a bit.
 */
#define fprintf_color(color, handle, ...)	  \
	do { \
		int tty_ = isatty(fileno(handle)); \
		if (tty_) \
			fputs(color, handle); \
		fprintf(handle, __VA_ARGS__); \
		if (tty_) { \
			fputs(color_end, handle); \
			if (handle == stdout) \
				fflush(stdout); \
		} \
	} while (0)

#define printf_color(color, ...)            fprintf_color(color, stdout, __VA_ARGS__)
#define puts_color(color, string)           printf_color(color, string)
#define fputs_color(color, string, handle)  fprintf_color(color, handle, string)

/*
 * Like fprintf_color but only once per session.
 */
#define WARN_ONCE(...)	  \
	do { \
		static int warned; \
		if (!warned) { \
			fprintf_color(__VA_ARGS__); \
			warned = 1; \
		} \
	} while (0)

extern char *parse_esc(const char *string);
extern void color_init();

/* Color escape sequences as strings */
extern const char* const color_none;
extern char *color_error, *color_notice, *color_warning, *color_end;

#endif	/* _JOHN_COLOR_H */

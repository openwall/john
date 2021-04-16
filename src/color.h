/*
 * This software is Copyright (c) 2025 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#ifndef _JOHN_COLOR_H
#define _JOHN_COLOR_H

extern char *parse_esc(const char *string);
extern void color_init();

/* Color escape sequences as strings */
extern char *color_error, *color_notice, *color_warning, *color_end;

#define printf_color(color, ...)	fprintf_color(color, stdout, __VA_ARGS__);

#define puts_color(color, string)	  \
	do { \
		fputs_color(color, string, stdout); \
		putchar('\n'); \
	} while (0)

#define fprintf_color(color, handle, ...)	  \
	do { \
		if (isatty(fileno(handle))) \
			fputs( (color) , handle); \
		fprintf(handle, __VA_ARGS__); \
		if (isatty(fileno(handle))) \
			fputs(color_end, handle); \
	} while (0)

#define fputs_color(color, string, handle)	  \
	do { \
		if (isatty(fileno(handle))) \
			fputs( (color) , handle); \
		fputs(string, handle); \
		if (isatty(fileno(handle))) \
			fputs(color_end, handle); \
	} while (0)

#endif	/* _JOHN_COLOR_H */

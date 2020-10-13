/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2020
 *
 * Copyright (c) 2020 Claudio André <claudioandre.br at gmail.com>
 *
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef __MINGW32__
#include <sys/ioctl.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "config.h"
#include "john.h"
#include "logger.h"
#include "options.h"
#include "util.h"

static int is_blank(char symbol)
{
	if (symbol == ' ' || symbol == '\t' || symbol == '\n' || symbol == '\r')
		return 1;

	return 0;
}

static int is_separator(char symbol)
{
	if (strchr(")]},.", symbol) || is_blank(symbol) || symbol == '\0')
		return 1;

	return 0;
}

static inline int wordlen(const char * str)
{
	int len = 0;

	while (!is_separator(str[len]))
		len++;

	return len;
}

static int wrap(char * text, char * line, const int width, int first_line,
    int identation)
{
	int line_len = 0, pos = 0, limit;

	/* ltrim text. */
	while (!first_line && text[0] != '\0' && is_blank(text[0])) {
		text++; pos++;
	}

	/* Protection against invalid data. */
	if (identation > width || first_line)
		identation = 0;
	limit = width - identation;

	while (text[line_len] != '\0') {

		if (is_separator(text[line_len]))
			if ((text[line_len] == '\n') ||
			     line_len + wordlen(&text[line_len + 1]) >= limit) {
				/* If it is a blank, override it. */
				if (is_blank(text[line_len]))
					text[line_len] = '\0';

				/* The separator belongs to this line. */
				line_len++;
				break;
			}
		line_len++;

		/* Separator was not found. */
		if (line_len == limit)
			break;
	}

	if (identation)
		memset(line, ' ', identation);
	strncpy(line + identation, text, limit);
	line[line_len + identation] = '\0';

	return line_len + pos;
}

int get_windows_size(int *lines, int *cols)
{
#ifndef __MINGW32__
	struct winsize w;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
		const char *tmp_value;
		int limit = 0;

		*(lines) = w.ws_row;
		*(cols) = w.ws_col;

		if ((tmp_value = cfg_get_param(SECTION_OPTIONS, "", "MaxConsoleCols")))
			limit = atoi(tmp_value);

		/* Never use wider than n or john.conf option. */
		if (limit && *(cols) > limit)
			*(cols) = limit;
		if (*(cols) > 140)
			*(cols) = 140;
		if (*(cols) < 60)
			*(cols) = 60;
		return 0;
	}
#endif
	*(lines) = 20;
	*(cols) = 80;
	return -1;
}

void log_print(int destination, int verbosity, int main_only, int identation,
        char *format, ...)
{
	int lines, cols, pos, first_line = 1;
    char *line, *str, s[2048];

	get_windows_size(&lines, &cols);
	line = mem_alloc(cols + 1);

	if (options.verbosity >= verbosity &&
	   (!main_only || (main_only && john_main_process))) {
 		va_list arg;
		va_start(arg, format);
		vsnprintf(s, 2048, format, arg);
		va_end(arg);

		str = s;
		while ((pos = wrap(str, line, cols, first_line, identation))) {
			if (destination == OUT_STDOUT || destination == OUT_CONSOLE)
				fprintf(stdout, "%s\n", line);
			if (destination == OUT_STDERR)
				fprintf(stderr, "%s\n", line);

			first_line = 0;
			str += pos;
		}
		if (destination == OUT_LOG)
			log_event("%s", s);
	}
	MEM_FREE(line);
}

/*
                 ## The help itself is more like a text file ##
                 ## Ok, but help also word wrap, I have to handle it ##
                 ## How many columns, 1, 2 or 3? ##

Management Commands:
  builder     Manage builds

OpenCL options:
  device      The device number
  mask        The mask ...

Options:
      --config string      Location of config files (default "/home/claudio/.john")
  -v, --version            Print version information and quit

  ^
  |-- Two (maybe three) columns text. Should we care about this?

*/

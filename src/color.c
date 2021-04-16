/*
 * This software is Copyright (c) 2025 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#include "color.h"
#include "config.h"
#include "options.h"

char *color_error, *color_notice, *color_warning, *color_end;

/*
 * Translate ^ to Esc, in place.
 * Also turns a null pointer into a pointer to empty string.
 */
char *parse_esc(const char *string)
{
	char *out = str_alloc_copy(string);
	char *s = out;

	if (!s)
		return NULL;

	while (*s) {
		if (*s == '^')
			*s = 0x1b;
		s++;
	}

	return out;
}

void color_init()
{
	if (cfg_get_bool(SECTION_OPTIONS, NULL, "UseColors", 0)) {
		color_error = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL, "ColorError"));
		color_notice = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL, "ColorNotice"));
		color_warning = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL, "ColorWarning"));
		color_end = parse_esc(cfg_get_param(SECTION_OPTIONS, NULL, "ColorEnd"));
	} else
		color_error = color_notice = color_warning = color_end = "";
}

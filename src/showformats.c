/*
 * This software is Copyright (c) 2015,2019 Aleksey Cherepanov
 * Copyright (c) 2017 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file is based on the code of ldr_split_line() in loader.c.
 */

#include <stdio.h>
#include <string.h>

#include "loader.h"
#include "options.h"
#include "config.h"
#include "dynamic.h"

static char *escape_json(char *in)
{
	char *ret;
	size_t num = 0;
	uint8_t c;
	uint8_t *p = (uint8_t*)in;

	while ((c = *p++)) {
		if (c == '\\' || c == '"')
			num++;
		else if (c < ' ')
			num += 5;
	}
	if (!num)
		return in;

	num += (p - (uint8_t*)in);
	ret = mem_alloc_tiny(num, MEM_ALIGN_NONE);

	p = (uint8_t*)ret - 1;
	while ((*++p = *in++)) {
		if (*p == '\\')
			*++p = '\\';
		else if (*p == '"') {
			*p = '\\';
			*++p = '"';
		} else if (*p < ' ') {
			const char* const hex = "0123456789abcdef";
			uint8_t c = *p;

			*p = '\\';
			*++p = 'u';
			*++p = '0';
			*++p = '0';
			*++p = hex[ARCH_INDEX(c >> 4)];
			*++p = hex[ARCH_INDEX(c & 0xf)];
		}
	}
	return ret;
}

/* login may be NULL. */
/* origin is label (informal name of branch) for place in code that
 * skipped hash. */
void showformats_skipped(const char *origin, char **login, char **ciphertext,
	struct db_options *db_opts, int line_no)
{
	int fs = db_opts->field_sep_char;

	if (!db_opts->showformats_old) {
		/* NOTE: closing "]" for JSON is in john.c. */
		printf("%s{\"lineNo\":%d,",
		       line_no == 1 ? "[" : ",\n",
		       line_no);
		if (login && **login)
			printf("\"login\":\"%s\",",
			       escape_json(*login));
		if (**ciphertext)
			printf("\"ciphertext\":\"%s\",",
			       escape_json(*ciphertext));
		printf("\"rowFormats\":[],\"skipped\":\"%s\"}", origin);
	} else
		printf("%s%c%s%c%d%c\n",
		       login ? *login : "",
		       fs, *ciphertext,
		       /* "NIS" is 2, "lonely" is 3 */
		       fs, (origin[0] == 'N' ? 2 : 3),
		       fs);
}


void showformats_regular(char **login, char **ciphertext,
	char **gecos, char **home, char **uid, char *source,
	struct db_options *db_opts, int line_no,
	char **fields, char *gid, char *shell,
	int huge_line)
{
	struct fmt_main *alt;
	int fs = db_opts->field_sep_char;
	/* Flag: the format is not the first valid format. The
	 * first format should not print the first field
	 * separator. */
	int not_first_format = 0;
	/* \0 and \n are not possible in any field. */
	/* field_sep_char should not be possible in any field too.
	 * But it is possible with --field-separator-char=/ due to
	 * default value "/" for home field. Also ? may come from
	 * empty login. */
	/* Flag: no fields contain \n or field separator. */
	int bad_char = 0;
#ifndef DYNAMIC_DISABLED
	int bare_always_valid = 0;
	if ((options.dynamic_bare_hashes_always_valid == 'Y')
	    || (options.dynamic_bare_hashes_always_valid != 'N'
		&& cfg_get_bool(SECTION_OPTIONS, NULL, "DynamicAlwaysUseBareHashes", 1)))
		bare_always_valid = 1;
#endif
	/* We output 1 or 0, so 0 and 1 are bad field separators. */
	if (fs == '0' || fs == '1')
		bad_char = 1;
#define check_field_separator(str) bad_char |= strchr((str), fs) || strchr((str), '\n')
	/* To suppress warnings, particularly from
	 * generic crypt's valid() (c3_fmt.c). */
	ldr_in_pot = 1;
	/* The format:
	 * Once for each hash even if it can't be loaded (7 fields):
	 *   login,
	 *   ciphertext,
	 *   uid,
	 *   gid,
	 *   gecos,
	 *   home,
	 *   shell.
	 * For each valid format (may be nothing):
	 *   label,
	 *   is format disabled? (1/0),
	 *   is format dynamic? (1/0),
	 *   does format use the ciphertext field as is? (1/0),
	 *   canonical hash or hashes (if there are several parts).
	 * All fields above are separated by field_sep_char.
	 * Formats are separated by empty field.
	 * Additionally on the end:
	 *   separator,
	 *   line consistency mark (0/1/2/3):
	 *     0 - the line is consistent and can be parsed easily,
	 *     1 - field separator char occurs in fields, line can't
	 *         be parsed easily,
	 *     2 - the line was skipped as bad NIS stuff, only login
	 *         and ciphertext are shown,
	 *     3 - the line was skipped parsing descrypt with
	 *         invalid salt, only ciphertext is shown (together
	 *         with empty login); empty lines fall here,
	 *   separator.
	 * The additional field_sep_char at the end of line does not
	 * break numeration of fields but allows parser to get
	 * field_sep_char from the line.
	 * A parser have to check the last 3 chars.
	 * If the format does not use the ciphertext field as is,
	 * then a parser have to match input line with output line
	 * by number of line.
	 */
	if (!db_opts->showformats_old) {
		/* NOTE: closing "]" for JSON is in john.c. */
		printf("%s{\"lineNo\":%d,",
		       line_no == 1 ? "[" : ",\n",
		       line_no);
		if (strcmp(*login, "?"))
			printf("\"login\":\"%s\",",
			       escape_json(*login));
		if (**ciphertext)
			printf("\"ciphertext\":\"%s\",",
			       escape_json(*ciphertext));
		if (**uid)
			printf("\"uid\":\"%s\",",
			       escape_json(*uid));
		if (*gid)
			printf("\"gid\":\"%s\",",
			       escape_json(gid));
		if (**gecos && strcmp(*gecos, "/"))
			printf("\"gecos\":\"%s\",",
			       escape_json(*gecos));
		if (**home && strcmp(*home, "/"))
			printf("\"home\":\"%s\",",
			       escape_json(*home));
		if (*shell && strcmp(shell, "/"))
			printf("\"shell\":\"%s\",",
			       escape_json(shell));
		printf("\"rowFormats\":[");
	} else
		printf("%s%c%s%c%s%c%s%c%s%c%s%c%s",
		       *login,
		       fs, *ciphertext,
		       fs, *uid,
		       fs, gid,
		       fs, *gecos,
		       fs, *home,
		       fs, shell);

	check_field_separator(*login);
	check_field_separator(*ciphertext);
	check_field_separator(*uid);
	check_field_separator(gid);
	check_field_separator(*gecos);
	check_field_separator(*home);
	check_field_separator(shell);
	/* Fields above may be empty. */
	/* Empty fields are separators after this point. */
	alt = fmt_list;
	do {
		char *prepared;
		int disabled = 0;
		int prepared_eq_ciphertext;
		int valid;
		int part;
		int is_dynamic = ((alt->params.flags & FMT_DYNAMIC) == FMT_DYNAMIC);

		if (huge_line && !(alt->params.flags & FMT_HUGE_INPUT))
			continue;
/* We enforce DynamicAlwaysUseBareHashes for each format. By default
 * dynamics do that only if a bare hash occurs on the first line. */
#ifndef DYNAMIC_DISABLED
		if (bare_always_valid)
			dynamic_allow_rawhash_fixup = 1;
#endif
		prepared = alt->methods.prepare(fields, alt);
		if (!prepared)
			continue;
		prepared_eq_ciphertext = (*ciphertext == prepared || !strcmp(*ciphertext, prepared));
		valid = alt->methods.valid(prepared, alt);
		if (!valid)
			continue;
		ldr_set_encoding(alt);
		/* Empty field between valid formats */
		if (not_first_format) {
			if (!db_opts->showformats_old)
				printf(",{");
			else
				printf("%c", fs);
		} else if (!db_opts->showformats_old)
			printf("{");
		not_first_format = 1;
		if (!db_opts->showformats_old) {
			printf("\"label\":\"%s\",",
			       alt->params.label);
			if (disabled)
				printf("\"disabled\":true,");
			if (is_dynamic)
				printf("\"dynamic\":true,");
			if (huge_line)
				printf("\"truncated\":true,");
			if (prepared_eq_ciphertext)
				printf("\"prepareEqCiphertext\":true,");
			printf("\"canonHash\":[");
		} else
			printf("%c%s%c%d%c%d%c%d",
			       fs, alt->params.label,
			       fs, disabled,
			       fs, is_dynamic,
			       fs, prepared_eq_ciphertext);
		check_field_separator(alt->params.label);
		/* Canonical hash or hashes (like halves of LM) */
		for (part = 0; part < valid; part++) {
			char *split = alt->methods.split(prepared,
							 part, alt);

			if (!db_opts->showformats_old)
				printf("%s\"%s\"",
				       part ? "," : "",
				       escape_json(split));
			else
				printf("%c%s", fs, split);
			check_field_separator(split);
		}
		if (!db_opts->showformats_old) {
			printf("]");
			if (huge_line) {
				printf(",\"truncHash\":[");
				for (part = 0; part < valid; part++) {
					char *split = alt->methods.split(prepared, part, alt);
					char tr[LINE_BUFFER_SIZE + 1];

					ldr_pot_source(split, tr);
					printf("%s\"%s\"",
					       part ? "," : "",
					       escape_json(tr));
				}
				printf("]");
			}
			printf("}");
		}
	} while ((alt = alt->next));
	if (!db_opts->showformats_old) {
		/* bad_char is not meaningful for JSON. */
		printf("]}");
	} else
		printf("%c%d%c\n", fs, bad_char, fs);
#undef check_field_separator
}

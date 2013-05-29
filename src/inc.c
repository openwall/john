/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2006,2010-2013 by Solar Designer
 */

#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "signals.h"
#include "formats.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "config.h"
#include "charset.h"
#include "external.h"
#include "cracker.h"
#include "john.h"

extern struct fmt_main fmt_LM;

typedef char (*char2_table)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1];
typedef char (*chars_table)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1][CHARSET_SIZE + 1];

static unsigned int rec_entry, rec_length;
static unsigned char rec_numbers[CHARSET_LENGTH];

static unsigned int entry, length;
static unsigned char numbers[CHARSET_LENGTH];
static int counts[CHARSET_LENGTH][CHARSET_LENGTH];

static unsigned int real_count, real_minc, real_min, real_max, real_size;
static unsigned char real_chars[CHARSET_SIZE];

static void save_state(FILE *file)
{
	unsigned int pos;

	fprintf(file, "%u\n2\n%u\n", rec_entry, rec_length + 1);
	for (pos = 0; pos <= rec_length; pos++)
		fprintf(file, "%u\n", (unsigned int)rec_numbers[pos]);
}

static int restore_state(FILE *file)
{
	unsigned int compat, pos;

	if (rec_version < 2)
		return 1;

	if (fscanf(file, "%u\n%u\n%u\n", &rec_entry, &compat, &rec_length) != 3)
		return 1;
	rec_length--; /* zero-based */
	if (compat != 2 || rec_length >= CHARSET_LENGTH)
		return 1;
	for (pos = 0; pos <= rec_length; pos++) {
		unsigned int number;
		if (fscanf(file, "%u\n", &number) != 1)
			return 1;
		if (number >= CHARSET_SIZE)
			return 1;
		rec_numbers[pos] = number;
	}

	return 0;
}

static void fix_state(void)
{
	rec_entry = entry;
	rec_length = length;
	memcpy(rec_numbers, numbers, length);
}

static void inc_format_error(char *charset)
{
	log_event("! Incorrect charset file format: %.100s", charset);
	if (john_main_process)
		fprintf(stderr, "Incorrect charset file format: %s\n", charset);
	error();
}

static int is_mixedcase(char *chars)
{
	char present[0x100];
	char *ptr, c;

	memset(present, 0, sizeof(present));
	ptr = chars;
	while ((c = *ptr++))
		present[ARCH_INDEX(c)] = 1;

	ptr = chars;
	while ((c = *ptr++)) {
		/* assume ASCII */
		if (c >= 'A' && c <= 'Z' && present[ARCH_INDEX(c) | 0x20])
			return 1;
	}

	return 0;
}

static void inc_new_length(unsigned int length,
	struct charset_header *header, FILE *file, char *charset,
	char *char1, char2_table char2, chars_table *chars)
{
	long offset;
	int value, pos, i, j;
	char *buffer;
	int count;

	log_event("- Switching to length %d", length + 1);

	char1[0] = 0;
	if (length) {
		for (i = real_min; i <= real_max; i++)
			(*char2)[i][0] = 0;
		(*char2)[CHARSET_SIZE][0] = 0;
	}
	for (pos = 0; pos <= (int)length - 2; pos++) {
		for (i = real_min; i <= real_max; i++)
		for (j = real_min; j <= real_max; j++)
			(*chars[pos])[i][j][0] = 0;
		for (j = real_min; j <= real_max; j++)
			(*chars[pos])[CHARSET_SIZE][j][0] = 0;
		(*chars[pos])[CHARSET_SIZE][CHARSET_SIZE][0] = 0;
	}

	offset =
		(long)header->offsets[length][0] |
		((long)header->offsets[length][1] << 8) |
		((long)header->offsets[length][2] << 16) |
		((long)header->offsets[length][3] << 24);
	if (fseek(file, offset, SEEK_SET))
		pexit("fseek");

	i = j = pos = -1;
	if ((value = getc(file)) != EOF)
	do {
		if (value != CHARSET_ESC) {
			switch (pos) {
			case -1:
				inc_format_error(charset);

			case 0:
				buffer = char1;
				break;

			case 1:
				if (j < 0)
					inc_format_error(charset);
				buffer = (*char2)[j];
				break;

			default:
				if (i < 0 || j < 0)
					inc_format_error(charset);
				buffer = (*chars[pos - 2])[i][j];
			}

			buffer[count = 0] = value;
			while ((value = getc(file)) != EOF) {
				buffer[++count] = value;
				if (value == CHARSET_ESC)
					break;
				if (count >= CHARSET_SIZE)
					inc_format_error(charset);
			}
			buffer[count] = 0;

			continue;
		}

		if ((value = getc(file)) == EOF)
			break;
		else
		if (value == CHARSET_NEW) {
			if ((value = getc(file)) != (int)length)
				break;
			if ((value = getc(file)) == EOF)
				break;
			if (value < 0 || value > (int)length)
				inc_format_error(charset);
			pos = value;
		} else
		if (value == CHARSET_LINE) {
			if (pos < 0)
				inc_format_error(charset);
			if ((value = getc(file)) == EOF)
				break;
			i = value;
			if (i < 0 || i > CHARSET_SIZE)
				inc_format_error(charset);
			if ((value = getc(file)) == EOF)
				break;
			j = value;
			if (j < 0 || j > CHARSET_SIZE)
				inc_format_error(charset);
		} else
			inc_format_error(charset);

		value = getc(file);
	} while (value != EOF);

	if (value == EOF) {
		if (ferror(file))
			pexit("getc");
		else
			inc_format_error(charset);
	}
}

static int expand(char *dst, char *src, int size)
{
	char present[CHARSET_SIZE];
	char *dptr = dst, *sptr = src;
	int count = size;
	unsigned int i;

	memset(present, 0, real_size);
	while (*dptr) {
		if (--count <= 1)
			return 0;
		i = ARCH_INDEX(*dptr++) - real_minc;
		if (i >= real_size)
			return -1;
		present[i] = 1;
	}

	while (*sptr) {
		i = ARCH_INDEX(*sptr) - real_minc;
		if (i >= real_size)
			return -1;
		if (!present[i]) {
			*dptr++ = *sptr++;
			if (--count <= 1)
				break;
		} else
			sptr++;
	}
	*dptr = 0;

	return 0;
}

static void inc_new_count(unsigned int length, int count, char *charset,
	char *allchars, char *char1, char2_table char2, chars_table *chars)
{
	int pos, ci;
	int size;
	int error;

	log_event("- Expanding tables for length %d to character count %d",
	    length + 1, count + 1);

	size = count + 2;

	error = expand(char1, allchars, size);
	if (length)
		error |= expand((*char2)[CHARSET_SIZE], allchars, size);
	for (pos = 0; pos <= (int)length - 2; pos++)
		error |= expand((*chars[pos])[CHARSET_SIZE][CHARSET_SIZE],
		    allchars, size);

	for (ci = 0; ci < real_count; ci++) {
		int i = real_chars[ci];
		int cj;

		if (length)
			error |=
			    expand((*char2)[i], (*char2)[CHARSET_SIZE], size);

		for (cj = 0; cj < real_count; cj++) {
			int j = real_chars[cj];
			for (pos = 0; pos <= (int)length - 2; pos++) {
				error |= expand((*chars[pos])[i][j],
				    (*chars[pos])[CHARSET_SIZE][j], size);
				error |= expand((*chars[pos])[i][j],
				    (*chars[pos])[CHARSET_SIZE][CHARSET_SIZE],
				    size);
			}
		}
	}

	if (error)
		inc_format_error(charset);
}

static int inc_key_loop(int length, int fixed, int count,
	char *char1, char2_table char2, chars_table *chars)
{
	char key_i[PLAINTEXT_BUFFER_SIZE];
	char key_e[PLAINTEXT_BUFFER_SIZE];
	char *key;
	char *chars_cache;
	int *counts_length;
	int counts_cache;
	int numbers_cache;
	int pos;

	key_i[length + 1] = 0;
	numbers[fixed] = count;

	chars_cache = NULL;

	counts_length = counts[length];
	counts_cache = counts_length[length];

	pos = 0;
update_ending:
	if (pos < 2) {
		if (pos == 0)
			key_i[0] = char1[numbers[0]];
		if (length)
			key_i[1] = (*char2)[ARCH_INDEX(key_i[0]) - CHARSET_MIN]
			    [numbers[1]];
		pos = 2;
	}
	while (pos < length) {
		key_i[pos] = (*chars[pos - 2])
		    [ARCH_INDEX(key_i[pos - 2]) - CHARSET_MIN]
		    [ARCH_INDEX(key_i[pos - 1]) - CHARSET_MIN]
		    [numbers[pos]];
		pos++;
	}
	numbers_cache = numbers[length];
	if (pos == length) {
		chars_cache = (*chars[pos - 2])
		    [ARCH_INDEX(key_i[pos - 2]) - CHARSET_MIN]
		    [ARCH_INDEX(key_i[pos - 1]) - CHARSET_MIN];
update_last:
		key_i[length] = chars_cache[numbers_cache];
	}

	key = key_i;
	if (!f_filter || ext_filter_body(key_i, key = key_e))
		if (crk_process_key(key))
			return 1;

	pos = length;
	if (fixed < length) {
		if (++numbers_cache <= counts_cache) {
			if (length >= 2)
				goto update_last;
			numbers[length] = numbers_cache;
			goto update_ending;
		}
		numbers[pos--] = 0;
		while (pos > fixed) {
			if (++numbers[pos] <= counts_length[pos])
				goto update_ending;
			numbers[pos--] = 0;
		}
	}
	while (pos-- > 0) {
		if (++numbers[pos] <= counts_length[pos])
			goto update_ending;
		numbers[pos] = 0;
	}

	return 0;
}

void do_incremental_crack(struct db_main *db, char *mode)
{
	char *charset;
	int min_length, max_length, max_count;
	char *extra;
	FILE *file;
	struct charset_header *header;
	unsigned int check;
	char allchars[CHARSET_SIZE + 1];
	char char1[CHARSET_SIZE + 1];
	char2_table char2;
	chars_table chars[CHARSET_LENGTH - 2];
	unsigned char *ptr;
	unsigned int fixed, count;
	int last_length, last_count;
	int pos;

	if (!mode) {
		if (db->format == &fmt_LM)
			mode = "LM_ASCII";
		else
			mode = "ASCII";
	}

	log_event("Proceeding with \"incremental\" mode: %.100s", mode);

	if (!(charset = cfg_get_param(SECTION_INC, mode, "File"))) {
		log_event("! No charset defined");
		if (john_main_process)
			fprintf(stderr, "No charset defined for mode: %s\n",
			    mode);
		error();
	}

	extra = cfg_get_param(SECTION_INC, mode, "Extra");

	if ((min_length = cfg_get_int(SECTION_INC, mode, "MinLen")) < 0)
		min_length = 0;
	if ((max_length = cfg_get_int(SECTION_INC, mode, "MaxLen")) < 0)
		max_length = CHARSET_LENGTH;
	max_count = cfg_get_int(SECTION_INC, mode, "CharCount");

	if (min_length > max_length) {
		log_event("! MinLen = %d exceeds MaxLen = %d",
		    min_length, max_length);
		if (john_main_process)
			fprintf(stderr, "MinLen = %d exceeds MaxLen = %d\n",
			    min_length, max_length);
		error();
	}

	if (min_length > db->format->params.plaintext_length) {
		log_event("! MinLen = %d is too large for this hash type",
		    min_length);
		if (john_main_process)
			fprintf(stderr,
			    "MinLen = %d exceeds the maximum possible "
			    "length for the current hash type (%d)\n",
			    min_length, db->format->params.plaintext_length);
		error();
	}

	if (max_length > db->format->params.plaintext_length) {
		log_event("! MaxLen = %d is too large for this hash type",
		    max_length);
		if (john_main_process)
			fprintf(stderr, "Warning: MaxLen = %d is too large "
			    "for the current hash type, reduced to %d\n",
			    max_length, db->format->params.plaintext_length);
		max_length = db->format->params.plaintext_length;
	}

	if (max_length > CHARSET_LENGTH) {
		log_event("! MaxLen = %d exceeds the compile-time limit of %d",
		    max_length, CHARSET_LENGTH);
		if (john_main_process)
			fprintf(stderr, "MaxLen = %d exceeds the compile-time "
			    "limit of %d\n", max_length, CHARSET_LENGTH);
		error();
	}

	if (!(file = fopen(path_expand(charset), "rb")))
		pexit("fopen: %s", path_expand(charset));

	header = (struct charset_header *)mem_alloc(sizeof(*header));

	if (charset_read_header(file, header) && !ferror(file))
		inc_format_error(charset);
	if (ferror(file))
		pexit("fread");

	if (feof(file) ||
	    memcmp(header->version, CHARSET_V, sizeof(header->version)) ||
	    !header->count)
		inc_format_error(charset);

	if (header->min != CHARSET_MIN || header->max != CHARSET_MAX ||
	    header->length != CHARSET_LENGTH) {
		log_event("! Incompatible charset file: %.100s", charset);
		if (john_main_process)
			fprintf(stderr, "Incompatible charset file: %s\n",
			    charset);
		error();
	}

#if CHARSET_SIZE < 0xff
	if (header->count > CHARSET_SIZE)
		inc_format_error(charset);
#endif

	check =
		(unsigned int)header->check[0] |
		((unsigned int)header->check[1] << 8) |
		((unsigned int)header->check[2] << 16) |
		((unsigned int)header->check[3] << 24);
	if (!rec_restoring_now)
		rec_check = check;
	if (rec_check != check) {
		log_event("! Charset file has changed: %.100s", charset);
		if (john_main_process)
			fprintf(stderr, "Charset file has changed: %s\n",
			    charset);
		error();
	}

	if (fread(allchars, header->count, 1, file) != 1) {
		if (ferror(file))
			pexit("fread");
		inc_format_error(charset);
	}

/* Sanity-check and expand allchars */
	real_minc = CHARSET_MIN; real_size = CHARSET_SIZE;
	allchars[header->count] = 0;
	if (expand(allchars, "", sizeof(allchars)))
		inc_format_error(charset);
	if (extra && expand(allchars, extra, sizeof(allchars))) {
		log_event("! Extra characters not in compile-time "
		    "specified range ('\\x%02x' to '\\x%02x')",
		    CHARSET_MIN, CHARSET_MAX);
		if (john_main_process)
			fprintf(stderr, "Extra characters not in compile-time "
			    "specified range ('\\x%02x' to '\\x%02x')\n",
			    CHARSET_MIN, CHARSET_MAX);
		error();
	}

/* Calculate the actual real_* based on sanitized and expanded allchars */
	{
		unsigned char c;
		real_min = 0xff;
		real_count = real_max = 0;
		while ((c = allchars[real_count])) {
			c -= CHARSET_MIN;
			if (c < real_min)
				real_min = c;
			if (c > real_max)
				real_max = c;
			real_chars[real_count++] = c;
		}
		real_minc = CHARSET_MIN + real_min;
		real_size = real_max - real_min + 1;
		if (real_size < real_count)
			inc_format_error(charset);
	}

	if (max_count < 0)
		max_count = CHARSET_SIZE;

	if (min_length != max_length)
		log_event("- Lengths %d to %d, up to %d different characters",
		    min_length, max_length, max_count);
	else
		log_event("- Length %d, up to %d different characters",
		    min_length, max_count);

	if ((unsigned int)max_count > real_count) {
		log_event("! Only %u characters available", real_count);
		if (john_main_process)
			fprintf(stderr,
			    "Warning: only %u characters available\n",
			    real_count);
	}

	if (!(db->format->params.flags & FMT_CASE) && is_mixedcase(allchars)) {
		log_event("! Mixed-case charset, "
		    "but the hash type is case-insensitive");
		if (john_main_process)
			fprintf(stderr, "Warning: mixed-case charset, "
			    "but the current hash type is case-insensitive;\n"
			    "some candidate passwords may be unnecessarily "
			    "tried more than once.\n");
	}

	char2 = NULL;
	for (pos = 0; pos < CHARSET_LENGTH - 2; pos++)
		chars[pos] = NULL;
	if (max_length >= 2) {
		char2 = (char2_table)mem_alloc(sizeof(*char2));
		for (pos = 0; pos < max_length - 2; pos++)
			chars[pos] = (chars_table)mem_alloc(sizeof(*chars[0]));
	}

	rec_entry = 0;
	memset(rec_numbers, 0, sizeof(rec_numbers));

	status_init(NULL, 0);

	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	ptr = header->order;
	entry = 0;
	while (entry < rec_entry &&
	    ptr < &header->order[sizeof(header->order) - 1]) {
		entry++;
		length = *ptr++; fixed = *ptr++; count = *ptr++;

		if (length >= CHARSET_LENGTH ||
		    fixed > length ||
		    count >= CHARSET_SIZE)
			inc_format_error(charset);

		if (count >= real_count || (fixed && !count))
			continue;

		if ((int)length + 1 < min_length ||
		    (int)length >= max_length ||
		    (int)count >= max_count)
			continue;

		if (count)
			counts[length][fixed]++;

		if (counts[length][fixed] != count) {
			log_event("! Unexpected count: %d != %d",
			    counts[length][fixed] + 1, count + 1);
			fprintf(stderr, "Unexpected count: %d != %d\n",
			    counts[length][fixed] + 1, count + 1);
			error();
		}
	}

	memcpy(numbers, rec_numbers, sizeof(numbers));

	crk_init(db, fix_state, NULL);

	last_count = last_length = -1;

	entry--;
	while (ptr < &header->order[sizeof(header->order) - 1]) {
		int skip = 0;
		if (options.node_count) {
			int for_node = entry % options.node_count + 1;
			skip = for_node < options.node_min ||
			    for_node > options.node_max;
		}

		entry++;
		length = *ptr++; fixed = *ptr++; count = *ptr++;

		if (length >= CHARSET_LENGTH ||
		    fixed > length ||
		    count >= CHARSET_SIZE)
			inc_format_error(charset);

		if (entry != rec_entry)
			memset(numbers, 0, sizeof(numbers));

		if (count >= real_count || (fixed && !count))
			continue;

		if ((int)length + 1 < min_length ||
		    (int)length >= max_length ||
		    (int)count >= max_count)
			continue;

		if (!skip) {
			int i, max_count = 0;
			if ((int)length != last_length) {
				inc_new_length(last_length = length,
				    header, file, charset, char1, char2, chars);
				last_count = -1;
			}
			for (i = 0; i <= length; i++)
				if (counts[length][i] > max_count)
					max_count = counts[length][i];
			if (count > max_count)
				max_count = count;
			if (max_count > last_count) {
				last_count = max_count;
				inc_new_count(length, max_count, charset,
				    allchars, char1, char2, chars);
			}
		}

		if (!length && !min_length) {
			min_length = 1;
			if (!skip && crk_process_key(""))
				break;
		}

		if (count)
			counts[length][fixed]++;

		if (counts[length][fixed] != count) {
			log_event("! Unexpected count: %d != %d",
			    counts[length][fixed] + 1, count + 1);
			fprintf(stderr, "Unexpected count: %d != %d\n",
			    counts[length][fixed] + 1, count + 1);
			error();
		}

		if (skip)
			continue;

		log_event("- Trying length %d, fixed @%d, character count %d",
		    length + 1, fixed + 1, counts[length][fixed] + 1);

		if (inc_key_loop(length, fixed, count, char1, char2, chars))
			break;
	}

	crk_done();
	rec_done(event_abort);

	for (pos = 0; pos < max_length - 2; pos++)
		MEM_FREE(chars[pos]);
	MEM_FREE(char2);
	MEM_FREE(header);

	fclose(file);
}

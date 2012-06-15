/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2006 by Solar Designer
 *
 * ...with a change in the jumbo patch, by JoMo-Kun
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
#include "config.h"
#include "charset.h"
#include "external.h"
#include "cracker.h"

extern struct fmt_main fmt_LM;
extern struct fmt_main fmt_NETLM;
extern struct fmt_main fmt_NETHALFLM;

#ifdef HAVE_MPI
#include "john-mpi.h"
#endif
#include <math.h>

static unsigned long long try, cand;

static int get_progress(int *hundth_perc)
{
	int hundredXpercent, percent;

	if (!cand)
		return -1;

	if (try > 1844674407370955LL) {
		*hundth_perc = percent = 99;
	} else {
		hundredXpercent = (int)((unsigned long long)(10000 * (try)) / (unsigned long long)cand);
		percent = hundredXpercent / 100;
		*hundth_perc = hundredXpercent - (percent*100);
	}
	return percent;
}

typedef char (*char2_table)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1];
typedef char (*chars_table)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1][CHARSET_SIZE + 1];

static int rec_compat;
static int rec_entry;
static int rec_numbers[CHARSET_LENGTH];

static int entry;
static int numbers[CHARSET_LENGTH];

static void save_state(FILE *file)
{
	int pos;
	unsigned tmp;
	unsigned long long tmpLL;

	fprintf(file, "%d\n%d\n%d\n", rec_entry, rec_compat, CHARSET_LENGTH);
	for (pos = 0; pos < CHARSET_LENGTH; pos++)
		fprintf(file, "%d\n", rec_numbers[pos]);
	// number added 'after' array, to preserve the try count, so that we can later know the 
	// values tested, to report progress.  Before this, we could NOT report.
	if (cand) {
		tmpLL = try;
		tmp = (unsigned) (tmpLL>>32);
		fprintf(file, "%u\n", tmp);
		tmp = (unsigned)tmpLL;
		fprintf(file, "%u\n", tmp);
	}
}

static int restore_state(FILE *file)
{
	int length;
	int pos;
	unsigned tmp;

	if (fscanf(file, "%d\n", &rec_entry) != 1) return 1;
	rec_compat = 1;
	length = CHARSET_LENGTH;
	if (rec_version >= 2) {
		if (fscanf(file, "%d\n%d\n", &rec_compat, &length) != 2)
			return 1;
		if ((unsigned int)rec_compat > 1) return 1;
		if ((unsigned int)length > CHARSET_LENGTH) return 1;
	}
	for (pos = 0; pos < length; pos++) {
		if (fscanf(file, "%d\n", &rec_numbers[pos]) != 1) return 1;
		if ((unsigned int)rec_numbers[pos] >= CHARSET_SIZE) return 1;
	}
	tmp = 0;
	if (fscanf(file, "%u\n", &tmp) != 1) { cand = 0; return 0; } // progress reporting don't work after resume so we mute it
	try = tmp;
	try <<= 32;
	tmp = 0;
	if (fscanf(file, "%u\n", &tmp) != 1) { cand = 0; try = 0; return 0; } // progress reporting don't work after resume so we mute it
	try += tmp;

	return 0;
}

static void fix_state(void)
{
	rec_entry = entry;
	memcpy(rec_numbers, numbers, sizeof(rec_numbers));
}

static void inc_format_error(char *charset)
{
	log_event("! Incorrect charset file format: %.100s", charset);
#ifdef HAVE_MPI
	if (mpi_id == 0)
#endif
	fprintf(stderr, "Incorrect charset file format: %s\n", charset);
	error();
}

static int is_mixedcase(char *chars)
{
	char present[CHARSET_SIZE];
	char *ptr, c;
	unsigned int i;

	memset(present, 0, sizeof(present));
	ptr = chars;
	while ((c = *ptr++)) {
		i = ARCH_INDEX(c) - CHARSET_MIN;
		if (i >= CHARSET_SIZE)
			return -1;
		present[i] = 1;
	}

	ptr = chars;
	while ((c = *ptr++)) {
		/* assume ASCII */
		if (c >= 'A' && c <= 'Z') {
			i = ARCH_INDEX(c | 0x20) - CHARSET_MIN;
			if (i < CHARSET_SIZE && present[i])
				return 1;
		}
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
	if (length)
		memset(char2, 0, sizeof(*char2));
	for (pos = 0; pos <= (int)length - 2; pos++)
		memset(chars[pos], 0, sizeof(**chars));

	offset =
		(long)header->offsets[length][0] |
		((long)header->offsets[length][1] << 8) |
		((long)header->offsets[length][2] << 16) |
		((long)header->offsets[length][3] << 24);
	if (fseek(file, offset, SEEK_SET)) pexit("fseek");

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
				if (value == CHARSET_ESC) break;
				if (count >= CHARSET_SIZE)
					inc_format_error(charset);
			}
			buffer[count] = 0;

			continue;
		}

		if ((value = getc(file)) == EOF) break; else
		if (value == CHARSET_NEW) {
			if ((value = getc(file)) != (int)length) break;
			if ((value = getc(file)) == EOF) break;
			if (value < 0 || value > (int)length)
				inc_format_error(charset);
			pos = value;
		} else
		if (value == CHARSET_LINE) {
			if (pos < 0)
				inc_format_error(charset);
			if ((value = getc(file)) == EOF) break;
			i = value;
			if (i < 0 || i > CHARSET_SIZE)
				inc_format_error(charset);
			if ((value = getc(file)) == EOF) break;
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

	memset(present, 0, sizeof(present));
	while (*dptr) {
		if (--count <= 1)
			return 0;
		i = ARCH_INDEX(*dptr++) - CHARSET_MIN;
		if (i >= CHARSET_SIZE)
			return -1;
		present[i] = 1;
	}

	while (*sptr) {
		i = ARCH_INDEX(*sptr) - CHARSET_MIN;
		if (i >= CHARSET_SIZE)
			return -1;
		if (!present[i]) {
			*dptr++ = *sptr++;
			if (--count <= 1) break;
		} else
			sptr++;
	}
	*dptr = 0;

	return 0;
}

static void inc_new_count(unsigned int length, int count, char *charset,
	char *allchars, char *char1, char2_table char2, chars_table *chars)
{
	int pos, i, j;
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

	for (i = 0; i < CHARSET_SIZE; i++) {
		if (length) error |=
			expand((*char2)[i], (*char2)[CHARSET_SIZE], size);

		for (j = 0; j < CHARSET_SIZE; j++)
		for (pos = 0; pos <= (int)length - 2; pos++) {
			error |= expand((*chars[pos])[i][j], (*chars[pos])
				[CHARSET_SIZE][j], size);
			error |= expand((*chars[pos])[i][j], (*chars[pos])
				[CHARSET_SIZE][CHARSET_SIZE], size);
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
	int numbers_cache;
	int pos;

	key_i[length + 1] = 0;
	numbers[fixed] = count;

	chars_cache = NULL;

update_all:
	pos = 0;
update_ending:
	if (pos < 2) {
		if (pos == 0)
			key_i[0] = char1[numbers[0]];
		if (length) key_i[1] = (*char2)
			[ARCH_INDEX(key_i[0]) - CHARSET_MIN][numbers[1]];
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
	try++;
	if (!f_filter || ext_filter_body(key_i, key = key_e))
		if (crk_process_key(key))
			return 1;

	if (rec_compat) goto compat;

	pos = length;
	if (fixed < length) {
		if (++numbers_cache <= count) {
			if (length >= 2) goto update_last;
			numbers[length] = numbers_cache;
			goto update_ending;
		}
		numbers[pos--] = 0;
		while (pos > fixed) {
			if (++numbers[pos] <= count) goto update_ending;
			numbers[pos--] = 0;
		}
	}
	while (pos-- > 0) {
		if (++numbers[pos] < count) goto update_ending;
		numbers[pos] = 0;
	}

	return 0;

compat:
	pos = 0;
	if (fixed) {
		if (++numbers[0] < count) goto update_all;
		if (!length && numbers[0] <= count) goto update_all;
		numbers[0] = 0;
		pos = 1;
		while (pos < fixed) {
			if (++numbers[pos] < count) goto update_all;
			numbers[pos++] = 0;
		}
	}
	while (++pos <= length) {
		if (++numbers[pos] <= count) goto update_all;
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
	unsigned int length, fixed, count;
	unsigned int real_count;
	int last_length, last_count;
	int pos;

	if (!mode) {
		if (db->format == &fmt_LM)
			mode = "LanMan";
		else if (db->format == &fmt_NETLM)
			mode = "LanMan";
		else if (db->format == &fmt_NETHALFLM)
			mode = "LanMan";
		else
			mode = "All";
	}

	log_event("Proceeding with \"incremental\" mode: %.100s", mode);

	if (!(charset = cfg_get_param(SECTION_INC, mode, "File"))) {
		if(cfg_get_section(SECTION_INC, mode) == NULL) {
			log_event("! Unknown incremental mode: %s", mode);
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "Unknown incremental mode: %s\n", mode);
			error();
		}
		else {
			log_event("! No charset defined");
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "No charset defined for mode: %s\n", mode);
			error();
		}
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
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "MinLen = %d exceeds MaxLen = %d\n",
			min_length, max_length);
		error();
	}

	if (min_length > db->format->params.plaintext_length) {
		log_event("! MinLen = %d is too large for this hash type",
			min_length);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "MinLen = %d exceeds the maximum possible "
			"length for the current hash type (%d)\n",
			min_length, db->format->params.plaintext_length);
		error();
	}

	if (max_length > db->format->params.plaintext_length) {
		log_event("! MaxLen = %d is too large for this hash type",
			max_length);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: "
			"MaxLen = %d is too large for the current hash type, "
			"reduced to %d\n",
			max_length, db->format->params.plaintext_length);
		max_length = db->format->params.plaintext_length;
	}

	if (max_length > CHARSET_LENGTH) {
		log_event("! MaxLen = %d exceeds the compile-time limit of %d",
			max_length, CHARSET_LENGTH);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr,
			"\n"
			"MaxLen = %d exceeds the compile-time limit of %d\n\n"
			"There are several good reasons why you probably don't "
			"need to raise it:\n"
			"- many hash types don't support passwords "
			"(or password halves) longer than\n"
			"7 or 8 characters;\n"
			"- you probably don't have sufficient statistical "
			"information to generate a\n"
			"charset file for lengths beyond 8;\n"
			"- the limitation applies to incremental mode only.\n",
			max_length, CHARSET_LENGTH);
		error();
	}

	if (!(file = fopen(path_expand(charset), "rb")))
		pexit("fopen: %s", path_expand(charset));

	header = (struct charset_header *)mem_alloc(sizeof(*header));

	if (charset_read_header(file, header) && !ferror(file))
		inc_format_error(charset);
	if (ferror(file)) pexit("fread");

	if (feof(file) ||
	    (memcmp(header->version, CHARSET_V1, sizeof(header->version)) &&
	    memcmp(header->version, CHARSET_V2, sizeof(header->version))) ||
	    !header->count)
		inc_format_error(charset);

	if (header->min != CHARSET_MIN || header->max != CHARSET_MAX ||
	    header->length != CHARSET_LENGTH) {
		log_event("! Incompatible charset file: %.100s", charset);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Incompatible charset file: %s\n", charset);
		error();
	}

	if (header->count > CHARSET_SIZE)
		inc_format_error(charset);

	check =
		(unsigned int)header->check[0] |
		((unsigned int)header->check[1] << 8) |
		((unsigned int)header->check[2] << 16) |
		((unsigned int)header->check[3] << 24);
	if (!rec_restoring_now)
		rec_check = check;
	if (rec_check != check) {
		log_event("! Charset file has changed: %.100s", charset);
		fprintf(stderr, "Charset file has changed: %s\n", charset);
		error();
	}

	if (fread(allchars, header->count, 1, file) != 1) {
		if (ferror(file)) pexit("fread");
		inc_format_error(charset);
	}

	allchars[header->count] = 0;
	if (expand(allchars, "", sizeof(allchars)))
		inc_format_error(charset);
	if (extra && expand(allchars, extra, sizeof(allchars))) {
		log_event("! Extra characters not in compile-time "
			"specified range ('\\x%02x' to '\\x%02x')",
			CHARSET_MIN, CHARSET_MAX);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Extra characters not in compile-time "
			"specified range ('\\x%02x' to '\\x%02x')\n",
			CHARSET_MIN, CHARSET_MAX);
		error();
	}
	real_count = strlen(allchars);

	if (max_count < 0) max_count = CHARSET_SIZE;

	if (min_length != max_length)
		log_event("- Lengths %d to %d, up to %d different characters",
			min_length, max_length, max_count);
	else
		log_event("- Length %d, up to %d different characters",
			min_length, max_count);

	if ((unsigned int)max_count > real_count) {
		log_event("! Only %u characters available", real_count);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: only %u characters available\n",
			real_count);
	}

	for (pos = min_length; pos <= max_length; pos++)
		cand += pow(real_count, pos);

	if (!(db->format->params.flags & FMT_CASE))
	switch (is_mixedcase(allchars)) {
	case -1:
		inc_format_error(charset);

	case 1:
		log_event("! Mixed-case charset, "
			"but the hash type is case-insensitive");
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Warning: mixed-case charset, "
			"but the current hash type is case-insensitive;\n"
			"some candidate passwords may be unnecessarily "
			"tried more than once.\n");
	}

	if (header->length >= 2)
		char2 = (char2_table)mem_alloc(sizeof(*char2));
	else
		char2 = NULL;
	for (pos = 0; pos < (int)header->length - 2; pos++)
		chars[pos] = (chars_table)mem_alloc(sizeof(*chars[0]));

	rec_compat = 0;
#ifdef HAVE_MPI
	/* *ptr has to start at different positions so they don't overlap */
	rec_entry = mpi_id;
#else
	rec_entry = 0;
#endif
	memset(rec_numbers, 0, sizeof(rec_numbers));

	status_init(get_progress, 0);

	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	ptr = header->order + (entry = rec_entry) * 3;
	memcpy(numbers, rec_numbers, sizeof(numbers));

	crk_init(db, fix_state, NULL);

	last_count = last_length = -1;

	entry--;
	while (ptr < &header->order[sizeof(header->order) - 1]) {
		entry++;
		length = *ptr++; fixed = *ptr++; count = *ptr++;

#ifdef HAVE_MPI
		/* increment *ptr with the number of processors after this */
		ptr = ptr + (3 * (mpi_p - 1));
		entry = entry + mpi_p - 1;
#endif
		if (length >= CHARSET_LENGTH ||
			fixed > length ||
			count >= CHARSET_SIZE) inc_format_error(charset);

		if (entry != rec_entry)
			memset(numbers, 0, sizeof(numbers));

		if (count >= real_count || (fixed && !count)) continue;

		if ((int)length + 1 < min_length ||
			(int)length >= max_length ||
			(int)count >= max_count) continue;

		if ((int)length != last_length) {
			inc_new_length(last_length = length,
				header, file, charset, char1, char2, chars);
			last_count = -1;
		}
		if ((int)count > last_count)
			inc_new_count(length, last_count = count, charset,
				allchars, char1, char2, chars);

		if (!length && !min_length) {
			min_length = 1;
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			if (crk_process_key("")) break;
		}

		log_event("- Trying length %d, fixed @%d, character count %d",
			length + 1, fixed + 1, count + 1);

		if (inc_key_loop(length, fixed, count, char1, char2, chars))
			break;
	}

	if (!event_abort)
		try = cand = 100; // For reporting DONE after a no-ETA run

	crk_done();
	rec_done(event_abort);

	for (pos = 0; pos < (int)header->length - 2; pos++)
		MEM_FREE(chars[pos]);
	MEM_FREE(char2);
	MEM_FREE(header);

	fclose(file);
}

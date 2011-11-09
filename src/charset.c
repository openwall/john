/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2005,2008,2011 by Solar Designer
 *
 * ...with changes in the jumbo patch, by various authors
 */

#include <stdio.h>
#ifndef _MSC_VER
#include <unistd.h>
#else
#define unlink _unlink
#endif
#include <string.h>
#include <math.h>
#include <assert.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "crc32.h"
#include "signals.h"
#include "loader.h"
#include "external.h"
#include "charset.h"

typedef unsigned int (*char_counters)
	[CHARSET_SIZE + 1][CHARSET_SIZE + 1][CHARSET_SIZE];

typedef unsigned int (*crack_counters)
	[CHARSET_LENGTH][CHARSET_LENGTH][CHARSET_SIZE];

static CRC32_t checksum;

static void charset_filter_plaintexts(struct db_main *db)
{
	struct list_entry *current, *last;
	unsigned char *ptr;
	char key[PLAINTEXT_BUFFER_SIZE];

	last = NULL;
	if ((current = db->plaintexts->head))
	do {
		if (!current->data[0]) {
			list_del_next(db->plaintexts, last);
			continue;
		}

		for (ptr = (unsigned char *)current->data; *ptr; ptr++)
		if (*ptr < CHARSET_MIN || *ptr > CHARSET_MAX) {
			list_del_next(db->plaintexts, last);
			break;
		}
		if (*ptr) continue;

		strnzcpy(key, current->data, PLAINTEXT_BUFFER_SIZE);
		if (ext_filter(key)) {
			if (strlen(key) <= strlen(current->data))
				strcpy(current->data, key);
		} else {
			list_del_next(db->plaintexts, last);
			continue;
		}

		last = current;
	} while ((current = current->next));
}

static int cfputc(int c, FILE *stream)
{
	unsigned char ch;

	ch = c;
	CRC32_Update(&checksum, &ch, 1);

	return fputc(c, stream);
}

static void charset_checksum_header(struct charset_header *header)
{
	CRC32_Update(&checksum, header->version, sizeof(header->version));
	CRC32_Update(&checksum, &header->min, 1);
	CRC32_Update(&checksum, &header->max, 1);
	CRC32_Update(&checksum, &header->length, 1);
	CRC32_Update(&checksum, &header->count, 1);
	CRC32_Update(&checksum, header->offsets, sizeof(header->offsets));
	CRC32_Update(&checksum, header->order, sizeof(header->order));
	CRC32_Final(header->check, checksum);
}

static void charset_write_header(FILE *file, struct charset_header *header)
{
	fwrite(header->version, sizeof(header->version), 1, file);
	fwrite(header->check, sizeof(header->check), 1, file);
	fputc(header->min, file);
	fputc(header->max, file);
	fputc(header->length, file);
	fputc(header->count, file);
	fwrite(header->offsets, sizeof(header->offsets), 1, file);
	fwrite(header->order, sizeof(header->order), 1, file);
}

int charset_read_header(FILE *file, struct charset_header *header)
{
	if (fread(header->version, sizeof(header->version), 1, file) != 1)
		return -1;
	memset(header->check, 0, sizeof(header->check));
	if (memcmp(header->version, CHARSET_V1, sizeof(header->version)) &&
	    fread(header->check, sizeof(header->check), 1, file) != 1)
		return -1;
	{
		unsigned char values[4];
		if (fread(values, sizeof(values), 1, file) != 1)
			return -1;
		header->min = values[0];
		header->max = values[1];
		header->length = values[2];
		header->count = values[3];
	}
	return
	    fread(header->offsets, sizeof(header->offsets), 1, file) != 1 ||
	    fread(header->order, sizeof(header->order), 1, file) != 1;
}

static int charset_new_length(int length,
	struct charset_header *header, FILE *file)
{
	int result;
	long offset;

	if ((result = length < CHARSET_LENGTH)) {
		printf("%d ", length + 1);
		fflush(stdout);

		if ((offset = ftell(file)) < 0) pexit("ftell");
		header->offsets[length][0] = (unsigned char)((unsigned long)offset);
		header->offsets[length][1] = (unsigned char)((unsigned long)(offset >> 8));
		header->offsets[length][2] = (unsigned char)((unsigned long)(offset >> 16));
		header->offsets[length][3] = (unsigned char)((unsigned long)(offset >> 24));
	}

	return result;
}

static void charset_generate_chars(struct list_entry *plaintexts,
	FILE *file, struct charset_header *header,
	char_counters chars, crack_counters cracks)
{
	struct list_entry *current;
	unsigned char *ptr;
	unsigned char buffer[CHARSET_SIZE];
	int length, pos, best, count;
	unsigned int value, max;
	int i, j, k;

	current = plaintexts;
	do {
		for (ptr = (unsigned char *)current->data; *ptr; ptr++)
			(*chars)[0][0][ARCH_INDEX(*ptr - CHARSET_MIN)]++;
	} while ((current = current->next));

	count = 0;
	best = 0;
	do {
		max = 0;
		for (k = 0; k < CHARSET_SIZE; k++)
		if ((value = (*chars)[0][0][k]) > max) {
			max = value; best = k;
		}
		if (!max) break;

		(*chars)[0][0][best] = 0;
		buffer[count++] = CHARSET_MIN + best;
	} while (1);

	header->count = count;
	fwrite(buffer, 1, count, file);
	CRC32_Update(&checksum, buffer, count);

	for (length = 0; charset_new_length(length, header, file); length++)
	for (pos = 0; pos <= length; pos++) {
		if (event_abort) return;

		cfputc(CHARSET_ESC, file); cfputc(CHARSET_NEW, file);
		cfputc(length, file); cfputc(pos, file);

		memset(chars, 0, sizeof(*chars));

		current = plaintexts;
		do
		if ((int)strlen(current->data) == length + 1) {
			ptr = (unsigned char *)current->data;
			(*chars)
				[CHARSET_SIZE]
				[CHARSET_SIZE]
				[ARCH_INDEX(ptr[pos] - CHARSET_MIN)]++;
			if (pos) (*chars)
				[CHARSET_SIZE]
				[ARCH_INDEX(ptr[pos - 1] - CHARSET_MIN)]
				[ARCH_INDEX(ptr[pos] - CHARSET_MIN)]++;
			if (pos > 1) (*chars)
				[ARCH_INDEX(ptr[pos - 2] - CHARSET_MIN)]
				[ARCH_INDEX(ptr[pos - 1] - CHARSET_MIN)]
				[ARCH_INDEX(ptr[pos] - CHARSET_MIN)]++;
		} while ((current = current->next));

		for (i = (pos > 1 ? 0 : CHARSET_SIZE); i <= CHARSET_SIZE; i++)
		for (j = (pos ? 0 : CHARSET_SIZE); j <= CHARSET_SIZE; j++) {
			count = 0;
			do {
				max = 0;
				for (k = 0; k < CHARSET_SIZE; k++)
				if ((value = (*chars)[i][j][k]) > max) {
					max = value; best = k;
				}

				if (i == CHARSET_SIZE && j == CHARSET_SIZE)
					(*cracks)[length][pos][count] = max;

				if (!max) break;

				(*chars)[i][j][best] = 0;
				buffer[count++] = CHARSET_MIN + best;
			} while (1);

			if (count) {
				cfputc(CHARSET_ESC, file);
				cfputc(CHARSET_LINE, file);
				cfputc(i, file); cfputc(j, file);
				fwrite(buffer, 1, count, file);
				CRC32_Update(&checksum, buffer, count);
			}
		}
	}

	cfputc(CHARSET_ESC, file); cfputc(CHARSET_NEW, file);
	cfputc(CHARSET_LENGTH, file);
}

static double powi(int x, unsigned int y)
{
	double a = 1.0;
	if (y) {
		double b = x;
		do {
			if (y & 1)
				a *= b;
			if (!(y >>= 1))
				break;
			b *= b;
		} while (1);
	}
	return a;
}

/*
 * This generates the "cracking order" (please see the comment in charset.h)
 * based on the number of candidate passwords for each {length, fixed index
 * position, character count} combination, and on the number of cracked
 * passwords for that combination.  The idea is to start with combinations for
 * which the ratio between the number of candidates and the number of
 * successful cracks is the smallest.  This way, the expected number of
 * successful cracks per a unit of time will be monotonically non-increasing
 * over time.  Of course, this applies to the expectation only (based on
 * available statistics) - actual behavior (on a yet unknown set of passwords
 * to be cracked) may and likely will differ.
 *
 * The cracks[] array is used as input (containing the number of successful
 * cracks for each combination).
 */
static void charset_generate_order(crack_counters cracks,
	unsigned char *order, int size)
{
	int length, pos, count; /* zero-based */
	int best_length, best_pos, best_count;
	double total, min, value;
	unsigned char *ptr;
	double (*ratios)[CHARSET_LENGTH][CHARSET_LENGTH][CHARSET_SIZE];

	ratios = mem_alloc(sizeof(*ratios));

/* Calculate the ratios */

	for (length = 0; length < CHARSET_LENGTH; length++)
	for (count = 0; count < CHARSET_SIZE; count++) {
/* First, calculate the number of candidate passwords for this combination of
 * length and count (number of different character indices).  We subtract the
 * number of candidates for the previous count (at the same length) because
 * those are to be tried as a part of another combination. */
		total = powi(count + 1, length + 1) - powi(count, length + 1);

/* Calculate the number of candidates for a {length, fixed index position,
 * character count} combination, for the specific values of length and count.
 * Obviously, this value is the same for each position in which the character
 * index is fixed - it only depends on the length and count - which is why we
 * calculate it out of the inner loop. */
		if (count)
			total /= length + 1;

/* Finally, for each fixed index position separately, calculate the candidates
 * to successful cracks ratio.  We treat combinations with no successful cracks
 * (so far) the same as those with exactly one successful crack. */
		for (pos = 0; pos <= length; pos++) {
			double ratio = total;
			unsigned int div = (*cracks)[length][pos][count];
			if (div)
				ratio /= div;
			(*ratios)[length][pos][count] = ratio;
		}
	}

/*
 * Fill out the order[] with combinations sorted for non-decreasing ratios.
 *
 * We currently use a very inefficient sorting algorithm, but it's fine as long
 * as the size of order[] is small and this code only executes once per charset
 * file generated.
 */

	ptr = order;
	best_length = best_pos = best_count = 0;
	do {
/* Find the minimum ratio and its corresponding combination */
		int found = 0;
		min = 0.0; /* unused */

		for (length = 0; length < CHARSET_LENGTH; length++)
		for (count = 0; count < CHARSET_SIZE; count++)
		for (pos = 0; pos <= length; pos++) {
			value = (*ratios)[length][pos][count];
			if (value >= 0.0 && (!found || value < min)) {
				found = 1;
				min = value;
				best_length = length;
				best_pos = pos;
				best_count = count;
			}
		}

		if (!found)
			break;

/* Record the combination and "take" it out of the input array */
		(*ratios)[best_length][best_pos][best_count] = -1.0; /* taken */
		assert(ptr <= order + size - 3);
		*ptr++ = best_length;
		*ptr++ = best_pos;
		*ptr++ = best_count;
	} while (!event_abort);

	assert(event_abort || ptr == order + size);

	MEM_FREE(ratios);
}

static void charset_generate_all(struct list_entry *plaintexts, char *charset)
{
	FILE *file;
	int was_error;
	struct charset_header *header;
	char_counters chars;
	crack_counters cracks;

	header = (struct charset_header *)mem_alloc(sizeof(*header));
	memset(header, 0, sizeof(*header));

	chars = (char_counters)mem_alloc(sizeof(*chars));
	memset(chars, 0, sizeof(*chars));

	cracks = (crack_counters)mem_alloc(sizeof(*cracks));

	if (!(file = fopen(path_expand(charset), "wb")))
		pexit("fopen: %s", path_expand(charset));

	charset_write_header(file, header);

	printf("Generating charsets... ");
	fflush(stdout);

	charset_generate_chars(plaintexts, file, header, chars, cracks);
	if (event_abort) {
		fclose(file);
		unlink(charset);
		putchar('\n'); check_abort(0);
	}

	printf("DONE\nGenerating cracking order... ");
	fflush(stdout);

	charset_generate_order(cracks, header->order, sizeof(header->order));
	if (event_abort) {
		fclose(file);
		unlink(charset);
		putchar('\n'); check_abort(0);
	}

	puts("DONE");

	fflush(file);
	if (!ferror(file) && !fseek(file, 0, SEEK_SET)) {
		strncpy(header->version, CHARSET_V, sizeof(header->version));
		header->min = CHARSET_MIN;
		header->max = CHARSET_MAX;
		header->length = CHARSET_LENGTH;
		charset_checksum_header(header);
		charset_write_header(file, header);
	}

	MEM_FREE(cracks);
	MEM_FREE(chars);

	was_error = ferror(file);
	if (fclose(file) || was_error) {
		unlink(charset);
		fprintf(stderr, "Failed to write charset file: %s\n", charset);
		error();
	}

	printf("Successfully written charset file: %s (%d character%s)\n",
		charset, header->count, header->count != 1 ? "s" : "");

	MEM_FREE(header);
}

void do_makechars(struct db_main *db, char *charset)
{
	charset_filter_plaintexts(db);

	printf("Loaded %d plaintext%s%s\n",
		db->plaintexts->count,
		db->plaintexts->count != 1 ? "s" : "",
		db->plaintexts->count ? "" : ", exiting...");

	if (!db->plaintexts->count) return;

	CRC32_Init(&checksum);

	charset_generate_all(db->plaintexts->head, charset);
}

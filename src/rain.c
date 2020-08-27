/*
 * This software is Copyright (c) 2018 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

/*
 * TODO:
 * - Profile with Callgrind
 * - Assure hybrid support (mask or external)
 * - Reject other hybrid modes?
 * - Try inlining utf32_to_enc
 * - Are we still using an unnecessary step of indexing?
 *
 * IDEAS:
 * - Store charset in target encoding for quicker conversion, even for
 *   UTF-8 (we can store it in uint32_t)! Beware of endianness.
 *
 * RELATED:
 * - Unicode ranges charsets. Generator? Standalone? --subsets-file=FILE?
 * - Add global options --skip-odd-lengths and --skip-even-lengths (also
 *   affecting mask mode and inc, possibly some external modes)
 */
#include "os.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <math.h>

#include "arch.h"
#include "int128.h"
#include "john.h"
#include "loader.h"
#include "cracker.h"
#include "options.h"
#include "config.h"
#include "logger.h"
#include "status.h"
#include "signals.h"
#include "recovery.h"
#include "mask.h"
#include "unicode.h"
#include "unicode_range.h"

#define SUBSET_DEBUG 1

#define MAX_SUBSET_SIZE 16
#define MAX_CAND_LENGTH PLAINTEXT_BUFFER_SIZE
#define DEFAULT_MAX_LEN 16

#if JTR_HAVE_INT128
typedef uint128_t uint_big;
#define UINT_BIG_MAX UINT128_MAX
#else
typedef uint64_t uint_big;
#define UINT_BIG_MAX UINT64_MAX
#endif

int rain_cur_len;

static char *charset;
static UTF32 subset[MAX_CAND_LENGTH + 1];
static int done_len[MAX_SUBSET_SIZE + 1];
static int rec_done_len[MAX_SUBSET_SIZE + 1];
int **charset_idx;
int **rec_charset_idx;
int maxlength;
int minlength;
static int rec_num_comb, num_comb;
static int rec_word_len, word_len;
static int rec_set, set;
static int state_restored;
static int rec_cur_len;
static int quick_conversion;
uint_big keyspace;
static int charcount;
uint_big *rain;
uint_big glob;
int loop2, loop;//the outer and inner loop
int *Accu;//holds the modifiers

static double get_progress(void)
{
	emms();

	if (!keyspace)
		return -1;
	if (loop2 > maxlength-minlength && loop > maxlength - minlength)
		return 100;
	return 100.0 * glob / keyspace;
}

static void fix_state(void)
{
/*
	int i, j;

	rec_set = set;
	rec_num_comb = num_comb;
	rec_word_len = word_len;
	for (i = 0; i <= maxdiff; i++)
		rec_done_len[i] = done_len[i];
	for (i = 0; i <= maxlength-minlength; i++)
		for(j = 0; j < maxlength; ++j)
			rec_charset_idx[i][j] = charset_idx[i][j];
	rec_cur_len = rain_cur_len;
	for (i = 0; i <= maxlength; i++)
		rec_num_done[i] = num_done[i];
*/
}


static void save_state(FILE *file)
{
/*
	int i;

	fprintf(file, "%d\n", rec_set);
	fprintf(file, "%d\n", rec_num_comb);
	fprintf(file, "%d\n", rec_word_len);
	for (i = 0; i <= maxdiff; i++)
		fprintf(file, "%d\n", rec_done_len[i]);
	for (i = 0; i < rec_num_comb; i++)
		fprintf(file, "%d\n", rec_charset_idx[i]);
	fprintf(file, "%d\n", rec_cur_len);
	for (i = 0; i <= maxlength; i++)
		fprintf(file, "%"PRIu64"\n", rec_num_done[i]);
	//fprintf(file, "%s\n", charset);
*/
}

static int restore_state(FILE *file)
{
/*
	int i, d;
	uint64_t q;

	if (fscanf(file, "%d\n", &d) == 1)
		set = d;
	else
		return 1;

	if (fscanf(file, "%d\n", &d) == 1)
		num_comb = d;
	else
		return 1;

	if (fscanf(file, "%d\n", &d) == 1)
		word_len = d;
	else
		return 1;

	for (i = 0; i <= maxdiff; i++)
		if (fscanf(file, "%d\n", &d) == 1)
			done_len[i] = d;
		else
			return 1;

	for (i = 0; i < num_comb; i++)
		if (fscanf(file, "%d\n", &d) == 1)
			charset_idx[i] = d;
		else
			return 1;

	if (fscanf(file, "%d\n", &d) == 1)
		subsets_cur_len = d;
	else
		return 1;

	for (i = 0; i <= maxlength; i++)
		if (fscanf(file, "%"PRIu64"\n", &q) == 1)
			num_done[i] = q;
		else
			return 1;

	///if (fscanf(file, "%s\n", &charset) != 1)
	//	return 1;

	state_restored = 1;

	return 0;
*/
}




/* Parse \U+HHHH and \U+HHHHH notation to characters, in place. */
static void parse_unicode(char *string)
{
	static int warned;
	unsigned char *s = (unsigned char*)string;
	unsigned char *d = s;

	if (!string || !*string)
		return;

	while (*s)
		if (*s == '\\' && s[1] != 'U') {
			*d++ = *s++;
			*d++ = *s++;
		} else if (*s == '\\' && s[1] == 'U' && s[2] == '+' &&
		           atoi16[s[3]] != 0x7f && atoi16[s[4]] != 0x7f &&
		           atoi16[s[5]] != 0x7f && atoi16[s[6]] != 0x7f &&
		           atoi16[s[7]] != 0x7f) {
			UTF32 wc[2];
			UTF8 conv[8];
			char *c = (char*)conv;

			wc[0] = (atoi16[s[3]] << 16) + (atoi16[s[4]] << 12) +
				(atoi16[s[5]] << 8) + (atoi16[s[6]] << 4) + atoi16[s[7]];
			wc[1] = 0;
			if (!wc[0] && !warned++ && john_main_process)
				fprintf(stderr,
				        "Warning: \\U+00000 in mask terminates the string\n");
			if (wc[0] == '\\')
				*d++ = '\\';

			utf32_to_enc(conv, sizeof(conv), wc);

			while (*c)
				*d++ = *c++;
			s += 8;
		} else if (*s == '\\' && s[1] == 'U' && s[2] == '+' &&
		           atoi16[s[3]] != 0x7f && atoi16[s[4]] != 0x7f &&
		           atoi16[s[5]] != 0x7f && atoi16[s[6]] != 0x7f) {
			UTF32 wc[2];
			UTF8 conv[8];
			char *c = (char*)conv;

			wc[0] = (atoi16[s[3]] << 12) + (atoi16[s[4]] << 8) +
				(atoi16[s[5]] << 4) + atoi16[s[6]];
			wc[1] = 0;
			if (!wc[0] && !warned++ && john_main_process)
				fprintf(stderr,
				        "Warning: \\U+0000 in mask terminates the string\n");
			if (wc[0] == '\\')
				*d++ = '\\';

			utf32_to_enc(conv, sizeof(conv), wc);

			while (*c)
				*d++ = *c++;
			s += 7;
		} else
			*d++ = *s++;

	*d = 0;
}

static int submit(UTF32 *subset)
{
	UTF8 out[4 * MAX_CAND_LENGTH];
	int i;

	/* Set current word */
	if (quick_conversion) {
		/* Quick conversion (only ASCII or ISO-8859-1) */
		for (i = 0; i < word_len; i++)
			out[i] = subset[i];
		out[i] = 0;
	} else if (options.target_enc == UTF_8) {
		/* Nearly as quick conversion, from UTF-8-32[tm] to UTF-8 */
		subset[word_len] = 0;
		utf8_32_to_utf8(out, subset);
	} else {
		/* Slowest conversion, from real UTF-32 to sone legacy codepage */
		subset[word_len] = 0;
		utf32_to_enc(out, sizeof(out), subset);
	}

	if (options.flags & FLG_MASK_CHK)
		return do_mask_crack((char*)out);
	else
		return crk_process_key((char*)out);
}

static int accu(int a) {
	int b, c=0;
	for(b=1; b<=a; ++b)
		c+=b;
	return c;
}

char *roll_on(int loop) {
	short int mpl = minlength+loop;
 	short int pos = mpl - 1;
	short int i;
	char tmp[minlength+loop+1];
	for(i=0; i<mpl; ++i) {
		tmp[i] = charset[(charset_idx[loop][i] + rain[loop]) % charcount];
 		rain[loop]+=i+1;
 	}
 	//subtract what we added in the above loop, minus the modifier
 	if	(charcount % 10 == 0)	rain[loop] -= Accu[loop]-2;
	else if	(charcount % 2 == 0)	rain[loop] -= Accu[loop]-4;
	else 				rain[loop] -= Accu[loop]-1;
 	
	while(pos >= 0 && ++charset_idx[loop][pos] >= charcount) {
		charset_idx[loop][pos] = 0;
		--pos;
	}
	tmp[mpl] = '\0';
	crk_process_key(tmp);
	//current length is done ?	
	if(pos < 0) return NULL;
	else return "a";
}

int do_rain_crack(struct db_main *db, char *req_charset)
{
	int i, j;
	int fmt_case = (db->format->params.flags & FMT_CASE);
	char *default_set;
	UTF32 *charset_utf32;
	int required = options.subset_must;
	

	maxlength = MIN(MAX_CAND_LENGTH, options.eff_maxlength);
	minlength = MIN(MAX_CAND_LENGTH, options.eff_minlength);
		
	if (!options.req_maxlength)
		maxlength = MIN(maxlength, DEFAULT_MAX_LEN);
	if (!options.req_minlength)
		minlength = 1;

	charset_idx = mem_alloc(sizeof(int) * (maxlength - minlength+1));
	//rec_charset_idx = mem_alloc(sizeof(int) * (maxlength - minlength+1));
	Accu = mem_alloc(sizeof(int) * (maxlength - minlength+1));

	glob = 0;
	for(i=0; i<= maxlength - minlength; ++i) {
		charset_idx[i] = mem_alloc(sizeof(int) * maxlength);
		//rec_charset_idx[i] = mem_alloc(sizeof(int) * maxlength);
		Accu[i] = accu(minlength+i);		
		for(j=0; j < maxlength; ++j)
			charset_idx[i][j] = 0;
	}	
	rain = mem_alloc(sizeof(uint_big) * (maxlength - minlength + 1));

	done_len[0] = maxlength;

	default_set = (char*)cfg_get_param("Subsets", NULL, "DefaultCharset");
	if (!req_charset)
		req_charset = default_set;

	if (req_charset && *req_charset) {
		if (strlen(req_charset) == 1 && isdigit(req_charset[0])) {
			int cnum = atoi(req_charset);
			char pl[2] = { '0' + cnum, 0 };
			char *c = (char*)cfg_get_param("Subsets", NULL, pl);

			if (c)
				req_charset = c;
		}

		/* Parse \U+HHHH notation */
		parse_unicode(req_charset);
		charset = req_charset;
	} else if (fmt_case)
		charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	else
		charset = "0123456789abcdefghijklmnopqrstuvwxyz !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

	charcount = strlen(charset);

	/*	
	if (!strcasecmp(charset, "full-unicode")) {
		charset_utf32 = mem_alloc(0x22000 * sizeof(UTF32));
		charcount = full_unicode_charset(charset_utf32);
	}
	else if (options.input_enc == UTF_8) {
		if (!valid_utf8((UTF8*)charset)) {
			if (john_main_process)
				fprintf(stderr, "Error in Unicode conversion. "
				        "Ensure --input-encoding is correct\n");
			error();
		} else {
			int charsize = strlen8((UTF8*)charset) + 1;

			charset_utf32 = mem_alloc(charsize * sizeof(UTF32));
			utf8_to_utf32(charset_utf32, charsize * sizeof(UTF32),
			              (UTF8*)charset, charcount);
		}
	}
	else {
		charset_utf32 = mem_alloc((charcount + 1) * sizeof(UTF32));
		enc_to_utf32(charset_utf32, (charcount + 1) * sizeof(UTF32),
		             (UTF8*)charset, charcount);
	}

	//Performance step: Use UTF-32-8 when applicable
	if (options.target_enc == UTF_8)
		utf32_to_utf8_32(charset_utf32);

	charcount = strlen32(charset_utf32);
	
	if (required >= charcount) {
		if (john_main_process)
			fprintf(stderr, "Error, required part of charset must be smaller "
			        "than charset (1..%d out of %d)\n",
			        charcount - 1, charcount);
		error();
	}*/

	status_init(get_progress, 0);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	for (i = 0; i <= maxlength - minlength; i++)
		keyspace += (__int128)pow((double) charcount, (double) minlength+i);

	loop2 = 0;
	crk_init(db, fix_state, NULL);
	
	while (loop2 <= maxlength - minlength) {
		loop = loop2;
		/* Iterate over all lengths */
		while (loop <= maxlength - minlength) {
			if(roll_on(loop) == NULL) ++loop2;
			++loop;
			++glob;		
		}
	}
	crk_done();
	rec_done(event_abort);

	return 0;
}

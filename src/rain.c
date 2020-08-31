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
static UTF32 rain[MAX_CAND_LENGTH+1];
static int charset_idx[MAX_CAND_LENGTH][MAX_CAND_LENGTH];//the first value should be req_maxlen-req_minlen
static int rec_charset_idx[MAX_CAND_LENGTH][MAX_CAND_LENGTH];
static int maxlength;
static int minlength;
static int state_restored;
static uint_big keyspace;
static uint_big drops[MAX_CAND_LENGTH];//same as above
static uint_big rec_drops[MAX_CAND_LENGTH];
static uint_big glob;
static uint_big rec_glob;
static int quick_conversion;
static int loop2, loop;//the outer and inner loop
static int rec_loop2 ,set;
static int Accu[MAX_CAND_LENGTH];//holds the modifiers

static double get_progress(void)
{
	emms();

	if (!keyspace)
		return -1;
	if (loop2 > maxlength-minlength)
		return 100;
	return 100.0 * glob / keyspace;
}

static void fix_state(void)
{
	int i, j;

	for (i = 0; i <= maxlength - minlength; i++) {
		rec_drops[i] = drops[i];	
		for(j = 0; j < maxlength; ++j)
			rec_charset_idx[i][j] = charset_idx[i][j];
	}
	rain_cur_len = minlength+loop2;
	rec_loop2 = loop2;
	rec_glob = glob;
}


static void save_state(FILE *file)
{

	int i, j;

	for (i = 0; i <= maxlength - minlength; i++) {
		fprintf(file, "%llu\n ", rec_drops[i]);	
		for(j = 0; j < maxlength; ++j)
			fprintf(file, "%d\n", rec_charset_idx[i][j]);
	}
	fprintf(file, "%d\n", loop2);
	fprintf(file, "%llu\n", glob);
}

static int restore_state(FILE *file)
{
	int i, j, d;
	uint_big r;

	for (i = 0; i <= maxlength - minlength; i++) {
		if(fscanf(file, "%llu\n ", &r) == 1)//all those bigint needs a fix in save and restore state
			drops[i] = r;
		else return 1;	
		for(j = 0; j < maxlength; ++j)
			if(fscanf(file, "%d\n", &d) == 1)
				charset_idx[i][j] = d;
			else return 1;
	}
	if(fscanf(file, "%d\n", &d) == 1)
		loop2 = d;
	else return 1;

	if(fscanf(file, "%llu\n", &r) == 1)
		glob = r;
	else return 1;
	
	state_restored = 1;

	return 0;
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


int accu(int a) {
	int b, c=0;
	for(b=1; b<=a; ++b)
		c+=b;
	return c;
}

static int submit(UTF32 *subset)
{
	UTF8 out[4 * MAX_CAND_LENGTH];
	int i;

	/* Set current word */
	if (quick_conversion) {
		/* Quick conversion (only ASCII or ISO-8859-1) */
		for (i = 0; i < minlength+loop; i++)
			out[i] = rain[i];
		out[i] = 0;
	} else if (options.target_enc == UTF_8) {
		/* Nearly as quick conversion, from UTF-8-32[tm] to UTF-8 */
		rain[minlength+loop] = 0;
		utf8_32_to_utf8(out, rain);
	} else {
		/* Slowest conversion, from real UTF-32 to sone legacy codepage */
		rain[minlength+loop] = 0;
		utf32_to_enc(out, sizeof(out), rain);
	}

	if (options.flags & FLG_MASK_CHK)
		return do_mask_crack((char*)out);
	else
		return crk_process_key((char*)out);
}

int do_rain_crack(struct db_main *db, char *req_charset)
{
	int i, j;
	unsigned int charcount;
	int fmt_case = (db->format->params.flags & FMT_CASE);
	char *default_set;
	UTF32 *charset_utf32;

	maxlength = MIN(MAX_CAND_LENGTH, options.eff_maxlength);
	minlength = MAX(options.eff_minlength, 1);
		
	if (!options.req_maxlength)
		maxlength = MIN(maxlength, DEFAULT_MAX_LEN);
	if (!options.req_minlength)
		minlength = 1;

	default_set = (char*)cfg_get_param("Rain", NULL, "DefaultCharset");
	if (!req_charset)
		req_charset = default_set;

	if (req_charset && *req_charset) {
		if (strlen(req_charset) == 1 && isdigit(req_charset[0])) {
			int cnum = atoi(req_charset);
			char pl[2] = { '0' + cnum, 0 };
			char *c = (char*)cfg_get_param("Rain", NULL, pl);

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
	int cp_max = 255;
	rain_cur_len = loop2;

	status_init(get_progress, 0);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	for (i = 0; i <= maxlength - minlength; i++)
		keyspace += (__int128)pow((double) charcount, (double) minlength+i);

	crk_init(db, fix_state, NULL);
	

	if (!state_restored) {
		glob = 0;
		loop2 = 0;
	}
	
	for (i=0; i<= maxlength - minlength; ++i) {
		Accu[i] = accu(minlength+i);
		if (!state_restored) {
			drops[i] = 0;
			for (j = 0; j < maxlength; ++j)
				charset_idx[i][j] = 0;
		}
	}

	while(loop2 <= maxlength - minlength) {
	
		loop = loop2;
		int bail = 0;
		/* Iterate over all lengths */
		while(loop <= maxlength - minlength) {
			int skip = 0;

			if(state_restored)
				state_restored = 0;
			else
				++set;
			
			if(options.node_count) {
				int for_node = set % options.node_count + 1;
				skip = for_node < options.node_min ||
					for_node > options.node_max;
			}
			
			int pos = minlength + loop - 1;
			
			if(!skip) {
				quick_conversion = 1;
				for(i=0; i<minlength+loop; ++i) {
					if((rain[i] = charset_utf32[(charset_idx[loop][i] + drops[loop]) % charcount]) > cp_max)
						quick_conversion = 0;
					drops[loop]+=i+1;
				}
				
				drops[loop] -= Accu[loop];		
				
				submit(rain);
				
			}
			if (charcount % 10 == 0)
				drops[loop] += 2;

			else if (charcount % 2 == 0)
				drops[loop] += 4;

			else
				++drops[loop];
				
			while(pos >= 0 && ++charset_idx[loop][pos] >= charcount) {
				charset_idx[loop][pos] = 0;
				if(--pos < 0) {
					++loop2;
					break;
				}
			}
			
					
				
			++loop;
		}
	}
	crk_done();
	rec_done(event_abort);
	MEM_FREE(charset_utf32);
	return 0;
}


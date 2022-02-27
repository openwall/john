/*
 * This software is Copyright (c) 2018 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

/*
 * TODO:
 * - Profile with Callgrind
 * - Reject other hybrid modes?
 * - Are we still using an unnecessary step of indexing?
 *
 * RELATED:
 * - Unicode ranges charsets. Generator? Standalone? --Rain-file=FILE?
 * - Add global options --skip-odd-lengths and --skip-even-lengths (also
 *   affecting mask mode and inc, possibly some external modes)
 */
#include "os.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

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

#define MAX_CAND_LENGTH PLAINTEXT_BUFFER_SIZE
#define DEFAULT_MIN_LEN 1
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
static UTF32 rain[MAX_CAND_LENGTH + 1];
static int charset_idx[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH];
static int rec_charset_idx[MAX_CAND_LENGTH-1][MAX_CAND_LENGTH];
static int state_restored;
static int rec_cur_len;
static int quick_conversion;
static uint64_t cur_keyspace, keyspace;
static int rec_set, set;
static short int maxlength;
static short int minlength;


static double get_progress(void)
{
	emms();

	if (!cur_keyspace)
		return -1;

	return 100.0 * rain_cur_len / cur_keyspace;
}

static void fix_state(void)
{
	int i, j;
	for (i = 0; i <= maxlength-minlength; i++)
		for (j = 0; j < maxlength; j++)
			rec_charset_idx[i][j] = charset_idx[i][j];
	rec_cur_len = rain_cur_len;
	rec_set = set;
}

static void save_state(FILE *file)
{
	int i, j;
	for (i = 0; i <= maxlength-minlength; i++)
		for (j = 0; j < maxlength; j++)
			fprintf(file, "%d\n", rec_charset_idx[i][j]);
	fprintf(file, "%d\n", rec_cur_len);
	fprintf(file, "%d\n", rec_set);
}

static int restore_state(FILE *file)
{
	int i, j, d;

	for (i = 0; i <= maxlength-minlength; i++)
		for (j = 0; j < maxlength; j++)
			if(fscanf(file, "%d\n", &d) == 1)
				charset_idx[i][j] = d;
			else
				return 1;
	state_restored = 1;
	if(fscanf(file, "%d\n", &d))
		rain_cur_len = d;
	if(fscanf(file, "%d\n", &d))
		set = d;
	
	return 0;
}

/* uint128_t max. eg. 2^127, 3^80, 4^63, 5^55, 6^49, 7^45 */
/* uint64_t            2^63, 3^40, 4^31, 5^27, 6^24, 7^22 */
static uint_big powi(uint32_t b, uint32_t p)
{
	uint_big res = 1;
	uint32_t orig = p;

	if (b == 0)
		return 0;

	while (p--) {
		uint_big temp = res * b;

		if (temp < res)
			error_msg("Rain: %s(%u, %u) overflow\n", __FUNCTION__, b, orig);
		res = temp;
	}

	return res;
}

/* Drop dupes in string, in place. */
static void remove_dupes(UTF32 *string)
{
	UTF32 *s = string, *d = string;

	while (*s) {
		UTF32 c = *s, *p = s;

		while (p > string) {
			if (*--p == c) {
				c = 0;
				break;
			}
		}
		if (c)
			*d++ = *s++;
		else
			s++;
	}
	*d = 0;
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

static int submit(UTF32 *rain)
{
	UTF8 out[4 * MAX_CAND_LENGTH];
	int i;

	/* Set current word */
	if (quick_conversion) {
		/* Quick conversion (only ASCII or ISO-8859-1) */
		for (i = 0; i < rain_cur_len; i++)
			out[i] = rain[i];
		out[i] = 0;
	} else if (options.target_enc == UTF_8) {
		/* Nearly as quick conversion, from UTF-8-32[tm] to UTF-8 */
		rain[rain_cur_len] = 0;
		utf8_32_to_utf8(out, rain);
	} else {
		/* Slowest conversion, from real UTF-32 to some legacy codepage */
		rain[rain_cur_len] = 0;
		utf32_to_enc(out, sizeof(out), rain);
	}

	if (options.flags & FLG_MASK_CHK)
		return do_mask_crack((char*)out);
	else
		return crk_process_key((char*)out);
}

int do_rain_crack(struct db_main *db, char *req_charset)
{
	int i, j, cp_max = 127;
	int charcount;
	int fmt_case = (db->format->params.flags & FMT_CASE);
	char *default_set;
	UTF32 *charset_utf32;
	
	maxlength = MIN(MAX_CAND_LENGTH, options.eff_maxlength);
	minlength = MIN(MAX_CAND_LENGTH, options.eff_minlength);

	if (!options.req_maxlength)
		maxlength = MIN(maxlength, DEFAULT_MAX_LEN);
	
	if (!options.req_minlength)
		minlength = MIN(minlength, DEFAULT_MIN_LEN);

	if (options.eff_minlength > maxlength) {
		if (john_main_process)
			fprintf(stderr, "Rain: Too large min. length\n");
		error();
	}
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

	/* Convert charset to UTF-32 */
	if (!strcasecmp(charset, "full-unicode")) {
		charset_utf32 = mem_alloc(0x24000 * sizeof(UTF32));
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

	/* Performance step: Use UTF-32-8 when applicable */
	if (options.target_enc == UTF_8)
		utf32_to_utf8_32(charset_utf32);

	/* Silently drop dupes */
	remove_dupes(charset_utf32);

	charcount = strlen32(charset_utf32);

	if (options.target_enc == ENC_RAW || options.target_enc == ISO_8859_1)
		cp_max = 255;

	rain_cur_len = MAX(DEFAULT_MIN_LEN, options.eff_minlength);

	status_init(get_progress, 0);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	for (i = 0; i <= minlength - maxlength; i++)
		keyspace += powi(charcount, minlength + i);

	if (john_main_process) {
		uint64_t total_keyspace = 0;

		log_event("Proceeding with \"Rain\" mode");
		log_event("- Charset: %s size %d", req_charset ? req_charset : charset,
		          charcount);
		log_event("- Lengths: %d-%d",
		          minlength, maxlength);
		if (total_keyspace)
			log_event("- Total keyspace: %" PRIu64, keyspace);
		else
			log_event("- Total keyspace: larger than 64-bit");
		if (rain_cur_len < maxlength) {
			if (keyspace)
				log_event("- Length %d total keyspace: %" PRIu64, rain_cur_len, keyspace);
			else
				log_event("- Length %d total keyspace: larger than 64-bit", rain_cur_len);
		}
		if (rec_restored) {
			fprintf(stderr, "Proceeding with \"Rain\"%s%s",
			        req_charset ? ": " : "",
			        req_charset ? req_charset : "");
			if (options.flags & FLG_MASK_CHK)
				fprintf(stderr, ", hybrid mask:%s", options.mask ?
				        options.mask : options.eff_mask);
			if (options.rule_stack)
				fprintf(stderr, ", rules-stack:%s", options.rule_stack);
			if (options.req_minlength >= 0 || options.req_maxlength)
				fprintf(stderr, ", lengths: %d-%d",
				        options.eff_minlength,
				        options.eff_maxlength);
			fprintf(stderr, "\n");
		}
	}

	crk_init(db, fix_state, NULL);
	
	/* Iterate over subset sizes and output lengths */
	for(rain_cur_len; rain_cur_len <= maxlength; rain_cur_len++) {
		if(rain_cur_len == minlength)
			cur_keyspace = powi(charcount, rain_cur_len);
		else
			cur_keyspace = powi(charcount, rain_cur_len) - powi(charcount, rain_cur_len-1);
		
		if (options.verbosity >= VERB_DEFAULT)
		log_event("Rain - word length %d  - keyspace %"PRIu64, rain_cur_len, cur_keyspace);

		if (!state_restored) {
			/* Initialize first subset */
			for (i = 0; i <= maxlength - minlength; i++)
				for (j = 0; j < maxlength; j++)
					charset_idx[i][j] = i;
		}
		/* Iterate over Rain for this size */
		uint64_t X;
		for(X = 0; X < cur_keyspace; X++)
		{
			int loop2;
			for(loop2 = 0; loop2 <= maxlength - rain_cur_len; loop2++) {
				int skip = 0;
	
				if (state_restored)
					state_restored = 0;
				else
					set++;
	
				if (options.node_count) {
					int for_node = set % options.node_count + 1;
					skip = for_node < options.node_min ||
						for_node > options.node_max;
				}
				if (!skip) {
					/* Set current subset */
					quick_conversion = 1;
					for (i = 0; i < minlength+loop2; i++) {
						if ((rain[i] = charset_utf32[charset_idx[loop2][i]]) > cp_max)
							quick_conversion = 0;
					}
					submit(rain);
				}
				for(i = 0; i < minlength+loop2; i++) {
					if(++charset_idx[loop2][i] >= charcount) {
						charset_idx[loop2][i] = 0;
						break;
					}
				}
			}
		}
	}
	crk_done();
	rec_done(event_abort);
	MEM_FREE(charset_utf32);

	return 0;
}

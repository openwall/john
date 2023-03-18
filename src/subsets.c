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

int subsets_cur_len;

static char *charset;
static UTF32 subset[MAX_CAND_LENGTH + 1];
static int done_len[MAX_SUBSET_SIZE + 1];
static int rec_done_len[MAX_SUBSET_SIZE + 1];
static int charset_idx[MAX_CAND_LENGTH];
static int rec_charset_idx[MAX_CAND_LENGTH];
static int maxdiff;
static int maxlength;
static int rec_num_comb, num_comb;
static int rec_word_len, word_len;
static int rec_set, set;
static int state_restored;
static int rec_cur_len;
static int quick_conversion;
static uint64_t rec_num_done[MAX_CAND_LENGTH + 1];
static uint64_t num_done[MAX_CAND_LENGTH + 1];
static uint64_t keyspace;

static double get_progress(void)
{
	emms();

	if (!keyspace)
		return -1;

	return 100.0 * num_done[subsets_cur_len] / keyspace;
}

static void fix_state(void)
{
	int i;

	rec_set = set;
	rec_num_comb = num_comb;
	rec_word_len = word_len;
	for (i = 0; i <= maxdiff; i++)
		rec_done_len[i] = done_len[i];
	for (i = 0; i < rec_num_comb; i++)
		rec_charset_idx[i] = charset_idx[i];
	rec_cur_len = subsets_cur_len;
	for (i = 0; i <= maxlength; i++)
		rec_num_done[i] = num_done[i];
}

static void save_state(FILE *file)
{
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
}

static int restore_state(FILE *file)
{
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

	state_restored = 1;

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
			error_msg("Subsets: %s(%u, %u) overflow\n", __FUNCTION__, b, orig);
		res = temp;
	}

	return res;
}

/* Max 34! for uint128_t or 20! for uint64_t */
static uint_big fac(uint32_t n)
{
	uint_big res = n;
	uint32_t orig = n;

	if (n == 0)
		return 1;

	while (--n) {
		uint_big temp = res * n;

		if (temp < res)
			error_msg("Subsets: %s(%u) overflow\n", __FUNCTION__, orig);
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

/*
 * How many unique sets of size k can you make from full set of size n?
 * No repeats, order does not matter.
 * numsets(3, 2) == 3, eg. abc --> ab ac cb (not aa or ba etc.)
 *
 * This is known as "n choose k":   n! / (k!(n - k)!)
 *
 * fac() would overflow so here's a recursing function that does the
 * job nicely at O(k).
 *
 * if r > 0, this is size of required part of set
 */
static uint64_t numsets(uint64_t n, uint64_t k, uint32_t r)
{
	if (r)
		return numsets(n, k, 0) - numsets(n - r, k, 0);
	if (k == 0)
		return 1;
	else if (k == 1)
		return n;
	else
		return (n * numsets(n - 1, k - 1, 0)) / k;
}

/*
 * How many unique words of length len can you make from all subsets of
 * size k from a full set with size n? k is <= len.
 * Repeats are allowed, order does matter, all of the subset must be
 * represented.
 *
 * numwords(2, 3, 2) = 6  "abc" --> ab ac ba bc ca cb (not aa, bb or cc)
 *
 * if r > 0, this is size of required part of set
 */
static uint64_t numwords(uint32_t k, uint32_t n, uint32_t len, uint32_t r)
{
	if (r)
		return numwords(k, n, len, 0) - numwords(k, n - r, len, 0);
	if (k == 1)
		return n;
	else if (n == len && k == n)
		return fac(n);
	else if (k == len)
		return fac(k) * numsets(n, k, 0);
	else {
		uint64_t res, i;

		res = powi(k, len);
		i = 0;
		do {
			i++;
			res -= numsets(k, i, 0) * powi(k - i, len);
			if (i == k)
				break;
			i++;
			res += numsets(k, i, 0) * powi(k - i, len);
		} while (i < k);

		return res * numsets(n, k, 0);
	}
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
		out[maxlength] = 0;
	} else {
		/* Slowest conversion, from real UTF-32 to some legacy codepage */
		subset[word_len] = 0;
		utf32_to_enc(out, sizeof(out), subset);
	}

	if (options.flags & FLG_MASK_CHK)
		return do_mask_crack((char*)out);
	else
		return crk_process_key((char*)out);
}

static void swap(UTF32 *x, UTF32 *y)
{
	int temp;

	temp = *x;
	*x = *y;
	*y = temp;
}


static int permute(UTF32 *a, int i, int n)
{
	int j;

	if (i >= n - 1)
		return submit(a);

	for (j = i; j < n; j++) {
		swap(&a[i], &a[j]);
		if (permute(a, i + 1, n))
			return 1;
		swap(&a[i], &a[j]);
	}

	return 0;
}

static int unique(UTF32 *a, int start, int index)
{
	int i;

	for (i = start; i < index; i++)
		if (a[i] == a[index])
			return 0;
	return 1;
}

static int permute_dupe(UTF32 *a, int i, int n)
{
	int j;

	if (i >= n - 1)
		return submit(a);

	for (j = i; j < n; j++) {
		if (unique(a, i, j)) {
			swap(&a[i], &a[j]);
			if (permute_dupe(a, i + 1, n))
				return 1;
			swap(&a[i], &a[j]);
		}
	}

	return 0;
}

static int expand(UTF32 *a, int setlen, int outlen, int base)
{
	int j;

	if (setlen == outlen)
		return permute_dupe(a, 0, outlen);

	for (j = base; j < num_comb; j++) {
		a[setlen] = a[j];
		if (expand(a, setlen + 1, outlen, j))
			return 1;
	}

	return 0;
}

int do_subsets_crack(struct db_main *db, char *req_charset)
{
	int i, cp_max = 127;
	int charcount;
	int fmt_case = (db->format->params.flags & FMT_CASE);
	char *default_set;
	UTF32 *charset_utf32;
	int required = options.subset_must;
	int min_comb = options.subset_min_diff;

	maxlength = MIN(MAX_CAND_LENGTH, options.eff_maxlength);

	if (!options.req_maxlength)
		maxlength = MIN(maxlength, DEFAULT_MAX_LEN);

	if ((maxdiff = options.subset_max_diff) < 0)
		maxdiff += maxlength;

	if (!min_comb && ((min_comb = cfg_get_int("Subsets", NULL, "MinDiff")) < 1))
		min_comb = 1;

	if (!maxdiff && ((maxdiff = cfg_get_int("Subsets", NULL, "MaxDiff")) < 0))
		maxdiff = MAX_SUBSET_SIZE;

	if (maxdiff < min_comb)
		maxdiff = min_comb;

	if (options.eff_minlength > maxlength) {
		if (john_main_process)
			fprintf(stderr, "Subsets: Too large min. length\n");
		error();
	}

	num_comb = min_comb;

	if (maxdiff > MAX_SUBSET_SIZE)
		maxdiff = MAX_SUBSET_SIZE;

	done_len[0] = maxlength;
	for (i = 1; i <= maxdiff; i++)
		done_len[i] = MAX(MAX(i, options.eff_minlength), 1) - 1;

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

	if (required >= charcount) {
		if (john_main_process)
			fprintf(stderr, "Error, required part of charset must be smaller "
			        "than charset (1..%d out of %d)\n",
			        charcount - 1, charcount);
		error();
	}

	if (options.target_enc == ENC_RAW || options.target_enc == ISO_8859_1)
		cp_max = 255;

	if (maxdiff > charcount)
		maxdiff = charcount;

	if (maxdiff > maxlength)
		maxdiff = maxlength;

	subsets_cur_len = word_len = MAX(num_comb, options.eff_minlength);

	status_init(get_progress, 0);
	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	for (i = min_comb; i <= MIN(subsets_cur_len, maxdiff); i++) {
		uint64_t nw = numwords(i, charcount, subsets_cur_len, required);
		keyspace += nw;
		if (keyspace < nw) {
			keyspace = 0;
			break;
		}
	}

	if (john_main_process) {
		int len;
		uint64_t total_keyspace = 0;

		if (keyspace)
		for (len = subsets_cur_len; len <= maxlength; len++) {
			for (i = min_comb; i <= MIN(len, maxdiff); i++) {
				uint64_t nw = numwords(i, charcount, len, required);
				total_keyspace += nw;
				if (total_keyspace < nw) {
					total_keyspace = 0;
					break;
				}
			}
			if (!total_keyspace)
				break;
		}

		log_event("Proceeding with \"subsets\" mode");
		log_event("- Charset: %s size %d", req_charset ? req_charset : charset,
		          charcount);
		log_event("- Lengths: %d-%d, max. subset size %d",
		          word_len, maxlength, maxdiff);
		if (required)
			log_event("- Required set: First %d of charset", required);
		if (total_keyspace)
			log_event("- Total keyspace: %" PRIu64, total_keyspace);
		else
			log_event("- Total keyspace: larger than 64-bit");
		if (word_len < maxlength) {
			if (keyspace)
				log_event("- Length %d total keyspace: %" PRIu64, subsets_cur_len, keyspace);
			else
				log_event("- Length %d total keyspace: larger than 64-bit", subsets_cur_len);
		}
		if (rec_restored) {
			fprintf(stderr, "Proceeding with \"subsets\"%s%s",
			        req_charset ? ": " : "",
			        req_charset ? req_charset : "");
			if (options.flags & FLG_MASK_CHK)
				fprintf(stderr, ", hybrid mask:%s", options.mask ?
				        options.mask : options.eff_mask);
			if (options.rule_stack)
				fprintf(stderr, ", rules-stack:%s", options.rule_stack);
			if (options.req_minlength >= 0 || options.req_maxlength)
				fprintf(stderr, ", lengths: %d-%d",
				        options.eff_minlength + mask_add_len,
				        options.eff_maxlength + mask_add_len);
			fprintf(stderr, "\n");
		}
	}

	crk_init(db, fix_state, NULL);

	/* Iterate over subset sizes and output lengths */
	while (num_comb <= maxdiff && word_len <= maxlength) {
		int target = MIN(num_comb, word_len);
		uint64_t num_sets = numsets(charcount, num_comb, required);
		uint64_t num_words = numwords(num_comb, charcount, word_len, required);
		uint64_t num_per_set = num_words / num_sets;
		int bail = 0;

		if (options.verbosity >= VERB_DEFAULT)
		log_event("- Subset size %d, word length %d (%"PRIu64" sets x %"PRIu64
		          " words), keyspace %"PRIu64, num_comb, word_len, num_sets,
		          num_per_set, num_words);

		if (!state_restored) {
			/* Initialize first subset */
			for (i = 0; i < num_comb; i++)
				charset_idx[num_comb - i - 1] = i;
		}

		/* Iterate over subsets for this size */
		while (1) {
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
				for (i = 0; i < num_comb; i++) {
					if ((subset[i] = charset_utf32[charset_idx[i]]) > cp_max)
						quick_conversion = 0;
				}

				/* Create all words for this subset and length */
				if (word_len > num_comb) {
					if (expand(subset, num_comb, word_len, 0)) {
						bail = 1;
						break;
					}
				} else {
					if (permute(subset, 0, word_len)) {
						bail = 1;
						break;
					}
				}
			}

			num_done[word_len] += num_per_set;

			if (bail || num_comb == charcount)
				break;

			/* Next subset of this size */
			i = 0;
			do {
				int b;

				while (i < target && ++charset_idx[i] >= charcount)
					++i;

				if (required && charset_idx[num_comb - 1] >= required)
					i = num_comb;

				if (i >= num_comb)
					break;

				b = i;
				while (--i >= 0)
				if ((charset_idx[i] = charset_idx[i + 1] + 1) >= charcount) {
					i = b + 1;
					break;
				}
			} while (i >= 0);

			if (i >= num_comb)
				break;
		}

		if (bail)
			break;

		done_len[num_comb] = word_len;

		for (i = min_comb; i <= maxdiff; i++)
			if (done_len[i] < word_len)
				break;

		if (i > maxdiff) {
			log_event("- Length %d now fully exhausted", word_len);
			if (word_len < maxlength) {
				subsets_cur_len = word_len + 1;
				keyspace = 0;
				for (i = min_comb; i <= MIN(subsets_cur_len, maxdiff); i++) {
					uint64_t nw = numwords(i, charcount, subsets_cur_len, required);
					keyspace += nw;
					if (keyspace < nw) {
						keyspace = 0;
						break;
					}
				}
				if (keyspace)
					log_event("- Length %d total keyspace: %" PRIu64, subsets_cur_len, keyspace);
				else
					log_event("- Length %d total keyspace: larger than 64-bit", subsets_cur_len);
				if (cfg_get_bool("Subsets", NULL, "LengthIterStatus", 1))
					event_pending = event_status = 1;
			}
		}

		/*
		 * Prefer keeping candidate length small
		 */
		if (options.flags & FLG_SUBSETS_SHORT) {
			if (num_comb < maxdiff && num_comb < word_len) {
				num_comb++;
				continue;
			}
			else if (word_len < maxlength) {
				word_len++;
				num_comb = min_comb;
				continue;
			}
		}

		num_comb = min_comb;
		while (done_len[num_comb] == maxlength && num_comb < maxdiff)
			num_comb++;

		if ((word_len = done_len[num_comb] + 1) > maxlength)
			break;

		/*
		 * Prefer keeping subset size small.
		 */
		if (options.flags & FLG_SUBSETS_SMALL)
			continue;

		/*
		 * Default: Look for shortest pending set of (length, subset size).
		 */
		uint64_t nw = numwords(num_comb, charcount, word_len, required);
		uint64_t smallest = nw;

		int i, best_i = 0;

		for (i = 1; num_comb + i <= maxdiff; i++) {
			if (done_len[num_comb + i] + 1 < maxlength) {
				uint64_t alt_nw = numwords(num_comb + i, charcount, done_len[num_comb + i] + 1, required);
				if (alt_nw < smallest) {
					smallest = alt_nw;
					best_i = i;
				}
			}
		}

		if (smallest < nw) {
			num_comb += best_i;
			word_len = done_len[num_comb] + 1;
		}
	}

	crk_done();
	rec_done(event_abort);

	MEM_FREE(charset_utf32);

	return 0;
}

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 * Copyright (c) 2013-2014 by magnum
 * Copyright (c) 2014 by Sayantan Datta
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h> /* for fprintf(stderr, ...) */
#include <string.h>

#include "misc.h" /* for error() */
#include "logger.h"
#include "recovery.h"
#include "os.h"
#include "signals.h"
#include "status.h"
#include "options.h"
#include "config.h"
#include "external.h"
#include "cracker.h"
#include "john.h"
#include "mask.h"
#include "unicode.h"
#include "encoding_data.h"
#include "memdbg.h"
#include <ctype.h>

static parsed_ctx parsed_mask;
static cpu_mask_context cpu_mask_ctx, rec_ctx;
static int *template_key_offsets;
static char *mask = NULL, *template_key;

/*
 * cand and rec_cand is the number of remaining candidates.
 * So, it's value decreases as cracking progress.
 */
static unsigned long long cand, rec_cand;

/*
 * Total number of candidates to begin with.
 * Remains unchanged throughout.
 */
unsigned long long mask_tot_cand;

#define BUILT_IN_CHARSET "aludshHA1234LU"

#define store_op(k, i) \
	parsed_mask->stack_op_br[k] = i;

#define store_cl(k, i) \
	parsed_mask->stack_cl_br[k] = i;

#define load_op(i) \
	parsed_mask->stack_op_br[i]

#define load_cl(i) \
	parsed_mask->stack_cl_br[i]

#define load_qtn(i) \
	parsed_mask->stack_qtn[i]

/* Converts \xHH notation to characters. The original buffer is modified -
   we are guaranteed the new string is shorter or same length */
static void parse_hex(char *string)
{
	unsigned char *s = (unsigned char*)string;
	unsigned char *d = s;

	if (!string || !*string)
		return;

	while (*s)
	if (*s == '\\' && s[1] != 'x') {
		*d++ = *s++;
		*d++ = *s++;
	} else if (*s == '\\' && s[1] == 'x' &&
	    atoi16[s[2]] != 0x7f && atoi16[s[3]] != 0x7f) {
		*d++ = (atoi16[s[2]] << 4) + atoi16[s[3]];
		s += 4;
	} else
		*d++ = *s++;

	*d = 0;
}

/* Expands custom placeholders in string and returns a new resulting string.
   with -1=?u?l, "A?1abc[3-6]" will expand to "A[?u?l]abc[3-6]" */
static char* expand_cplhdr(char *string)
{
	static char out[0x8000];
	unsigned char *s = (unsigned char*)string;
	char *d = out;

	if (!string || !*string)
		return string;

	//fprintf(stderr, "%s(%s)\n", __FUNCTION__, string);
	while (*s && d < &out[sizeof(out) - 2]) {
		if (*s == '\\') {
			*d++ = *s++;
			*d++ = *s++;
		} else
		if (*s == '?' && s[1] >= '1' && s[1] <= '4') {
			char *cs = options.custom_mask[s[1] - '1'];
			if (*cs == '[')
				cs++;
			*d++ = '[';
			while (*cs && d < &out[sizeof(out) - 2]) {
				if (strstr("\\[]-", cs))
					*d++ = '\\';
				*d++ = *cs++;
			}
			if (d[-1] == ']' && d[-2] == '\\') {
				--d;
				d[-1] = ']';
			}
			s += 2;
		} else
			*d++ = *s++;
	}
	*d = '\0';

	//fprintf(stderr, "return: %s\n", out);
	return out;
}

/* Convert a single placeholder like ?l (given as 'l' char arg.) to a string.
   plhdr2string('d', n) will return "0123456789" plus any Unicode oddities */
static char* plhdr2string(char p, int fmt_case)
{
	static char out[256];
	char *s, *o = out;
	int j;

#define add_range(a, b)	for (j = a; j <= b; j++) *o++ = j
#define add_string(str)	for (s = (char*)str; *s; s++) *o++ = *s

	if (pers_opts.internal_enc == ASCII)
	if (p == 'U' || p == 'L') {
		fprintf(stderr, "Can't use ?%c placeholder with "
		        "ASCII encoding\n", p);
		error();
	}

	switch(p) {
	case 'a': /* Printable ASCII */
		if (fmt_case)
			add_range(0x20, 0x7e);
		else {
			add_range(0x20, 0x40);
			add_range(0x5b, 0x7e);
		}
		break;
	case 'l': /* lower-case letters */
		add_range('a', 'z');
	case 'L': /* lower-case non-ASCII only */
		switch (pers_opts.internal_enc) {
		case CP437:
			add_string(CHARS_LOWER_CP437
			           CHARS_LOW_ONLY_CP437);
			break;
		case CP737:
			add_string(CHARS_LOWER_CP737
			           CHARS_LOW_ONLY_CP737);
			break;
		case CP850:
			add_string(CHARS_LOWER_CP850
			           CHARS_LOW_ONLY_CP850);
			break;
		case CP852:
			add_string(CHARS_LOWER_CP852
			           CHARS_LOW_ONLY_CP852);
			break;
		case CP858:
			add_string(CHARS_LOWER_CP858
			           CHARS_LOW_ONLY_CP858);
			break;
		case CP866:
			add_string(CHARS_LOWER_CP866
			           CHARS_LOW_ONLY_CP866);
			break;
		case CP1250:
			add_string(CHARS_LOWER_CP1250
			           CHARS_LOW_ONLY_CP1250);
			break;
		case CP1251:
			add_string(CHARS_LOWER_CP1251
			           CHARS_LOW_ONLY_CP1251);
			break;
		case CP1252:
			add_string(CHARS_LOWER_CP1252
			           CHARS_LOW_ONLY_CP1252);
			break;
		case CP1253:
			add_string(CHARS_LOWER_CP1253
			           CHARS_LOW_ONLY_CP1253);
			break;
		case ISO_8859_1:
			add_string(CHARS_LOWER_ISO_8859_1
			           CHARS_LOW_ONLY_ISO_8859_1);
			break;
		case ISO_8859_2:
			add_string(CHARS_LOWER_ISO_8859_2
			           CHARS_LOW_ONLY_ISO_8859_2);
			break;
		case ISO_8859_7:
			add_string(CHARS_LOWER_ISO_8859_7
			           CHARS_LOW_ONLY_ISO_8859_7);
			break;
		case ISO_8859_15:
			add_string(CHARS_LOWER_ISO_8859_15
			           CHARS_LOW_ONLY_ISO_8859_15);
			break;
		case KOI8_R:
			add_string(CHARS_LOWER_KOI8_R
			           CHARS_LOW_ONLY_KOI8_R);
			break;
		}
		break;
	case 'u': /* upper-case letters */
		add_range('A', 'Z');
	case 'U': /* upper-case non-ASCII only */
		switch (pers_opts.internal_enc) {
		case CP437:
			add_string(CHARS_UPPER_CP437
			           CHARS_UP_ONLY_CP437);
			break;
		case CP737:
			add_string(CHARS_UPPER_CP737
			           CHARS_UP_ONLY_CP737);
			break;
		case CP850:
			add_string(CHARS_UPPER_CP850
			           CHARS_UP_ONLY_CP850);
			break;
		case CP852:
			add_string(CHARS_UPPER_CP852
			           CHARS_UP_ONLY_CP852);
			break;
		case CP858:
			add_string(CHARS_UPPER_CP858
			           CHARS_UP_ONLY_CP858);
			break;
		case CP866:
			add_string(CHARS_UPPER_CP866
			           CHARS_UP_ONLY_CP866);
			break;
		case CP1250:
			add_string(CHARS_UPPER_CP1250
			           CHARS_UP_ONLY_CP1250);
			break;
		case CP1251:
			add_string(CHARS_UPPER_CP1251
			           CHARS_UP_ONLY_CP1251);
			break;
		case CP1252:
			add_string(CHARS_UPPER_CP1252
			           CHARS_UP_ONLY_CP1252);
			break;
		case CP1253:
			add_string(CHARS_UPPER_CP1253
			           CHARS_UP_ONLY_CP1253);
			break;
		case ISO_8859_1:
			add_string(CHARS_UPPER_ISO_8859_1
			           CHARS_UP_ONLY_ISO_8859_1);
			break;
		case ISO_8859_2:
			add_string(CHARS_UPPER_ISO_8859_2
			           CHARS_UP_ONLY_ISO_8859_2);
			break;
		case ISO_8859_7:
			add_string(CHARS_UPPER_ISO_8859_7
			           CHARS_UP_ONLY_ISO_8859_7);
			break;
		case ISO_8859_15:
			add_string(CHARS_UPPER_ISO_8859_15
			           CHARS_UP_ONLY_ISO_8859_15);
			break;
		case KOI8_R:
			add_string(CHARS_UPPER_KOI8_R
			           CHARS_UP_ONLY_KOI8_R);
			break;
		}
		break;
	case 'd': /* digits */
		add_range('0', '9');
		switch (pers_opts.internal_enc) {
		case CP437:
			add_string(CHARS_DIGITS_CP437);
			break;
		case CP737:
			add_string(CHARS_DIGITS_CP737);
			break;
		case CP850:
			add_string(CHARS_DIGITS_CP850);
			break;
		case CP852:
			add_string(CHARS_DIGITS_CP852);
			break;
		case CP858:
			add_string(CHARS_DIGITS_CP858);
			break;
		case CP866:
			add_string(CHARS_DIGITS_CP866);
			break;
		case CP1250:
			add_string(CHARS_DIGITS_CP1250);
			break;
		case CP1251:
			add_string(CHARS_DIGITS_CP1251);
			break;
		case CP1252:
			add_string(CHARS_DIGITS_CP1252);
			break;
		case CP1253:
			add_string(CHARS_DIGITS_CP1253);
			break;
		case ISO_8859_1:
			add_string(CHARS_DIGITS_ISO_8859_1);
			break;
		case ISO_8859_2:
			add_string(CHARS_DIGITS_ISO_8859_2);
			break;
		case ISO_8859_7:
			add_string(CHARS_DIGITS_ISO_8859_7);
			break;
		case ISO_8859_15:
			add_string(CHARS_DIGITS_ISO_8859_15);
			break;
		case KOI8_R:
			add_string(CHARS_DIGITS_KOI8_R);
			break;
		}
		break;
	case 's': /* specials */
		add_range(32, 47);
		add_range(58, 64);
		add_range(91, 96);
		add_range(123, 126);
		switch (pers_opts.internal_enc) {
		case CP437:
			add_string(CHARS_PUNCTUATION_CP437
			           CHARS_SPECIALS_CP437
			           CHARS_WHITESPACE_CP437);
			break;
		case CP737:
			add_string(CHARS_PUNCTUATION_CP737
			           CHARS_SPECIALS_CP737
			           CHARS_WHITESPACE_CP737);
			break;
		case CP850:
			add_string(CHARS_PUNCTUATION_CP850
			           CHARS_SPECIALS_CP850
			           CHARS_WHITESPACE_CP850);
			break;
		case CP852:
			add_string(CHARS_PUNCTUATION_CP852
			           CHARS_SPECIALS_CP852
			           CHARS_WHITESPACE_CP852);
			break;
		case CP858:
			add_string(CHARS_PUNCTUATION_CP858
			           CHARS_SPECIALS_CP858
			           CHARS_WHITESPACE_CP858);
			break;
		case CP866:
			add_string(CHARS_PUNCTUATION_CP866
			           CHARS_SPECIALS_CP866
			           CHARS_WHITESPACE_CP866);
			break;
		case CP1250:
			add_string(CHARS_PUNCTUATION_CP1250
			           CHARS_SPECIALS_CP1250
			           CHARS_WHITESPACE_CP1250);
			break;
		case CP1251:
			add_string(CHARS_PUNCTUATION_CP1251
			           CHARS_SPECIALS_CP1251
			           CHARS_WHITESPACE_CP1251);
			break;
		case CP1252:
			add_string(CHARS_PUNCTUATION_CP1252
			           CHARS_SPECIALS_CP1252
			           CHARS_WHITESPACE_CP1252);
			break;
		case CP1253:
			add_string(CHARS_PUNCTUATION_CP1253
			           CHARS_SPECIALS_CP1253
			           CHARS_WHITESPACE_CP1253);
			break;
		case ISO_8859_1:
			add_string(CHARS_PUNCTUATION_ISO_8859_1
			           CHARS_SPECIALS_ISO_8859_1
			           CHARS_WHITESPACE_ISO_8859_1);
			break;
		case ISO_8859_2:
			add_string(CHARS_PUNCTUATION_ISO_8859_2
			           CHARS_SPECIALS_ISO_8859_2
			           CHARS_WHITESPACE_ISO_8859_2);
			break;
		case ISO_8859_7:
			add_string(CHARS_PUNCTUATION_ISO_8859_7
			           CHARS_SPECIALS_ISO_8859_7
			           CHARS_WHITESPACE_ISO_8859_7);
			break;
		case ISO_8859_15:
			add_string(CHARS_PUNCTUATION_ISO_8859_15
			           CHARS_SPECIALS_ISO_8859_15
			           CHARS_WHITESPACE_ISO_8859_15);
			break;
		case KOI8_R:
			add_string(CHARS_PUNCTUATION_KOI8_R
			           CHARS_SPECIALS_KOI8_R
			           CHARS_WHITESPACE_KOI8_R);
			break;
		}
		break;
	case 'h': /* All high-bit */
		add_range(0x80, 0xff);
		break;
	case 'H': /* All, except 0 (which we can't handle) */
		add_range(0x01, 0xff);
		break;
	case 'A': /* All valid chars in codepage */
		if (fmt_case)
			add_range(0x20, 0x7e);
		else {
			add_range(0x20, 0x40);
			add_range(0x5b, 0x7e);
		}
		switch (pers_opts.internal_enc) {
		case CP437:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP437);
			else
				add_string(CHARS_LOWER_CP437
				           CHARS_LOW_ONLY_CP437);
			add_string(CHARS_DIGITS_CP437
			           CHARS_PUNCTUATION_CP437
			           CHARS_SPECIALS_CP437
			           CHARS_WHITESPACE_CP437);
			break;
		case CP737:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP737);
			else
				add_string(CHARS_LOWER_CP737
				           CHARS_LOW_ONLY_CP737);
			add_string(CHARS_DIGITS_CP737
			           CHARS_PUNCTUATION_CP737
			           CHARS_SPECIALS_CP737
			           CHARS_WHITESPACE_CP737);
			break;
		case CP850:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP850);
			else
				add_string(CHARS_LOWER_CP850
				           CHARS_LOW_ONLY_CP850);
			add_string(CHARS_DIGITS_CP850
			           CHARS_PUNCTUATION_CP850
			           CHARS_SPECIALS_CP850
			           CHARS_WHITESPACE_CP850);
			break;
		case CP852:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP852);
			else
				add_string(CHARS_LOWER_CP852
				           CHARS_LOW_ONLY_CP852);
			add_string(CHARS_DIGITS_CP852
			           CHARS_PUNCTUATION_CP852
			           CHARS_SPECIALS_CP852
			           CHARS_WHITESPACE_CP852);
			break;
		case CP858:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP858);
			else
				add_string(CHARS_LOWER_CP858
				           CHARS_LOW_ONLY_CP858);
			add_string(CHARS_DIGITS_CP858
			           CHARS_PUNCTUATION_CP858
			           CHARS_SPECIALS_CP858
			           CHARS_WHITESPACE_CP858);
			break;
		case CP866:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP866);
			else
				add_string(CHARS_LOWER_CP866
				           CHARS_LOW_ONLY_CP866);
			add_string(CHARS_DIGITS_CP866
			           CHARS_PUNCTUATION_CP866
			           CHARS_SPECIALS_CP866
			           CHARS_WHITESPACE_CP866);
			break;
		case CP1250:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP1250);
			else
				add_string(CHARS_LOWER_CP1250
				           CHARS_LOW_ONLY_CP1250);
			add_string(CHARS_DIGITS_CP1250
			           CHARS_PUNCTUATION_CP1250
			           CHARS_SPECIALS_CP1250
			           CHARS_WHITESPACE_CP1250);
			break;
		case CP1251:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP1251);
			else
				add_string(CHARS_LOWER_CP1251
				           CHARS_LOW_ONLY_CP1251);
			add_string(CHARS_DIGITS_CP1251
			           CHARS_PUNCTUATION_CP1251
			           CHARS_SPECIALS_CP1251
			           CHARS_WHITESPACE_CP1251);
			break;
		case CP1252:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP1252);
			else
				add_string(CHARS_LOWER_CP1252
				           CHARS_LOW_ONLY_CP1252);
			add_string(CHARS_DIGITS_CP1252
			           CHARS_PUNCTUATION_CP1252
			           CHARS_SPECIALS_CP1252
			           CHARS_WHITESPACE_CP1252);
			break;
		case CP1253:
			if (fmt_case)
				add_string(CHARS_ALPHA_CP1253);
			else
				add_string(CHARS_LOWER_CP1253
				           CHARS_LOW_ONLY_CP1253);
			add_string(CHARS_DIGITS_CP1253
			           CHARS_PUNCTUATION_CP1253
			           CHARS_SPECIALS_CP1253
			           CHARS_WHITESPACE_CP1253);
			break;
		case ISO_8859_1:
			if (fmt_case)
				add_string(CHARS_ALPHA_ISO_8859_1);
			else
				add_string(CHARS_LOWER_ISO_8859_1
				           CHARS_LOW_ONLY_ISO_8859_1);
			add_string(CHARS_DIGITS_ISO_8859_1
			           CHARS_PUNCTUATION_ISO_8859_1
			           CHARS_SPECIALS_ISO_8859_1
			           CHARS_WHITESPACE_ISO_8859_1);
			break;
		case ISO_8859_2:
			if (fmt_case)
				add_string(CHARS_ALPHA_ISO_8859_2);
			else
				add_string(CHARS_LOWER_ISO_8859_2
				           CHARS_LOW_ONLY_ISO_8859_2);
			add_string(CHARS_DIGITS_ISO_8859_2
			           CHARS_PUNCTUATION_ISO_8859_2
			           CHARS_SPECIALS_ISO_8859_2
			           CHARS_WHITESPACE_ISO_8859_2);
			break;
		case ISO_8859_7:
			if (fmt_case)
				add_string(CHARS_ALPHA_ISO_8859_7);
			else
				add_string(CHARS_LOWER_ISO_8859_7
				           CHARS_LOW_ONLY_ISO_8859_7);
			add_string(CHARS_DIGITS_ISO_8859_7
			           CHARS_PUNCTUATION_ISO_8859_7
			           CHARS_SPECIALS_ISO_8859_7
			           CHARS_WHITESPACE_ISO_8859_7);
			break;
		case ISO_8859_15:
			if (fmt_case)
				add_string(CHARS_ALPHA_ISO_8859_15);
			else
				add_string(CHARS_LOWER_ISO_8859_15
				           CHARS_LOW_ONLY_ISO_8859_15);
			add_string(CHARS_DIGITS_ISO_8859_15
			           CHARS_PUNCTUATION_ISO_8859_15
			           CHARS_SPECIALS_ISO_8859_15
			           CHARS_WHITESPACE_ISO_8859_15);
			break;
		case KOI8_R:
			if (fmt_case)
				add_string(CHARS_ALPHA_KOI8_R);
			else
				add_string(CHARS_LOWER_KOI8_R
				           CHARS_LOW_ONLY_KOI8_R);
			add_string(CHARS_DIGITS_KOI8_R
			           CHARS_PUNCTUATION_KOI8_R
			           CHARS_SPECIALS_KOI8_R
			           CHARS_WHITESPACE_KOI8_R);
			break;
		default:
			add_range(0x80, 0xff);
		}
		break;
/*
 * Note: To add more cases, also append the symbol to string BUILT_IN_CHARSET.
 */
	default:
		if (john_main_process)
			fprintf(stderr, "Can't nest custom placeholder ?%c.\n",
			        p);
		error();
	}

	*o = '\0';
	return out;
}
#undef add_string

/* Expands all non-custom placeholders in string and returns a new resulting
   string. ?d is expanded to [0123456789] as opposed to [0-9]. If the outer
   brackets are already given, as in [?d], output is still [0123456789] */
static char* expand_plhdr(char *string, int fmt_case)
{
	static char out[0x8000];
	unsigned char *s = (unsigned char*)string;
	char *d = out;

	if (!string || !*string)
		return string;

	//fprintf(stderr, "%s(%s)\n", __FUNCTION__, string);
	if (*s != '[')
		*d++ = '[';
	while (*s && d < &out[sizeof(out) - 1]) {
		if (*s == '\\') {
			*d++ = *s++;
			*d++ = *s++;
		} else
		if (*s == '?' && strchr(BUILT_IN_CHARSET, s[1])) {
			char *ps = plhdr2string(s[1], fmt_case);
			while (*ps && d < &out[sizeof(out) - 2]) {
				if (strchr("\\[]-", *ps))
					*d++ = '\\';
				*d++ = *ps++;
			}
			s += 2;
		} else
			*d++ = *s++;
	}
	if (d[-1] != ']')
		*d++ = ']';
	*d = '\0';

	//fprintf(stderr, "return: %s\n", out);
	return out;
}

/*
 * valid braces:
 * [abcd], [[[[[abcde], []]abcde]]], [[[ab]cdefr]]
 * invalid braces:
 * [[ab][c], parsed as two separate ranges [[ab] and [c]
 * [[ab][, error, sets parse_ok to 0.
 */
static void parse_braces(char *mask, parsed_ctx *parsed_mask)
{

	int i, j ,k;
	int cl_br_enc;

	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		store_cl(i, -1);
		store_op(i, -1);
	}

	j = k = 0;
	while (j < strlen(mask)) {

		for (i = j; i < strlen(mask); i++)
			if (mask[i] == '[' && (!i || mask[i-1] != '\\'))
				break;

		if (i < strlen(mask))
		/* store first opening brace for kth placeholder */
			store_op(k, i);

		i++;

		cl_br_enc = 0;
		for (;i < strlen(mask); i++) {
			if (mask[i] == ']' && (!i || mask[i-1] != '\\')) {
			/* store last closing brace for kth placeholder */
				store_cl(k, i);
				cl_br_enc = 1;
			}
			if (mask[i] == '[' &&
			    (!i || mask[i-1] != '\\') && cl_br_enc)
				break;
		}

		j = i;
		k++;
	}

	parsed_mask->parse_ok = 1;
	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++)
		if ((load_op(i) == -1) ^ (load_cl(i) == -1))
			parsed_mask->parse_ok = 0;
}

/*
 * Stores the valid ? placeholders in a stack_qtn
 * valid:
 * -if outside [] braces and
 * -if ? is immediately followed by the identifier such as
 * ?a for all printable ASCII.
 */
static void parse_qtn(char *mask, parsed_ctx *parsed_mask)
{
	int i, j, k;

	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++)
		parsed_mask->stack_qtn[i] = -1;

	for (i = 0, k = 0; i < strlen(mask); i++) {
		if (mask[i] == '?')
		if (i + 1 < strlen(mask))
		if (strchr(BUILT_IN_CHARSET, mask[i + 1])) {
			j = 0;
			while (load_op(j) != -1 &&
			       load_cl(j) != -1) {
				if (i > load_op(j) &&
				    i < load_cl(j))
					goto cont;
				j++;
			}
			parsed_mask->stack_qtn[k++] = i;
		}
cont:
		;
	}
}

static int search_stack(parsed_ctx *parsed_mask, int loc)
{
	int t;

	for (t = 0; load_op(t) != -1; t++)
		if (load_op(t) <= loc && load_cl(t) >= loc)
			return load_cl(t);

	for (t = 0; load_qtn(t) != -1; t++)
		if (load_qtn(t) == loc)
			return loc + 1;
	return 0;
}

/*
 * Maps the postion of a range in a mask to its actual postion in a key.
 * Offset for wordlist + mask is not taken into account.
 */
static int calc_pos_in_key(char *mask, parsed_ctx *parsed_mask, int mask_loc)
{
	int i, ret_pos;

	i = ret_pos = 0;
	while (i < mask_loc) {
		int t;
		t = search_stack(parsed_mask, i);
		i = t ? t + 1: i + 1;
		ret_pos++;
	}

	return ret_pos;
}

static void init_cpu_mask(char *mask, parsed_ctx *parsed_mask,
                          cpu_mask_context *cpu_mask_ctx, struct db_main *db)
{
	int i, qtn_ctr, op_ctr, cl_ctr;
	char *p;
	int fmt_case = (db->format->params.flags & FMT_CASE);

#define count(i) cpu_mask_ctx->ranges[i].count
#define swap(a, b) { x = a; a = b; b = x; }
#define fill_range() 							\
	if (a > b)							\
		swap(a, b);						\
	for (x = a; x <= b; x++) 					\
		if (!memchr((const char*)cpu_mask_ctx->ranges[i].chars, \
		    x, count(i)))					\
			cpu_mask_ctx->ranges[i].chars[count(i)++] = x;

/* Safe in non-bracketed if/for: The final ';' comes with the invocation */
#define add_string(string)						\
	for (p = (char*)string; *p; p++)				\
		cpu_mask_ctx->ranges[i].chars[count(i)++] = *p

#define set_range_start()						\
	for (j = 0; j < cpu_mask_ctx->ranges[i].count; j++)		\
			if (cpu_mask_ctx->ranges[i].chars[0] + j !=	\
			    cpu_mask_ctx->ranges[i].chars[j])		\
				break;					\
	if (j == cpu_mask_ctx->ranges[i].count)				\
		cpu_mask_ctx->ranges[i].start =				\
			cpu_mask_ctx->ranges[i].chars[0];

	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		cpu_mask_ctx->ranges[i].start =
		cpu_mask_ctx->ranges[i].count =
		cpu_mask_ctx->ranges[i].pos =
		cpu_mask_ctx->ranges[i].iter =
		cpu_mask_ctx->active_positions[i] =
		cpu_mask_ctx->ranges[i].offset = 0;
		cpu_mask_ctx->ranges[i].next = MAX_NUM_MASK_PLHDR;
	}
	cpu_mask_ctx->count = cpu_mask_ctx->offset =
	cpu_mask_ctx->cpu_count = 0;
	cpu_mask_ctx->ps1 = MAX_NUM_MASK_PLHDR;

	qtn_ctr = op_ctr = cl_ctr = 0;
	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		if ((unsigned int)load_op(op_ctr) <
		    (unsigned int)load_qtn(qtn_ctr)) {
#define check_n_insert 						\
	(!memchr((const char*)cpu_mask_ctx->ranges[i].chars,	\
		(int)mask[j], count(i)))			\
		cpu_mask_ctx->ranges[i].chars[count(i)++] = mask[j];
			int j;

			cpu_mask_ctx->
			ranges[i].pos = calc_pos_in_key(mask,
						        parsed_mask,
				                        load_op(op_ctr));

			for (j = load_op(op_ctr) + 1; j < load_cl(cl_ctr);) {
				int a , b;

				if (mask[j] == '\\' &&
				    (!j || mask[j - 1] != '\\')) {
					j++;
					if check_n_insert
				}
				else if (mask[j] == '-' &&
				         j + 1 < load_cl(cl_ctr) &&
				         j - 1 > load_op(op_ctr)) {
					int x;

/* Remove the character mask[j-1] added in previous iteration */
					count(i)--;

					a = mask[j - 1];
					b = mask[j + 1];

					fill_range();

					j++;
				}
				else if check_n_insert

				j++;
			}

			set_range_start();

			op_ctr++;
			cl_ctr++;
			cpu_mask_ctx->count++;
#undef check_n_insert
		}
		else if ((unsigned int)load_op(op_ctr) >
		         (unsigned int)load_qtn(qtn_ctr))  {
			int j;

			cpu_mask_ctx->
			ranges[i].pos = calc_pos_in_key(mask,
							parsed_mask,
							load_qtn(qtn_ctr));

			add_string(plhdr2string(mask[load_qtn(qtn_ctr) + 1],
			                        fmt_case));
			set_range_start();

			qtn_ctr++;
			cpu_mask_ctx->count++;
		}
	}
#undef count
#undef swap
#undef fill_range
	for (i = 0; i < cpu_mask_ctx->count - 1; i++) {
		cpu_mask_ctx->ranges[i].next = i + 1;
		cpu_mask_ctx->active_positions[i] = 1;
	}
	cpu_mask_ctx->ranges[i].next = MAX_NUM_MASK_PLHDR;
	cpu_mask_ctx->active_positions[i] = 1;
}

/*
 * Returns the template of the keys corresponding to the mask.
 */
static char* generate_template_key(char *mask, const char *key,
				   parsed_ctx *parsed_mask,
				   cpu_mask_context *cpu_mask_ctx)
{
	int i, k, t, j, l, offset = 0;
	i = 0, k = 0, j = 0, l = 0;

	while (template_key_offsets[l] != -1)
		template_key_offsets[l++] = -1;

	l = 0;
	while (i < strlen(mask)) {
		if ((t = search_stack(parsed_mask, i))){
			template_key[k++] = '#';
			i = t + 1;
			cpu_mask_ctx->ranges[j++].offset = offset;
		}
		else if (key != NULL && mask[i + 1] == 'w' && mask[i] == '?') {
			template_key_offsets[l++] = k;
			/* Subtract 2 to account for '?w' in mask.*/
			offset += (strlen(key) - 2);
			k += strlen(key);
			i += 2;
		}
		else
			template_key[k++] = mask[i++];
	}
	template_key[k] = '\0';

	return template_key;
}

/* Handle internal encoding. */
static MAYBE_INLINE char* mask_cp_to_utf8(char *in)
{
	static char out[PLAINTEXT_BUFFER_SIZE + 1];

	if (pers_opts.internal_enc != UTF_8 &&
	    pers_opts.internal_enc != pers_opts.target_enc)
		return cp_to_utf8_r(in, out, PLAINTEXT_BUFFER_SIZE);

	return in;
}

static int generate_keys(cpu_mask_context *cpu_mask_ctx,
			  unsigned long long *my_candidates)
{
	int ps1 = MAX_NUM_MASK_PLHDR, ps2 = MAX_NUM_MASK_PLHDR,
	    ps3 = MAX_NUM_MASK_PLHDR, ps4 = MAX_NUM_MASK_PLHDR, ps ;
	int start1, start2, start3, start4;

#define ranges(i) cpu_mask_ctx->ranges[i]

#define process_key(key)						\
	if (ext_filter(template_key))					\
		if ((crk_process_key(mask_cp_to_utf8(template_key))))   \
			return 1;
/*
 * Calculate next state of remaing placeholders, working
 * similar to counters.
 */
#define next_state(ps)							\
	while(1) {							\
		if (ps == MAX_NUM_MASK_PLHDR) goto done;		\
		if ((++(ranges(ps).iter)) == ranges(ps).count) {	\
			ranges(ps).iter = 0;				\
			template_key[ranges(ps).pos + ranges(ps).offset] =		\
			ranges(ps).chars[ranges(ps).iter];		\
			ps = ranges(ps).next;				\
		}							\
		else {							\
			template_key[ranges(ps).pos + ranges(ps).offset] =		\
			      ranges(ps).chars[ranges(ps).iter];	\
			break;						\
		}							\
	}

#define init_key(ps)							\
	while (ps != MAX_NUM_MASK_PLHDR) {				\
		template_key[ranges(ps).pos + ranges(ps).offset] =			\
		ranges(ps).chars[ranges(ps).iter];			\
		ps = ranges(ps).next;					\
	}

#define iterate_over(ps)						\
	;ranges(ps).iter < ranges(ps).count; ranges(ps).iter++

#define set_template_key(ps, start)					\
	template_key[ranges(ps).pos + ranges(ps).offset] =				\
		start ? start + ranges(ps).iter:			\
		ranges(ps).chars[ranges(ps).iter];

	ps1 = cpu_mask_ctx->ps1;
	ps2 = cpu_mask_ctx->ranges[ps1].next;
	ps3 = cpu_mask_ctx->ranges[ps2].next;
	ps4 = cpu_mask_ctx->ranges[ps3].next;

	if (cpu_mask_ctx->cpu_count < 4) {
		ps = ps1;

		/* Initialize the placeholders */
		init_key(ps);

		while (1) {
			if (options.node_count &&
			    !(options.flags & FLG_MASK_STACKED) &&
			    !(*my_candidates)--)
				goto done;

			process_key(template_key);
			ps = ps1;
			next_state(ps);
		}
	}

	else if (cpu_mask_ctx->cpu_count >= 4) {
		ps = ranges(ps4).next;

	/* Initialize the reaming placeholders other than the first four */
		init_key(ps);

		while (1) {
			start1 = ranges(ps1).start;
			start2 = ranges(ps2).start;
			start3 = ranges(ps3).start;
			start4 = ranges(ps4).start;
			/* Iterate over first three placeholders */
			for (iterate_over(ps4)) {
				set_template_key(ps4, start4);
				for (iterate_over(ps3)) {
					set_template_key(ps3, start3);
					for (iterate_over(ps2)) {
						set_template_key(ps2, start2);
						for (iterate_over(ps1)) {
							if (options.node_count &&
							    !(options.flags & FLG_MASK_STACKED) &&
							    !(*my_candidates)--)
								goto done;
							set_template_key(ps1, start1);
							process_key(template_key);
						}
					ranges(ps1).iter = 0;
					}
				ranges(ps2).iter = 0;
				}
			ranges(ps3).iter = 0;
			}
			ranges(ps4).iter = 0;
			ps = ranges(ps4).next;
			next_state(ps);
		}
	}
done:
	return 0;
#undef ranges
#undef process_key
#undef next_state
#undef init_key
#undef iterate_over
#undef set_template_key
}

/* Skips iteration for postions stored in arr */
static void skip_position(cpu_mask_context *cpu_mask_ctx, int *arr)
{
	int i;

	if (arr != NULL) {
		int k = 0;
		while (arr[k] >= 0 && arr[k] < cpu_mask_ctx->count) {
			int j, i, flag1 = 0, flag2 = 0;
			cpu_mask_ctx->active_positions[arr[k]] = 0;
			cpu_mask_ctx->ranges[arr[k]].next = MAX_NUM_MASK_PLHDR;

			for (j = arr[k] - 1; j >= 0; j--)
				if ((int)(cpu_mask_ctx->active_positions[j])) {
					flag1 = 1;
					break;
				}

			for (i = arr[k] + 1; i < cpu_mask_ctx->count; i++)
				if ((int)(cpu_mask_ctx->active_positions[i])) {
					flag2 = 1;
					break;
				}

			if (flag1)
				cpu_mask_ctx->ranges[j].next =
					flag2?i:MAX_NUM_MASK_PLHDR;
			k++;
		}
	}

	cpu_mask_ctx->cpu_count = 0;
	cpu_mask_ctx->ps1 = MAX_NUM_MASK_PLHDR;
	for (i = 0; i < cpu_mask_ctx->count; i++)
		if ((int)(cpu_mask_ctx->active_positions[i])) {
			if (!cpu_mask_ctx->cpu_count)
				cpu_mask_ctx->ps1 = i;
			cpu_mask_ctx->cpu_count++;
		}
}

static double get_progress(void)
{
	double try;

	emms();

	try = ((unsigned long long)status.cands.hi << 32) + status.cands.lo;

	if (!mask_tot_cand)
		return -1;

	return 100.0 * try / (double)mask_tot_cand;
}

void mask_save_state(FILE *file)
{
	int i;

	fprintf(file, "%llu\n", rec_cand + 1);
	fprintf(file, "%d\n", rec_ctx.count);
	fprintf(file, "%d\n", rec_ctx.offset);
	for (i = 0; i < rec_ctx.count; i++)
		fprintf(file, "%hhu\n", rec_ctx.ranges[i].iter);
}

int mask_restore_state(FILE *file)
{
	int i, d;
	unsigned char uc;
	unsigned long long ull;
	int fail = !(options.flags & FLG_MASK_STACKED);

	if (fscanf(file, "%llu\n", &ull) == 1)
		cand = ull;
	else
		return fail;

	if (fscanf(file, "%d\n", &d) == 1)
		cpu_mask_ctx.count = d;
	else
		return fail;

	if (fscanf(file, "%d\n", &d) == 1)
		cpu_mask_ctx.offset = d;
	else
		return fail;

	for (i = 0; i < cpu_mask_ctx.count; i++)
	if (fscanf(file, "%hhu\n", &uc) == 1)
		cpu_mask_ctx.ranges[i].iter = uc;
	else
		return fail;

	return 0;
}

void mask_fix_state(void)
{
	int i;

	rec_cand = cand;
	rec_ctx.count = cpu_mask_ctx.count;
	rec_ctx.offset = cpu_mask_ctx.offset;
	for (i = 0; i < rec_ctx.count; i++)
		rec_ctx.ranges[i].iter = cpu_mask_ctx.ranges[i].iter;
}

static unsigned long long divide_work(cpu_mask_context *cpu_mask_ctx)
{
	unsigned long long offset, my_candidates, total_candidates, ctr;
	int i;
	double fract;

	fract = (double)(options.node_max - options.node_min + 1) /
		options.node_count;

	offset = 1;
	for (i = 0; i < cpu_mask_ctx->count; i++)
		if ((int)(cpu_mask_ctx->active_positions[i]))
			offset *= cpu_mask_ctx->ranges[i].count;

	total_candidates = offset;
	offset *= fract;
	my_candidates = offset;
	offset = my_candidates * (options.node_min - 1);

	if (options.node_max == options.node_count)
		my_candidates = total_candidates - offset;

	if (!my_candidates) {
		if (john_main_process)
			fprintf(stderr, "Insufficient work. Cannot distribute "
			        "work among nodes!\n");
		error();
	}

	ctr = 1;
	for (i = 0; i < cpu_mask_ctx->count; i++)
	if ((int)(cpu_mask_ctx->active_positions[i])) {
		cpu_mask_ctx->ranges[i].iter = (offset / ctr) %
			cpu_mask_ctx->ranges[i].count;
		ctr *= cpu_mask_ctx->ranges[i].count;
	}

	return my_candidates;
}

void mask_init(struct db_main *db, char *unprocessed_mask)
{
	int i, ctr = 0;

#ifdef MASK_DEBUG
	fprintf(stderr, "%s(%s)\n", __FUNCTION__, unprocessed_mask);
#endif
	mask = unprocessed_mask;
	template_key = (char*)mem_alloc(0x400);

	/* We do not yet support min/max-len */
	if (options.force_minlength >= 0 || options.force_maxlength) {
		if (john_main_process)
			fprintf(stderr, "Mask mode: --min-length and "
			        "--max-length currently not supported\n");
		error();
	}

	log_event("Proceeding with mask mode");

	/* Load defaults from john.conf */
	if (!options.mask &&
	    !(options.mask = cfg_get_param("Mask", NULL, "DefaultMask")))
		options.mask = "";
	if (!options.custom_mask[0] &&
	    !(options.custom_mask[0] = cfg_get_param("Mask", NULL, "1")))
		options.custom_mask[0] = "";
	if (!options.custom_mask[1] &&
	    !(options.custom_mask[1] = cfg_get_param("Mask", NULL, "2")))
		options.custom_mask[1] = "";
	if (!options.custom_mask[2] &&
	    !(options.custom_mask[2] = cfg_get_param("Mask", NULL, "3")))
		options.custom_mask[2] = "";
	if (!options.custom_mask[3] &&
	    !(options.custom_mask[3] = cfg_get_param("Mask", NULL, "4")))
		options.custom_mask[3] = "";

	/* Handle command-line arguments given in UTF-8 */
	if (pers_opts.input_enc == UTF_8 && pers_opts.internal_enc != UTF_8) {
		if (valid_utf8((UTF8*)mask) > 1)
			utf8_to_cp_r(mask, mask, strlen(mask));
		for (i = 0; i < 4; i++)
		if (valid_utf8((UTF8*)options.custom_mask[i]) > 1)
			utf8_to_cp_r(options.custom_mask[i],
			             options.custom_mask[i],
			             strlen(options.custom_mask[i]));
	}

	/* De-hexify mask and custom placeholders */
	parse_hex(mask);
	for (i = 0; i < 4; i++)
		parse_hex(options.custom_mask[i]);

	/* Expand static placeholders within custom ones */
	for (i = 0; i < 4; i++)
		options.custom_mask[i] =
			str_alloc_copy(expand_plhdr(options.custom_mask[i],
				db->format->params.flags & FMT_CASE));

	/* Finally expand custom placeholders ?1 .. ?4 */
	mask = expand_cplhdr(mask);

#ifdef MASK_DEBUG
	fprintf(stderr, "Custom masks expanded (this is 'mask' when passed to "
	        "init_cpu_mask()):\n%s\n", mask);
#endif

	/* Parse ranges */
	parse_braces(mask, &parsed_mask);

	if (parsed_mask.parse_ok)
		parse_qtn(mask, &parsed_mask);
	else {
		if (john_main_process)
			fprintf(stderr, "Parsing unsuccessful\n");
		error();
	}

	i = 0;
	while (i < strlen(mask)) {
		if (i + 1 < strlen(mask) && mask[i] == '?' && mask[i + 1] == 'w') {
			ctr++;
			i += 2;
		}
		else
			i++;
	}

	ctr++;
	template_key_offsets = (int*)mem_alloc(ctr * sizeof(int));

	for (i = 0; i < ctr; i++)
		template_key_offsets[i] = -1;

	init_cpu_mask(mask, &parsed_mask, &cpu_mask_ctx, db);

	/*
	 * Warning: NULL to be replaced by an array containing information
	 * regarding GPU portion of mask.
	 */
	skip_position(&cpu_mask_ctx, NULL);

	/* If running hybrid (stacked), we let the parent mode distribute */
	if (options.node_count && !(options.flags & FLG_MASK_STACKED))
		cand = divide_work(&cpu_mask_ctx);
	else {
		cand = 1;
		for (i = 0; i < cpu_mask_ctx.count; i++)
			if ((int)(cpu_mask_ctx.active_positions[i]))
				cand *= cpu_mask_ctx.ranges[i].count;
	}
	mask_tot_cand = cand;

	if (!(options.flags & FLG_MASK_STACKED)) {
		status_init(get_progress, 0);

		rec_restore_mode(mask_restore_state);
		rec_init(db, mask_save_state);

		crk_init(db, mask_fix_state, NULL);
	}
}

void mask_done()
{
	MEM_FREE(template_key);
	MEM_FREE(template_key_offsets);

	if (!(options.flags & FLG_MASK_STACKED)) {
		// For reporting DONE regardless of rounding errors
		if (!event_abort)
			cand =
				((unsigned long long)status.cands.hi << 32) +
				status.cands.lo;

		crk_done();

		rec_done(event_abort);
	}
}

int do_mask_crack(const char *key)
{
	int i;
	static int old_keylen = -1;
	int key_len = key ? strlen(key) : 0;

#ifdef MASK_DEBUG
	fprintf(stderr, "%s(%s)\n", __FUNCTION__, key);
#endif

	if (old_keylen != key_len) {
		generate_template_key(mask, key, &parsed_mask, &cpu_mask_ctx);
		old_keylen = key_len;
	}

	i = 0;
	while(template_key_offsets[i] != -1)
		memcpy(template_key + template_key_offsets[i++], key, key_len);

	if (generate_keys(&cpu_mask_ctx, &cand))
		return 1;

	if (!event_abort && (options.flags & FLG_MASK_STACKED))
		crk_fix_state();

	return event_abort;
}

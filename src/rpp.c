/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2006,2009,2010,2011,2013 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "config.h"
#include "rpp.h"
#include "common.h"
#include "options.h"
#include "encoding_data.h"
#include "memdbg.h"

int rpp_init(struct rpp_context *ctx, char *subsection)
{
	struct cfg_list *list;

	if ((list = cfg_get_list(SECTION_RULES, subsection)))
	if ((ctx->input = list->head)) {
		ctx->count = -1;
		return 0;
	}

	return 1;
}

void rpp_init_mask(struct rpp_context *ctx, char *mask)
{
	ctx->input = &ctx->dummy_list_entry;
	ctx->input->data = mask;
	ctx->input->next = NULL;
	ctx->count = -1;
}

static void rpp_add_char(struct rpp_range *range, unsigned char c)
{
	if (range->flag_r) {
		if (range->count >= 0x100) return;
	} else {
		int index = c / ARCH_BITS;
		ARCH_WORD mask = (ARCH_WORD)1 << (c % ARCH_BITS);

		if (range->mask[index] & mask) return;

		range->mask[index] |= mask;
	}

	range->chars[range->count++] = (char)c;
}

void rpp_process_rule(struct rpp_context *ctx)
{
	struct rpp_range *range;
	unsigned char *input, *output, *end;
	unsigned char *saved_input;
	unsigned char c1, c2, c;
	int flag_p, flag_r;

	input = (unsigned char *)ctx->input->data;
	output = (unsigned char *)ctx->output;
	end = output + RULE_BUFFER_SIZE - 1;
	flag_p = flag_r = 0;
	ctx->count = ctx->refs_count = 0;

	saved_input = NULL;

	while (*input && output < end)
	switch (*input) {
	case '\\':
		if (!(c = *++input)) break;
		c1 = ctx->count ? '0' : '1';
		c2 = (ctx->count <= 9) ? '0' + ctx->count : '9';
		if (c >= c1 && c <= c2 && ctx->refs_count < RULE_RANGES_MAX) {
			struct rpp_ref *ref = &ctx->refs[ctx->refs_count++];
			ref->pos = (char *)output;
			ref->range = (c == '0') ? ctx->count - 1 : c - '1';
		}
		input++;
		if (ctx->count < RULE_RANGES_MAX)
		switch (c) {
		case 'p':
			if ((c2 = *input) == '[' || c2 == '\\') {
				flag_p = -1;
				break;
			} else if (c2 >= '0' && c2 <= '9') {
				flag_p = (c2 == '0') ? ctx->count : c2 - '0';
				input++;
				break;
			}
			*output++ = c;
			break;
		case 'r':
			if (*input == '[' || *input == '\\') {
				flag_r = 1;
				break;
			}
			/* fall through */
		default:
			if (c == 'x' && atoi16[*input] != 0x7f &&
			    atoi16[input[1]] != 0x7f) {
				// handle hex char
				*output++ =
					((atoi16[*input]<<4)+atoi16[input[1]]);
				input += 2;
			} else
				*output++ = c;
		}
		break;

	case '?':
		if (ctx->input != &ctx->dummy_list_entry) /* not mask mode */
			goto not_mask;
		if (*++input == '?')
			goto not_mask;
		saved_input = input + 1;
		switch (*input) {
		case 'l':
			switch (pers_opts.target_enc) {
			case CP437:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP437
					CHARS_LOW_ONLY_CP437
					"]";
				break;
			case CP737:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP737
					CHARS_LOW_ONLY_CP737
					"]";
				break;
			case CP850:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP850
					CHARS_LOW_ONLY_CP850
					"]";
				break;
			case CP852:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP852
					CHARS_LOW_ONLY_CP852
					"]";
				break;
			case CP858:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP858
					CHARS_LOW_ONLY_CP858
					"]";
				break;
			case CP866:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP866
					CHARS_LOW_ONLY_CP866
					"]";
				break;
			case CP1250:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP1250
					CHARS_LOW_ONLY_CP1250
					"]";
				break;
			case CP1251:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP1251
					CHARS_LOW_ONLY_CP1251
					"]";
				break;
			case CP1252:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP1252
					CHARS_LOW_ONLY_CP1252
					"]";
				break;
			case CP1253:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_CP1253
					CHARS_LOW_ONLY_CP1253
					"]";
				break;
			case ISO_8859_1:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_ISO_8859_1
					CHARS_LOW_ONLY_ISO_8859_1
					"]";
				break;
			case ISO_8859_2:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_ISO_8859_2
					CHARS_LOW_ONLY_ISO_8859_2
					"]";
				break;
			case ISO_8859_7:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_ISO_8859_7
					CHARS_LOW_ONLY_ISO_8859_7
					"]";
				break;
			case ISO_8859_15:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_ISO_8859_15
					CHARS_LOW_ONLY_ISO_8859_15
					"]";
				break;
			case KOI8_R:
				input = (unsigned char *)"[a-z"
					CHARS_LOWER_KOI8_R
					CHARS_LOW_ONLY_KOI8_R
					"]";
				break;
			default:
				input = (unsigned char *)"[a-z]";
			}
			break;
		case 'u':
			switch (pers_opts.target_enc) {
			case CP437:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP437
					CHARS_UP_ONLY_CP437
					"]";
				break;
			case CP737:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP737
					CHARS_UP_ONLY_CP737
					"]";
				break;
			case CP850:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP850
					CHARS_UP_ONLY_CP850
					"]";
				break;
			case CP852:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP852
					CHARS_UP_ONLY_CP852
					"]";
				break;
			case CP858:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP858
					CHARS_UP_ONLY_CP858
					"]";
				break;
			case CP866:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP866
					CHARS_UP_ONLY_CP866
					"]";
				break;
			case CP1250:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP1250
					CHARS_UP_ONLY_CP1250
					"]";
				break;
			case CP1251:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP1251
					CHARS_UP_ONLY_CP1251
					"]";
				break;
			case CP1252:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP1252
					CHARS_UP_ONLY_CP1252
					"]";
				break;
			case CP1253:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_CP1253
					CHARS_UP_ONLY_CP1253
					"]";
				break;
			case ISO_8859_1:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_ISO_8859_1
					CHARS_UP_ONLY_ISO_8859_1
					"]";
				break;
			case ISO_8859_2:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_ISO_8859_2
					CHARS_UP_ONLY_ISO_8859_2
					"]";
				break;
			case ISO_8859_7:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_ISO_8859_7
					CHARS_UP_ONLY_ISO_8859_7
					"]";
				break;
			case ISO_8859_15:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_ISO_8859_15
					CHARS_UP_ONLY_ISO_8859_15
					"]";
				break;
			case KOI8_R:
				input = (unsigned char *)"[A-Z"
					CHARS_UPPER_KOI8_R
					CHARS_UP_ONLY_KOI8_R
					"]";
				break;
			default:
				input = (unsigned char *)"[A-Z]";
			}
			break;
		case 'd':
			switch (pers_opts.target_enc) {
			case CP437:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP437 "]";
				break;
			case CP737:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP737 "]";
				break;
			case CP850:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP850 "]";
				break;
			case CP852:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP852 "]";
				break;
			case CP858:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP858 "]";
				break;
			case CP866:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP866 "]";
				break;
			case CP1250:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP1250 "]";
				break;
			case CP1251:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP1251 "]";
				break;
			case CP1252:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP1252 "]";
				break;
			case CP1253:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_CP1253 "]";
				break;
			case ISO_8859_1:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_ISO_8859_1 "]";
				break;
			case ISO_8859_2:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_ISO_8859_2 "]";
				break;
			case ISO_8859_7:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_ISO_8859_7 "]";
				break;
			case ISO_8859_15:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_ISO_8859_15 "]";
				break;
			case KOI8_R:
				input = (unsigned char *)"[0-9"
					CHARS_DIGITS_KOI8_R "]";
				break;
			default:
				input = (unsigned char *)"[0-9]";
			}
			break;
		case 's':
			switch (pers_opts.target_enc) {
			case CP437:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP437
					CHARS_SPECIALS_CP437
					CHARS_WHITESPACE_CP437 "]";
				break;
			case CP737:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP737
					CHARS_SPECIALS_CP737
					CHARS_WHITESPACE_CP737 "]";
				break;
			case CP850:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP850
					CHARS_SPECIALS_CP850
					CHARS_WHITESPACE_CP850 "]";
				break;
			case CP852:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP852
					CHARS_SPECIALS_CP852
					CHARS_WHITESPACE_CP852 "]";
				break;
			case CP858:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP858
					CHARS_SPECIALS_CP858
					CHARS_WHITESPACE_CP858 "]";
				break;
			case CP866:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP866
					CHARS_SPECIALS_CP866
					CHARS_WHITESPACE_CP866 "]";
				break;
			case CP1250:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP1250
					CHARS_SPECIALS_CP1250
					CHARS_WHITESPACE_CP1250 "]";
				break;
			case CP1251:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP1251
					CHARS_SPECIALS_CP1251
					CHARS_WHITESPACE_CP1251 "]";
				break;
			case CP1252:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP1252
					CHARS_SPECIALS_CP1252
					CHARS_WHITESPACE_CP1252 "]";
				break;
			case CP1253:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_CP1253
					CHARS_SPECIALS_CP1253
					CHARS_WHITESPACE_CP1253 "]";
				break;
			case ISO_8859_1:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_ISO_8859_1
					CHARS_SPECIALS_ISO_8859_1
					CHARS_WHITESPACE_ISO_8859_1 "]";
				break;
			case ISO_8859_2:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_ISO_8859_2
					CHARS_SPECIALS_ISO_8859_2
					CHARS_WHITESPACE_ISO_8859_2 "]";
				break;
			case ISO_8859_7:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_ISO_8859_7
					CHARS_SPECIALS_ISO_8859_7
					CHARS_WHITESPACE_ISO_8859_7 "]";
				break;
			case ISO_8859_15:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_ISO_8859_15
					CHARS_SPECIALS_ISO_8859_15
					CHARS_WHITESPACE_ISO_8859_15 "]";
				break;
			case KOI8_R:
				input = (unsigned char *)"[ -/:-@[-`{-~"
					CHARS_PUNCTUATION_KOI8_R
					CHARS_SPECIALS_KOI8_R
					CHARS_WHITESPACE_KOI8_R "]";
				break;
			default:
				input = (unsigned char *)"[ -/:-@[-`{-~]";
			}
			break;
		case 'h':
			input = (unsigned char *)"[\x80-\xff]";
			break;
		case 'H':
			input = (unsigned char *)"[\x01-\xff]";
			break;
		case 'a':
			input = (unsigned char *)"[ -~]";
			break;
		case 'A':
			switch (pers_opts.target_enc) {
			case CP437:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_CP437
					CHARS_DIGITS_CP437
					CHARS_PUNCTUATION_CP437
					CHARS_SPECIALS_CP437
					CHARS_WHITESPACE_CP437 "]";
				break;
			case CP737:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_CP737
					CHARS_DIGITS_CP737
					CHARS_PUNCTUATION_CP737
					CHARS_SPECIALS_CP737
					CHARS_WHITESPACE_CP737 "]";
				break;
			case CP850:
				input = (unsigned char *)"[\x20-\x7f"
					CHARS_ALPHA_CP850
					CHARS_DIGITS_CP850
					CHARS_PUNCTUATION_CP850
					CHARS_SPECIALS_CP850
					CHARS_WHITESPACE_CP850 "]";
				break;
			case CP852:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_CP852
					CHARS_DIGITS_CP852
					CHARS_PUNCTUATION_CP852
					CHARS_SPECIALS_CP852
					CHARS_WHITESPACE_CP852 "]";
				break;
			case CP858:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_CP858
					CHARS_DIGITS_CP858
					CHARS_PUNCTUATION_CP858
					CHARS_SPECIALS_CP858
					CHARS_WHITESPACE_CP858 "]";
				break;
			case CP866:
				input = (unsigned char *)"[\x20-\x7f"
					CHARS_ALPHA_CP866
					CHARS_DIGITS_CP866
					CHARS_PUNCTUATION_CP866
					CHARS_SPECIALS_CP866
					CHARS_WHITESPACE_CP866 "]";
				break;
			case CP1250:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_CP1250
					CHARS_DIGITS_CP1250
					CHARS_PUNCTUATION_CP1250
					CHARS_SPECIALS_CP1250
					CHARS_WHITESPACE_CP1250 "]";
				break;
			case CP1251:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_CP1251
					CHARS_DIGITS_CP1251
					CHARS_PUNCTUATION_CP1251
					CHARS_SPECIALS_CP1251
					CHARS_WHITESPACE_CP1251 "]";
				break;
			case CP1252:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_CP1252
					CHARS_DIGITS_CP1252
					CHARS_PUNCTUATION_CP1252
					CHARS_SPECIALS_CP1252
					CHARS_WHITESPACE_CP1252 "]";
				break;
			case CP1253:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_CP1253
					CHARS_DIGITS_CP1253
					CHARS_PUNCTUATION_CP1253
					CHARS_SPECIALS_CP1253
					CHARS_WHITESPACE_CP1253 "]";
				break;
			case ISO_8859_1:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_ISO_8859_1
					CHARS_DIGITS_ISO_8859_1
					CHARS_PUNCTUATION_ISO_8859_1
					CHARS_SPECIALS_ISO_8859_1
					CHARS_WHITESPACE_ISO_8859_1 "]";
				break;
			case ISO_8859_2:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_ISO_8859_2
					CHARS_DIGITS_ISO_8859_2
					CHARS_PUNCTUATION_ISO_8859_2
					CHARS_SPECIALS_ISO_8859_2
					CHARS_WHITESPACE_ISO_8859_2 "]";
				break;
			case ISO_8859_7:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_ISO_8859_7
					CHARS_DIGITS_ISO_8859_7
					CHARS_PUNCTUATION_ISO_8859_7
					CHARS_SPECIALS_ISO_8859_7
					CHARS_WHITESPACE_ISO_8859_7 "]";
				break;
			case ISO_8859_15:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_ISO_8859_15
					CHARS_DIGITS_ISO_8859_15
					CHARS_PUNCTUATION_ISO_8859_15
					CHARS_SPECIALS_ISO_8859_15
					CHARS_WHITESPACE_ISO_8859_15 "]";
				break;
			case KOI8_R:
				input = (unsigned char *)"[ -"
					CHARS_ALPHA_KOI8_R
					CHARS_DIGITS_KOI8_R
					CHARS_PUNCTUATION_KOI8_R
					CHARS_SPECIALS_KOI8_R
					CHARS_WHITESPACE_KOI8_R "]";
				break;
			default:
				input = (unsigned char *)"[\x20-\xff]";
			}
			break;
		default:
			saved_input = NULL;
			input--;
			goto not_mask;
		}

	case '[':
		if (ctx->count >= RULE_RANGES_MAX) {
			if (saved_input) {
				input = saved_input - 2;
				saved_input = NULL;
			}
			*output++ = *input++;
			break;
		}
		input++;

		range = &ctx->ranges[ctx->count++];
		range->pos = (char *)output++;
		range->index = range->count = 0;
		range->flag_p = flag_p; flag_p = 0;
		range->flag_r = flag_r; flag_r = 0;
		memset(range->mask, 0, sizeof(range->mask));
		range->chars[0] = 0;

		c1 = 0;
		while (*input && *input != ']')
		switch (*input) {
		case '\\':
			if (input[1] == 'x' && atoi16[input[2]] != 0x7F &&
			    atoi16[input[3]] != 0x7F) {
				rpp_add_char(range,
				             c1 = ((atoi16[input[2]]<<4) +
				                   atoi16[input[3]]));
				input += 4;
			} else
				if (*++input) rpp_add_char(range,
				                           c1 = *input++);
			break;

		case '-':
			if ((c2 = *++input)) {
				input++;
				if (c2 == '\\') {
					if (input[0] == 'x' &&
					    atoi16[input[1]] != 0x7F &&
					    atoi16[input[2]] != 0x7F) {
						c2 = ((atoi16[input[1]]<<4) +
						      atoi16[input[2]]);
						input += 3;
					}
				}
				if (c1 && range->count) {
					if (c1 > c2)
						for (c = c1 - 1; c >= c2; c--)
						rpp_add_char(range, c);
					else
						for (c = c1; c < c2; c++)
						rpp_add_char(range, c + 1);
				}
			}
			c1 = c2;
			break;

		default:
			rpp_add_char(range, c1 = *input++);
		}
		if (*input) input++;

		if (saved_input) {
			input = saved_input;
			saved_input = NULL;
		}
		break;

	default:
not_mask:
		*output++ = *input++;
	}

	*output = 0;
}

char *rpp_next(struct rpp_context *ctx)
{
	struct rpp_range *range;
	int index, done;

	if (ctx->count < 0) {
		if (!ctx->input) return NULL;
		rpp_process_rule(ctx);
	}

	done = 1;
	if ((index = ctx->count - 1) >= 0) {
		do {
			range = &ctx->ranges[index];
			*range->pos = range->chars[range->index];
		} while (index--);

		index = ctx->count - 1;
		do {
			range = &ctx->ranges[index];
			if (range->flag_p > 0)
				continue;
			if (++range->index < range->count) {
				if (range->flag_p)
					continue;
				else
					break;
			}
			range->index = 0;
		} while (index--);

		done = index < 0;

		index = ctx->count - 1;
		do {
			range = &ctx->ranges[index];
			if (range->flag_p <= 0 || range->flag_p > ctx->count)
				continue;
			if (ctx->ranges[range->flag_p - 1].flag_p)
				continue; /* don't bother to support this */
			range->index = ctx->ranges[range->flag_p - 1].index;
			if (range->index >= range->count)
				range->index = range->count - 1;
		} while (index--);
	}

	if (ctx->refs_count > 0) {
		int ref_index = ctx->refs_count - 1;
		do {
			index = ctx->refs[ref_index].range;
			if (index < ctx->count) {
				range = &ctx->ranges[index];
				*ctx->refs[ref_index].pos = *range->pos;
			}
		} while (ref_index--);
	}

	if (done) {
		ctx->input = ctx->input->next;
		ctx->count = -1;
	}

	return ctx->output;
}

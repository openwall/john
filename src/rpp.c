/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2006,2009,2010,2011 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "config.h"
#include "rpp.h"
#include "logger.h"
#include "common.h" /* for atoi16 */
#include "misc.h"   /* for strtokm */
#include "options.h"
#include "unicode.h"

int rpp_real_run = 0;

int rpp_init(struct rpp_context *ctx, const char *subsection)
{
	struct cfg_list *list;

	ctx->refs_count = 0;
	if (*subsection == ':') {
		char *p, *buf;
		const int sz = sizeof(struct cfg_line), al = sizeof(struct cfg_line *);
		struct cfg_line *cfg_cur = mem_calloc_tiny(sz, al);

		buf = str_alloc_copy(subsection+1);
		cfg_cur->cfg_name = "Command Line Rule";
		cfg_cur->data = buf;
		ctx->input = cfg_cur;
		p = strchr(buf, ';');
		while (p && p > buf && p[-1] == '\\')
			p = strchr(p+1, ';');
		while (p && *p) {
			*p++ = 0;
			if (!p[0]) continue;
			cfg_cur->next = mem_calloc_tiny(sz, al);
			cfg_cur = cfg_cur->next;
			cfg_cur->cfg_name = "Command Line Rule";
			cfg_cur->data = p;
			p = strchr(p, ';');
			while (p && p > buf && p[-1] == '\\')
				p = strchr(p+1, ';');
		}
		ctx->count = -1;
		return 0;
	} else if (strchr(subsection, ',')) {
		char *buf = str_alloc_copy(subsection), *cp;
		int id = 0;
		const int sz = sizeof(struct cfg_line), al = sizeof(struct cfg_line *);
		struct cfg_line *cfg_cur = mem_calloc_tiny(sz, al);
		int first = 1;

		ctx->input = cfg_cur;
		cp = strtokm(buf, ",");
		while (cp) {
			struct cfg_line *lp;
			if ((list = cfg_get_list(SECTION_RULES, cp)) == NULL) {
				fprintf(stderr, "\"%s\" not found; ", cp);
				return 1;
			}
			lp = list->head;
			while (lp) {
				if (!first) {
					cfg_cur->next = mem_calloc_tiny(sz, al);
					cfg_cur = cfg_cur->next;
				}
				first = 0;
				cfg_cur->cfg_name = cp;
				cfg_cur->data = lp->data;
				cfg_cur->number = lp->number;
				cfg_cur->id = ++id;
				lp = lp->next;
			}
			cp = strtokm(NULL, ",");
		}
		ctx->count = -1;
		return 0;
	} else
	if ((list = cfg_get_list(SECTION_RULES, subsection)))
	if ((ctx->input = list->head)) {
		ctx->count = -1;
		return 0;
	}

	return 1;
}

static void rpp_add_char(struct rpp_range *range, unsigned char c)
{
	if (range->flag_r) {
		if (range->count >= 0x100) return;
	} else {
		int index = c / ARCH_BITS;
		unsigned ARCH_WORD mask =
		    (unsigned ARCH_WORD)1 << (c % ARCH_BITS);

		if (range->mask[index] & mask) return;

		range->mask[index] |= mask;
	}

	range->chars[range->count++] = (char)c;
}

static void rpp_process_rule(struct rpp_context *ctx)
{
	struct rpp_range *range;
	unsigned char *input, *output, *end;
	unsigned char c1, c2, c;
	int flag_p, flag_r;

	input = (unsigned char *)ctx->input->data;
	output = (unsigned char *)ctx->output;
	end = output + RULE_BUFFER_SIZE - 1;
	flag_p = flag_r = 0;
	ctx->count = ctx->refs_count = 0;

	if (options.internal_cp != UTF_8 && options.internal_cp != ENC_RAW) {
		/*
		 * Rules encoded as UTF-8 and guarded with -U reject flag will be converted
		 * in-place to current internal codepage, if possible.
		 * If this fails, we need to reject all rules rendered from this PP rule, so
		 * we change -U to -- which is later parsed as "always reject".
		 */
		if (input[0] == '-' && input[1] == 'U' && valid_utf8(input) > 1) {
			char conv[RULE_BUFFER_SIZE];

			utf8_to_cp_r(ctx->input->data, conv, RULE_BUFFER_SIZE);

			if (strlen(conv) == strlen8(input))
				strcpy(ctx->input->data, conv); /* Always shorter than original */
			else {
				static int warned;

				if (!warned++)
					log_event("- Rule preprocessor: Rejected rule(s) not fitting current internal codepage");
				input[1] = '-';
			}
		}
	}

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
			/* (Jumbo) handle hex char */
			if (c == 'x' && atoi16[*input] != 0x7f &&
			    atoi16[input[1]] != 0x7f) {
				*output++ =
					((atoi16[*input]<<4)+atoi16[input[1]]);
				input += 2;
			} else
			*output++ = c;
		}
		break;

	case '[':
		if (ctx->count >= RULE_RANGES_MAX) {
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
			/* (Jumbo) Handle start char as hex in range */
			if (input[1] == 'x' && atoi16[input[2]] != 0x7F &&
			    atoi16[input[3]] != 0x7F) {
				rpp_add_char(range,
				             c1 = ((atoi16[input[2]]<<4) +
				                   atoi16[input[3]]));
				input += 4;
			} else
			if (*++input) rpp_add_char(range, c1 = *input++);
			break;

		case '-':
			if ((c2 = *++input)) {
				input++;
				/* (Jumbo) Handle end char as hex in range */
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
						/* Jumbo mod here */
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

		break;

	default:
		*output++ = *input++;
	}

	*output = 0;
}

char *rpp_next(struct rpp_context *ctx)
{
	struct rpp_range *range;
	int index, done;
	extern int hc_logic;

	if (ctx->count < 0) {
		if (!ctx->input) return NULL;
		if (hc_logic) {
			ctx->count = 0;
			strcpy(ctx->output, ctx->input->data);
		} else
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

		if (ctx->output[0] == '.' &&
		    !strncmp(ctx->output, ".log ", 5)) {
			char *cp = strchr(ctx->output, '\"');
			int len;
			if (!rpp_real_run)
				return rpp_next(ctx);
			if (!cp) {
				// warn about unknown/invalid .log directive
				return rpp_next(ctx);
			}
			++cp;
			len = strlen(cp)-1;
			if (!strncmp(ctx->output, ".log both ", 10) ||
			    !strncmp(ctx->output, ".log screen ", 11))
				fprintf(stderr, "%*.*s\n", len,len, cp);
			if (strncmp(ctx->output, ".log screen ", 11))
				log_event ("%*.*s\n", len, len, cp);
			return rpp_next(ctx);
		}

	}

	return ctx->output;
}

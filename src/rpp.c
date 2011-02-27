/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2006,2009,2010,2011 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "config.h"
#include "rpp.h"

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
			if (*++input) rpp_add_char(range, c1 = *input++);
			break;

		case '-':
			if ((c2 = *++input)) {
				input++;
				if (c1 && range->count) {
					if (c1 > c2)
						for (c = c1 - 1; c >= c2; c--)
							rpp_add_char(range, c);
					else
						for (c = c1 + 1; c <= c2; c++)
							rpp_add_char(range, c);
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

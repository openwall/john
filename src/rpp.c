/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2006,2009 by Solar Designer
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
	int index = c / ARCH_BITS;
	ARCH_WORD mask = (ARCH_WORD)1 << (c % ARCH_BITS);

	if (range->mask[index] & mask) return;

	range->mask[index] |= mask;
	range->chars[range->count++] = (char)c;
}

static void rpp_process_rule(struct rpp_context *ctx)
{
	struct rpp_range *range;
	unsigned char *input, *output, *end;
	unsigned char c1, c2, c;

	input = (unsigned char *)ctx->input->data;
	output = (unsigned char *)ctx->output;
	end = output + RULE_BUFFER_SIZE - 1;
	ctx->count = 0;

	while (*input && output < end)
	switch (*input) {
	case '\\':
		if (!(c = *++input)) break;
		input++;
		if (c >= '1' && c <= '9' && ctx->count < RULE_RANGES_MAX) {
			range = &ctx->ranges[ctx->count++];
			range->pos = (char *)output++;
			range->count = -(int)(c - '0');
			range->index = 0;
			break;
		}
		*output++ = c;
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
		memset(range->mask, 0, sizeof(range->mask));

		c1 = 0;
		while (*input && *input != ']')
		switch (*input) {
		case '\\':
			if (*++input) rpp_add_char(range, c1 = *input++);
			break;

		case '-':
			if ((c2 = *++input))
			if (c1 && range->count) {
				if (c1 > c2)
					for (c = c1 - 1; c >= c2; c--)
						rpp_add_char(range, c);
				else
					for (c = c1 + 1; c <= c2; c++)
						rpp_add_char(range, c);
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
	int index;

	if (ctx->count < 0) {
		if (!ctx->input) return NULL;
		rpp_process_rule(ctx);
	}

	if ((index = ctx->count - 1) >= 0) {
		do {
			char *p;
			range = &ctx->ranges[index];
			p = range->pos;
			if (range->count < 0)
				range = &ctx->ranges[-range->count - 1];
			*p = range->chars[range->index];
		} while (index--);

		index = ctx->count - 1;
		do {
			range = &ctx->ranges[index];
			if (++range->index < range->count) break;
			range->index = 0;
		} while (index--);
	}

	if (index < 0) {
		ctx->input = ctx->input->next;
		ctx->count = -1;
	}

	return ctx->output;
}

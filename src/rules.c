/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 */

#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "formats.h"
#include "loader.h"
#include "rpp.h"
#include "rules.h"

char *rules_errors[] = {
	NULL,	/* No error */
	"Unexpected end of rule",
	"Unknown command",
	"Invalid position code",
	"Unknown character class code",
	"Unknown rule reject flag"
};

int rules_errno, rules_line;

static int rules_debug;
static char *rules_classes[0x100], rules_length[0x100];
static int rules_max_length = 0;

#define CONV_SOURCE \
	"`1234567890-=\\qwertyuiop[]asdfghjkl;'zxcvbnm,./" \
	"~!@#$%^&*()_+|QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?"
#define CONV_SHIFT \
	"~!@#$%^&*()_+|QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?" \
	"`1234567890-=\\qwertyuiop[]asdfghjkl;'zxcvbnm,./"
#define CONV_INVERT \
	"`1234567890-=\\QWERTYUIOP[]ASDFGHJKL;'ZXCVBNM,./" \
	"~!@#$%^&*()_+|qwertyuiop{}asdfghjkl:\"zxcvbnm<>?"
#define CONV_VOWELS \
	"`1234567890-=\\QWeRTYuioP[]aSDFGHJKL;'ZXCVBNM,./" \
	"~!@#$%^&*()_+|QWeRTYuioP{}aSDFGHJKL:\"ZXCVBNM<>?"
#define CONV_RIGHT \
	"1234567890-=\\\\wertyuiop[]]sdfghjkl;''xcvbnm,./\\" \
	"!@#$%^&*()_+||WERTYUIOP{}}SDFGHJKL:\"\"XCVBNM<>?|"
#define CONV_LEFT \
	"``1234567890-=qqwertyuiop[aasdfghjkl;zzxcvbnm,." \
	"~~!@#$%^&*()_+QQWERTYUIOP{AASDFGHJKL:ZZXCVBNM<>"

#define CHARS_LOWER \
	"abcdefghijklmnopqrstuvwxyz"
#define CHARS_UPPER \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define CHARS_DIGITS \
	"0123456789"

static char *conv_source = CONV_SOURCE;
static char *conv_shift, *conv_invert, *conv_vowels, *conv_right, *conv_left;
static char *conv_tolower, *conv_toupper;

#define INVALID_LENGTH			0x7F

#define RULE				(*rule++)
#define LAST				(*(rule - 1))
#define NEXT				(*rule)

#define REJECT { \
	if (!rules_debug) return NULL; \
}

#define VALUE { \
	if (!(value = RULE)) { \
		rules_errno = RULES_ERROR_END; \
		return NULL; \
	} \
}

#define POSITION { \
	if ((pos = rules_length[ARCH_INDEX(RULE)]) == INVALID_LENGTH) { \
		if (LAST) \
			rules_errno = RULES_ERROR_POSITION; \
		else \
			rules_errno = RULES_ERROR_END; \
		return NULL; \
	} \
}

#define CLASS(start, true, false) { \
	if ((value = RULE) == '?') { \
		if (!(class = rules_classes[ARCH_INDEX(RULE)])) { \
			if (LAST) \
				rules_errno = RULES_ERROR_CLASS; \
			else \
				rules_errno = RULES_ERROR_END; \
			return NULL; \
		} \
		for (pos = (start); ARCH_INDEX(in[pos]); pos++) \
		if (class[ARCH_INDEX(in[pos])]) { \
			true; \
		} else { \
			false; \
		} \
	} else { \
		if (!value) { \
			rules_errno = RULES_ERROR_END; \
			return NULL; \
		} \
		for (pos = (start); ARCH_INDEX(in[pos]); pos++) \
		if (in[pos] == value) { \
			true; \
		} else { \
			false; \
		} \
	} \
}

#define SKIP_CLASS { \
	VALUE \
	if (value == '?') VALUE \
}

#define CONV(conv) { \
	for (pos = 0; (out[pos] = (conv)[ARCH_INDEX(in[pos])]); pos++); \
}

static void rules_init_class(char name, char *valid)
{
	char *pos, inv;

	rules_classes[ARCH_INDEX(name)] =
		mem_alloc_tiny(0x100, MEM_ALIGN_NONE);
	memset(rules_classes[ARCH_INDEX(name)], 0, 0x100);
	for (pos = valid; ARCH_INDEX(*pos); pos++)
		rules_classes[ARCH_INDEX(name)][ARCH_INDEX(*pos)] = 1;

	if (name >= 'a' && name <= 'z') {
		inv = name & ~0x20;
		rules_classes[ARCH_INDEX(inv)] =
			mem_alloc_tiny(0x100, MEM_ALIGN_NONE);
		memset(rules_classes[ARCH_INDEX(inv)], 1, 0x100);
		for (pos = valid; ARCH_INDEX(*pos); pos++)
			rules_classes[ARCH_INDEX(inv)][ARCH_INDEX(*pos)] = 0;
	}
}

static void rules_init_classes(void)
{
	memset(rules_classes, 0, sizeof(rules_classes));

	rules_init_class('?', "?");
	rules_init_class('v', "aeiouAEIOU");
	rules_init_class('c', "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ");
	rules_init_class('w', " \t");
	rules_init_class('p', ".,:;'\"?!`");
	rules_init_class('s', "$%^&*()-_+=|\\<>[]{}#@/~");
	rules_init_class('l', CHARS_LOWER);
	rules_init_class('u', CHARS_UPPER);
	rules_init_class('d', CHARS_DIGITS);
	rules_init_class('a', CHARS_LOWER CHARS_UPPER);
	rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_DIGITS);
}

static char *rules_init_conv(char *src, char *dst)
{
	char *conv;
	int pos;

	conv = mem_alloc_tiny(0x100, MEM_ALIGN_NONE);
	for (pos = 0; pos < 0x100; pos++) conv[pos] = pos;

	while (*src)
		conv[ARCH_INDEX(*src++)] = *dst++;

	return conv;
}

static void rules_init_convs(void)
{
	conv_shift = rules_init_conv(conv_source, CONV_SHIFT);
	conv_invert = rules_init_conv(conv_source, CONV_INVERT);
	conv_vowels = rules_init_conv(conv_source, CONV_VOWELS);
	conv_right = rules_init_conv(conv_source, CONV_RIGHT);
	conv_left = rules_init_conv(conv_source, CONV_LEFT);

	conv_tolower = rules_init_conv(CHARS_UPPER, CHARS_LOWER);
	conv_toupper = rules_init_conv(CHARS_LOWER, CHARS_UPPER);
}

static void rules_init_length(int max_length)
{
	int c;

	memset(rules_length, INVALID_LENGTH, sizeof(rules_length));

	for (c = '0'; c <= '9'; c++) rules_length[c] = c - '0';
	for (c = 'a'; c <= 'z'; c++) rules_length[c] = c - ('a' - 10);
	for (c = 'A'; c <= 'Z'; c++) rules_length[c] = c - ('A' - 10);
	rules_length['*'] = rules_max_length = max_length;
	rules_length['-'] = max_length - 1;
	rules_length['+'] = max_length + 1;
}

void rules_init(int max_length)
{
	if (rules_max_length) return;

	rules_init_classes();
	rules_init_convs();
	rules_init_length(max_length);

	rules_debug = 0;
	rules_errno = RULES_ERROR_NONE;
}

char *rules_reject(char *rule, struct db_main *db)
{
	while (RULE)
	switch (LAST) {
	case ':':
	case ' ':
	case '\t':
		break;

	case '-':
		switch (RULE) {
		case 'c':
			if (!db) continue;
			if (db->format->params.flags & FMT_CASE) continue;
			return NULL;

		case '8':
			if (!db) continue;
			if (db->format->params.flags & FMT_8_BIT) continue;
			return NULL;

		case 's':
			if (!db) continue;
			if (db->options->flags & DB_SPLIT) continue;
			return NULL;

		case '\0':
			rules_errno = RULES_ERROR_END;
			return NULL;

		default:
			rules_errno = RULES_ERROR_REJECT;
			return NULL;
		}

	default:
		return rule - 1;
	}

	return rule - 1;
}

char *rules_apply(char *word, char *rule, int split)
{
	static char buffer[3][RULE_WORD_SIZE * 2];
	char *in = buffer[0], *out = buffer[1];
	char memory[RULE_WORD_SIZE];
	int memory_empty, which;
	char value, *class;
	int pos, out_pos;
	int count, required;

	strnfcpy(in, word, RULE_WORD_SIZE);
	memory_empty = 1; which = 0;

	if (NEXT != ':' || *(rule + 1))
	while (RULE) {
		if (!in[0]) REJECT
		in[RULE_WORD_SIZE - 1] = 0;

		switch (LAST) {
/* Crack 4.1 rules */
		case ':':
		case ' ':
		case '\t':
			out = in;
			break;

		case '<':
			POSITION
			if ((int)strlen(in) < pos) out = in; else REJECT
			break;

		case '>':
			POSITION
			if ((int)strlen(in) > pos) out = in; else REJECT
			break;

		case 'l':
			CONV(conv_tolower)
			break;

		case 'u':
			CONV(conv_toupper)
			break;

		case 'c':
			pos = 0;
			if ((out[0] = conv_toupper[ARCH_INDEX(in[0])]))
			while (in[++pos])
				out[pos] = conv_tolower[ARCH_INDEX(in[pos])];
			out[pos] = 0;
			if (out[0] == 'M' && out[1] == 'c')
				out[2] = conv_toupper[ARCH_INDEX(out[2])];
			break;

		case 'r':
			*(out += strlen(in)) = 0;
			while (*in) *--out = *in++;
			break;

		case 'd':
			strcpy(out, in); strcat(out, in);
			break;

		case 'f':
			out = in;
			out[pos = strlen(out) << 1] = 0;
			while (*in) out[--pos] = *in++;
			break;

		case 'p':
			out = in;
			if (!out[0] || !out[1]) break;
			if (strchr("hsx", out[pos = strlen(out) - 1]))
				strcat(out, "es");
			else
			if (out[pos] == 'f' && out[pos - 1] != 'f')
				strcpy(&out[pos], "ves");
			else
			if (pos > 1 && out[pos] == 'e' && out[pos - 1] == 'f')
				strcpy(&out[pos - 1], "ves");
			else
			if (pos > 1 && out[pos] == 'y') {
				if (strchr("aeiou", out[pos - 1]))
					strcat(out, "s");
				else
					strcpy(&out[pos], "ies");
			} else
				strcat(out, "s");
			break;

		case '$':
			VALUE
			out = in;
			out[pos = strlen(out)] = value;
			out[pos + 1] = 0;
			break;

		case '^':
			VALUE
			out[0] = value;
			strcpy(&out[1], in);
			break;

		case 'x':
			POSITION
			if (pos < (int)strlen(in)) {
				in += pos;
				POSITION
				strnzcpy(out, in, pos + 1);
			} else {
				POSITION
				out[0] = 0;
			}
			break;

		case 'i':
			POSITION
			VALUE
			if (pos < (out_pos = strlen(in))) {
				memcpy(out, in, pos);
				out[pos] = value;
				strcpy(&out[pos + 1], &in[pos]);
			} else {
				out = in;
				out[out_pos] = value;
				out[out_pos + 1] = 0;
			}
			break;

		case 'o':
			POSITION
			VALUE
			out = in;
			if (out[pos]) out[pos] = value;
			break;

		case 's':
			out = in;
			CLASS(0, out[pos] = NEXT, {})
			VALUE
			break;

		case '@':
			out_pos = 0;
			CLASS(0, {}, out[out_pos++] = in[pos])
			out[out_pos] = 0;
			break;

		case '!':
			CLASS(0, REJECT, {})
			out = in;
			break;

		case '/':
			CLASS(0, break, {})
			if (!in[pos]) REJECT
			out = in;
			break;

		case '=':
			POSITION
			if (pos >= (int)strlen(in)) {
				SKIP_CLASS
				REJECT
			} else
				CLASS(pos, break, REJECT)
			out = in;
			break;

/* Crack 5.0 rules */
		case '[':
			if (in[0]) strcpy(out, &in[1]); else out[0] = 0;
			break;

		case ']':
			out = in;
			if (out[0]) out[strlen(out) - 1] = 0;
			break;

		case 'C':
			pos = 0;
			if ((out[0] = conv_tolower[ARCH_INDEX(in[0])]))
			while (in[++pos])
				out[pos] = conv_toupper[ARCH_INDEX(in[pos])];
			out[pos] = 0;
			if (out[0] == 'm' && out[1] == 'C')
				out[2] = conv_tolower[ARCH_INDEX(out[2])];
			break;

		case 't':
			CONV(conv_invert)
			break;

		case '(':
			CLASS(0, break, REJECT)
			out = in;
			break;

		case ')':
			if (!in[0]) {
				SKIP_CLASS
				REJECT
			} else
				CLASS(strlen(in) - 1, break, REJECT)
			out = in;
			break;

		case '\'':
			POSITION
			(out = in)[pos] = 0;
			break;

		case '%':
			POSITION
			count = 0; required = pos;
			CLASS(0, if (++count >= required) break, {})
			if (count < required) REJECT
			out = in;
			break;

/* Rules added in John */
		case 'T':
			POSITION
			out = in;
			out[pos] = conv_invert[ARCH_INDEX(out[pos])];
			break;

		case 'D':
			POSITION
			if (pos >= (int)strlen(in)) out = in; else {
				memcpy(out, in, pos);
				strcpy(&out[pos], &in[pos + 1]);
			}
			break;

		case '{':
			if (in[0]) {
				strcpy(out, &in[1]);
				in[1] = 0;
				strcat(out, in);
			} else
				out[0] = 0;
			break;

		case '}':
			if (in[0]) {
				out[0] = in[pos = strlen(in) - 1];
				in[pos] = 0;
				strcpy(&out[1], in);
			} else
				out[0] = 0;
			break;

		case 'S':
			CONV(conv_shift);
			break;

		case 'V':
			CONV(conv_vowels);
			break;

		case 'R':
			CONV(conv_right);
			break;

		case 'L':
			CONV(conv_left);
			break;

		case 'P':
			out = in;
			if ((pos = strlen(out) - 1) < 2) break;
			if (out[pos] == 'd' && out[pos - 1] == 'e') break;
			if (out[pos] == 'y') out[pos] = 'i'; else
			if (strchr("bgp", out[pos]) &&
			    !strchr("bgp", out[pos - 1])) {
				out[pos + 1] = out[pos];
				out[pos + 2] = 0;
			}
			if (out[pos] == 'e')
				strcat(out, "d");
			else
				strcat(out, "ed");
			break;

		case 'I':
			out = in;
			if ((pos = strlen(out) - 1) < 2) break;
			if (out[pos] == 'g' && out[pos - 1] == 'n' &&
			    out[pos - 2] == 'i') break;
			if (strchr("aeiou", out[pos]))
				strcpy(&out[pos], "ing");
			else {
				if (strchr("bgp", out[pos]) &&
				    !strchr("bgp", out[pos - 1])) {
					out[pos + 1] = out[pos];
					out[pos + 2] = 0;
				}
				strcat(out, "ing");
			}
			break;

		case 'M':
			strnfcpy(memory, (out = in), rules_max_length);
			memory_empty = 0;
			break;

		case 'Q':
			if (memory_empty) {
				if (!strncmp(word, in, rules_max_length))
					REJECT
			} else
				if (!strncmp(memory, in, rules_max_length))
					REJECT
			out = in;
			break;

/* Additional "single crack" mode rules */
		case '1':
			if (split < 0) {
				rules_errno = RULES_ERROR_UNKNOWN;
				return NULL;
			}
			if (!split) REJECT
			if (which) strcpy(buffer[2], in);
			else strnzcpy(buffer[2], &word[split], RULE_WORD_SIZE);
			strnzcpy(out, word, split + 1);
			which = 1;
			break;

		case '2':
			if (split < 0) {
				rules_errno = RULES_ERROR_UNKNOWN;
				return NULL;
			}
			if (!split) REJECT
			if (which) strcpy(buffer[2], in);
			else strnzcpy(buffer[2], word, split + 1);
			strnzcpy(out, &word[split], RULE_WORD_SIZE);
			which = 2;
			break;

		case '+':
			switch (which) {
			case 1:
				strcat(out = in, buffer[2]);
				break;

			case 2:
				strcpy(out, buffer[2]);
				strcat(out, in);
				break;

			default:
				rules_errno = RULES_ERROR_UNKNOWN;
				return NULL;
			}
			which = 0;
			break;

		default:
			rules_errno = RULES_ERROR_UNKNOWN;
			return NULL;
		}

		if (!out[0]) REJECT

		if ((in = out) == buffer[1])
			out = buffer[0];
		else
			out = buffer[1];
	}

	switch (which) {
	case 1:
		strcat(in, buffer[2]);
		break;

	case 2:
		strcpy(out, buffer[2]);
		strcat(out, in);
		in = out;
	}

	in[rules_max_length] = 0;
	return in;
}

int rules_check(struct rpp_context *start, int split)
{
	struct rpp_context ctx;
	char *rule;
	int count;

	rules_errno = RULES_ERROR_NONE;

	memcpy(&ctx, start, sizeof(ctx));
	rules_line = ctx.input->number;
	count = 0;

	rules_debug = 1;
	while ((rule = rpp_next(&ctx)))
	if ((rule = rules_reject(rule, NULL))) {
		rules_apply("", rule, split);
		if (rules_errno) break;

		if (ctx.input) rules_line = ctx.input->number;
		count++;
	}
	rules_debug = 0;

	return rules_errno ? 0 : count;
}

int rules_count(struct rpp_context *start, int split)
{
	int count;

	if (!(count = rules_check(start, split))) {
		fprintf(stderr, "Invalid rule in %s at line %d: %s\n",
			cfg_name, rules_line,
			rules_errors[rules_errno]);
		error();
	}

	return count;
}

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2005,2009,2010 by Solar Designer
 */

#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "common.h"
#include "memory.h"
#include "formats.h"
#include "loader.h"
#include "logger.h"
#include "rpp.h"
#include "rules.h"

/*
 * Error codes.
 */
#define RULES_ERROR_NONE		0
#define RULES_ERROR_END			1
#define RULES_ERROR_UNKNOWN		2
#define RULES_ERROR_UNALLOWED		3
#define RULES_ERROR_POSITION		4
#define RULES_ERROR_CLASS		5
#define RULES_ERROR_REJECT		6

/*
 * Error names.
 */
static const char * const rules_errors[] = {
	NULL,	/* No error */
	"Unexpected end of rule",
	"Unknown command",
	"Unallowed command",
	"Invalid position code",
	"Unknown character class code",
	"Unknown rule reject flag"
};

/*
 * Last error code.
 */
static int rules_errno;

/*
 * Configuration file line number, only set after a rules_check() call if
 * rules_errno indicates an error.
 */
static int rules_line;

static int rules_max_length = 0;

static struct {
	unsigned char vars[0x100];
/*
 * pass == -2	initial syntax checking of rules
 * pass == -1	optimization of rules (no-ops are removed)
 * pass == 0	actual processing of rules
 */
	int pass;
/*
 * Some rule commands may temporarily double the length, and we skip a few
 * machine words to avoid cache bank conflicts when copying data between the
 * buffers.  We need three buffers because some rule commands require separate
 * input and output buffers and we also need a buffer either for leaving the
 * previous mangled word intact for a subsequent comparison (in wordlist mode)
 * or for switching between two input words (in "single crack" mode).
 * rules_apply() tries to minimize data copying, and thus it may return a
 * pointer to any of the three buffers.
 */
	union {
		char buffer[3][RULE_WORD_SIZE * 2 + CACHE_BANK_SHIFT];
		ARCH_WORD dummy;
	} aligned;
/*
 * "memory" doesn't have to be static (could as well be on stack), but we keep
 * it here to ensure it doesn't occasionally "overlap" with our other data in
 * terms of cache tags.
 */
	char memory[RULE_WORD_SIZE];
	char *classes[0x100];
} CC_CACHE_ALIGN rules_data;

#define rules_pass rules_data.pass
#define rules_classes rules_data.classes
#define rules_vars rules_data.vars
#define buffer rules_data.aligned.buffer
#define memory_buffer rules_data.memory

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

#define INVALID_LENGTH			0x81
#define INFINITE_LENGTH			0xFF

#define RULE				(*rule++)
#define LAST				(*(rule - 1))
#define NEXT				(*rule)

#define REJECT { \
	if (!rules_pass) goto out_NULL; \
}

#define VALUE(value) { \
	if (!((value) = RULE)) goto out_ERROR_END; \
}

#define POSITION(pos) { \
	if (((pos) = rules_vars[ARCH_INDEX(RULE)]) == INVALID_LENGTH) \
		goto out_ERROR_POSITION; \
}

#define CLASS_export_pos(start, true, false) { \
	char value, *class; \
	if ((value = RULE) == '?') { \
		if (!(class = rules_classes[ARCH_INDEX(RULE)])) \
			goto out_ERROR_CLASS; \
		for (pos = (start); ARCH_INDEX(in[pos]); pos++) \
		if (class[ARCH_INDEX(in[pos])]) { \
			true; \
		} else { \
			false; \
		} \
	} else { \
		if (!value) goto out_ERROR_END; \
		for (pos = (start); ARCH_INDEX(in[pos]); pos++) \
		if (in[pos] == value) { \
			true; \
		} else { \
			false; \
		} \
	} \
}

#define CLASS(start, true, false) { \
	int pos; \
	CLASS_export_pos(start, true, false); \
}

#define SKIP_CLASS { \
	char value; \
	VALUE(value) \
	if (value == '?') VALUE(value) \
}

#define CONV(conv) { \
	int pos; \
	for (pos = 0; (in[pos] = (conv)[ARCH_INDEX(in[pos])]); pos++); \
}

#define GET_OUT { \
	out = alt; \
	alt = in; \
}

static void rules_init_class(char name, char *valid)
{
	char *pos, inv;

	rules_classes[ARCH_INDEX(name)] =
		mem_alloc_tiny(0x100, MEM_ALIGN_NONE);
	memset(rules_classes[ARCH_INDEX(name)], 0, 0x100);
	for (pos = valid; ARCH_INDEX(*pos); pos++)
		rules_classes[ARCH_INDEX(name)][ARCH_INDEX(*pos)] = 1;

	if ((name | 0x20) >= 'a' && (name | 0x20) <= 'z') {
		inv = name ^ 0x20;
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
	rules_init_class('Z', "");
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

	memset(rules_vars, INVALID_LENGTH, sizeof(rules_vars));

	for (c = '0'; c <= '9'; c++) rules_vars[c] = c - '0';
	for (c = 'A'; c <= 'Z'; c++) rules_vars[c] = c - ('A' - 10);

	rules_vars['*'] = rules_max_length = max_length;
	rules_vars['-'] = max_length - 1;
	rules_vars['+'] = max_length + 1;

	rules_vars['z'] = INFINITE_LENGTH;
}

void rules_init(int max_length)
{
	rules_pass = 0;
	rules_errno = RULES_ERROR_NONE;

	if (max_length > RULE_WORD_SIZE - 1)
		max_length = RULE_WORD_SIZE - 1;

	if (max_length == rules_max_length) return;

	if (!rules_max_length) {
		rules_init_classes();
		rules_init_convs();
	}
	rules_init_length(max_length);
}

char *rules_reject(char *rule, int split, char *last, struct db_main *db)
{
	static char out_rule[RULE_BUFFER_SIZE];

	while (RULE)
	switch (LAST) {
	case ':':
	case ' ':
	case '\t':
		break;

	case '-':
		switch (RULE) {
		case ':':
			continue;

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

		case 'p':
			if (split >= 0) continue;
			return NULL;

		case '\0':
			rules_errno = RULES_ERROR_END;
			return NULL;

		default:
			rules_errno = RULES_ERROR_REJECT;
			return NULL;
		}

	default:
		goto accept;
	}

accept:
	rules_pass--;
	strnzcpy(out_rule, rule - 1, sizeof(out_rule));
	rules_apply("", out_rule, split, last);
	rules_pass++;

	return out_rule;
}

char *rules_apply(char *word, char *rule, int split, char *last)
{
	char *in, *alt, *memory = word;
	int length;
	int which;

	in = buffer[0];
	if (in == last)
		in = buffer[2];

	length = 0;
	while (length < RULE_WORD_SIZE - 1) {
		if (!(in[length] = word[length]))
			break;
		length++;
	}

/*
 * This check assumes that rules_reject() has optimized the no-op rule
 * (a colon) into an empty string.
 */
	if (!NEXT)
		goto out_OK;

	if (!length) REJECT

	alt = buffer[1];
	if (alt == last)
		alt = buffer[2];

/*
 * This assumes that RULE_WORD_SIZE is small enough that length can't reach or
 * exceed INVALID_LENGTH.
 */
	rules_vars['l'] = length;
	rules_vars['m'] = (unsigned char)length - 1;

	which = 0;

	while (RULE) {
		in[RULE_WORD_SIZE - 1] = 0;

		switch (LAST) {
/* Crack 4.1 rules */
		case ':':
		case ' ':
		case '\t':
			if (rules_pass == -1) {
				memmove(rule - 1, rule, strlen(rule) + 1);
				rule--;
			}
			break;

		case '<':
			{
				int pos;
				POSITION(pos)
				if (length >= pos) REJECT
			}
			break;

		case '>':
			{
				int pos;
				POSITION(pos)
				if (length <= pos) REJECT
			}
			break;

		case 'l':
			CONV(conv_tolower)
			break;

		case 'u':
			CONV(conv_toupper)
			break;

		case 'c':
			{
				int pos = 0;
				if ((in[0] = conv_toupper[ARCH_INDEX(in[0])]))
				while (in[++pos])
					in[pos] =
					    conv_tolower[ARCH_INDEX(in[pos])];
				in[pos] = 0;
			}
			if (in[0] != 'M' || in[1] != 'c')
				break;
			in[2] = conv_toupper[ARCH_INDEX(in[2])];
			break;

		case 'r':
			{
				char *out;
				GET_OUT
				*(out += length) = 0;
				while (*in)
					*--out = *in++;
				in = out;
			}
			break;

		case 'd':
			memcpy(in + length, in, length);
			in[length <<= 1] = 0;
			break;

		case 'f':
			{
				int pos;
				in[pos = (length <<= 1)] = 0;
				{
					char *p = in;
					while (*p)
						in[--pos] = *p++;
				}
			}
			break;

		case 'p':
			if (length < 2) break;
			{
				int pos = length - 1;
				if (strchr("sxz", in[pos]) ||
				    (pos > 1 && in[pos] == 'h' &&
				    (in[pos - 1] == 'c' || in[pos - 1] == 's')))
					strcat(in, "es");
				else
				if (in[pos] == 'f' && in[pos - 1] != 'f')
					strcpy(&in[pos], "ves");
				else
				if (pos > 1 &&
				    in[pos] == 'e' && in[pos - 1] == 'f')
					strcpy(&in[pos - 1], "ves");
				else
				if (pos > 1 && in[pos] == 'y') {
					if (strchr("aeiou", in[pos - 1]))
						strcat(in, "s");
					else
						strcpy(&in[pos], "ies");
				} else
					strcat(in, "s");
			}
			length = strlen(in);
			break;

		case '$':
			VALUE(in[length++])
			in[length] = 0;
			break;

		case '^':
			{
				char *out;
				GET_OUT
				VALUE(out[0])
				strcpy(&out[1], in);
				in = out;
			}
			length++;
			break;

		case 'x':
			{
				int pos;
				POSITION(pos)
				if (pos < length) {
					char *out;
					GET_OUT
					in += pos;
					POSITION(pos)
					strnzcpy(out, in, pos + 1);
					length = strlen(in = out);
					break;
				}
				POSITION(pos)
				in[length = 0] = 0;
			}
			break;

		case 'i':
			{
				int pos;
				POSITION(pos)
				if (pos < length) {
					char *p = in + pos;
					memmove(p + 1, p, length++ - pos);
					VALUE(*p)
					in[length] = 0;
					break;
				}
			}
			VALUE(in[length++])
			in[length] = 0;
			break;

		case 'o':
			{
				int pos;
				char value;
				POSITION(pos)
				VALUE(value);
				if (pos < length)
					in[pos] = value;
			}
			break;

		case 's':
			CLASS(0, in[pos] = NEXT, {})
			{
				char value;
				VALUE(value)
			}
			break;

		case '@':
			length = 0;
			CLASS(0, {}, in[length++] = in[pos])
			in[length] = 0;
			break;

		case '!':
			CLASS(0, REJECT, {})
			break;

		case '/':
			{
				int pos;
				CLASS_export_pos(0, break, {})
				rules_vars['p'] = pos;
				if (in[pos]) break;
			}
			REJECT
			break;

		case '=':
			{
				int pos;
				POSITION(pos)
				if (pos >= length) {
					SKIP_CLASS
					REJECT
				} else {
					CLASS_export_pos(pos, break, REJECT)
				}
			}
			break;

/* Crack 5.0 rules */
		case '[':
			if (length) {
				char *out;
				GET_OUT
				strcpy(out, &in[1]);
				length--;
				in = out;
				break;
			}
			in[0] = 0;
			break;

		case ']':
			if (length)
				in[--length] = 0;
			break;

		case 'C':
			{
				int pos = 0;
				if ((in[0] = conv_tolower[ARCH_INDEX(in[0])]))
				while (in[++pos])
					in[pos] =
					    conv_toupper[ARCH_INDEX(in[pos])];
				in[pos] = 0;
			}
			if (in[0] == 'm' && in[1] == 'C')
				in[2] = conv_tolower[ARCH_INDEX(in[2])];
			break;

		case 't':
			CONV(conv_invert)
			break;

		case '(':
			CLASS(0, break, REJECT)
			break;

		case ')':
			if (!length) {
				SKIP_CLASS
				REJECT
			} else {
				CLASS(length - 1, break, REJECT)
			}
			break;

		case '\'':
			{
				int pos;
				POSITION(pos)
				if (pos < length)
					in[length = pos] = 0;
			}
			break;

		case '%':
			{
				int count = 0, required, pos;
				POSITION(required)
				CLASS_export_pos(0,
				    if (++count >= required) break, {})
				if (count < required) REJECT
				rules_vars['p'] = pos;
			}
			break;

/* Rules added in John */
		case 'A': /* append/insert/prepend string */
			{
				int pos;
				char term;
				POSITION(pos)
				VALUE(term)
				if (pos >= length) { /* append */
					char *start, *end, *p;
					start = p = &in[pos = length];
					end = &in[RULE_WORD_SIZE - 1];
					do {
						char c = RULE;
						if (c == term)
							break;
						if (p < end)
							*p++ = c;
						if (c)
							continue;
						goto out_ERROR_END;
					} while (1);
					*p = 0;
					length += p - start;
					break;
				}
				/* insert or prepend */
				{
					char *out, *start, *end, *p;
					GET_OUT
					memcpy(out, in, pos);
					start = p = &out[pos];
					end = &out[RULE_WORD_SIZE - 1];
					do {
						char c = RULE;
						if (c == term)
							break;
						if (p < end)
							*p++ = c;
						if (c)
							continue;
						goto out_ERROR_END;
					} while (1);
					strcpy(p, &in[pos]);
					length += p - start;
					in = out;
				}
			}
			break;

		case 'T':
			{
				int pos;
				POSITION(pos)
				in[pos] = conv_invert[ARCH_INDEX(in[pos])];
			}
			break;

		case 'D':
			{
				int pos;
				POSITION(pos)
				if (pos < length) {
					char *out;
					GET_OUT
					memcpy(out, in, pos);
					strcpy(&out[pos], &in[pos + 1]);
					length--;
					in = out;
				}
			}
			break;

		case '{':
			if (length) {
				char *out;
				GET_OUT
				strcpy(out, &in[1]);
				in[1] = 0;
				strcat(out, in);
				in = out;
				break;
			}
			in[0] = 0;
			break;

		case '}':
			if (length) {
				char *out;
				int pos;
				GET_OUT
				out[0] = in[pos = length - 1];
				in[pos] = 0;
				strcpy(&out[1], in);
				in = out;
				break;
			}
			in[0] = 0;
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
			{
				int pos;
				if ((pos = length - 1) < 2) break;
				if (in[pos] == 'd' && in[pos - 1] == 'e') break;
				if (in[pos] == 'y') in[pos] = 'i'; else
				if (strchr("bgp", in[pos]) &&
				    !strchr("bgp", in[pos - 1])) {
					in[pos + 1] = in[pos];
					in[pos + 2] = 0;
				}
				if (in[pos] == 'e')
					strcat(in, "d");
				else
					strcat(in, "ed");
			}
			length = strlen(in);
			break;

		case 'I':
			{
				int pos;
				if ((pos = length - 1) < 2) break;
				if (in[pos] == 'g' && in[pos - 1] == 'n' &&
				    in[pos - 2] == 'i') break;
				if (strchr("aeiou", in[pos]))
					strcpy(&in[pos], "ing");
				else {
					if (strchr("bgp", in[pos]) &&
					    !strchr("bgp", in[pos - 1])) {
						in[pos + 1] = in[pos];
						in[pos + 2] = 0;
					}
					strcat(in, "ing");
				}
			}
			length = strlen(in);
			break;

		case 'M':
			strnfcpy(memory = memory_buffer, in, rules_max_length);
			rules_vars['m'] = (unsigned char)length - 1;
			break;

		case 'Q':
			if (!strncmp(memory, in, rules_max_length))
				REJECT
			break;

		case 'X': /* append/insert/prepend substring from memory */
			{
				int mpos, count, ipos, mleft;
				char *inp, *mp;
				POSITION(mpos)
				POSITION(count)
				POSITION(ipos)
				mleft = (int)(rules_vars['m'] + 1) - mpos;
				if (count > mleft)
					count = mleft;
				if (count <= 0)
					break;
				mp = memory + mpos;
				if (ipos >= length) {
					memcpy(&in[length], mp, count);
					in[length += count] = 0;
					break;
				}
				inp = in + ipos;
				memmove(inp + count, inp, length - ipos);
				in[length += count] = 0;
				memcpy(inp, mp, count);
			}
			break;

		case 'v': /* assign value to numeric variable */
			{
				char var;
				unsigned char a, s;
				VALUE(var)
				if (var < 'a' || var > 'k')
					goto out_ERROR_POSITION;
				rules_vars['l'] = length;
				POSITION(a)
				POSITION(s)
				rules_vars[ARCH_INDEX(var)] = a - s;
			}
			break;

/* Additional "single crack" mode rules */
		case '1':
			if (split < 0)
				goto out_ERROR_UNALLOWED;
			if (!split) REJECT
			if (which)
				memcpy(buffer[2], in, length + 1);
			else
				strnzcpy(buffer[2], &word[split],
				    RULE_WORD_SIZE);
			length = split;
			if (length > RULE_WORD_SIZE - 1)
				length = RULE_WORD_SIZE - 1;
			memcpy(in, word, length);
			in[length] = 0;
			which = 1;
			break;

		case '2':
			if (split < 0)
				goto out_ERROR_UNALLOWED;
			if (!split) REJECT
			if (which) {
				memcpy(buffer[2], in, length + 1);
			} else {
				length = split;
				if (length > RULE_WORD_SIZE - 1)
					length = RULE_WORD_SIZE - 1;
				strnzcpy(buffer[2], word, length + 1);
			}
			strnzcpy(in, &word[split], RULE_WORD_SIZE);
			length = strlen(in);
			which = 2;
			break;

		case '+':
			switch (which) {
			case 1:
				strcat(in, buffer[2]);
				break;

			case 2:
				{
					char *out;
					GET_OUT
					strcpy(out, buffer[2]);
					strcat(out, in);
					in = out;
				}
				break;

			default:
				goto out_ERROR_UNALLOWED;
			}
			length = strlen(in);
			which = 0;
			break;

		default:
			goto out_ERROR_UNKNOWN;
		}

		if (!length) REJECT
	}

	if (which)
		goto out_which;

out_OK:
	in[rules_max_length] = 0;
	if (last) {
		if (length > rules_max_length)
			length = rules_max_length;
		if (length >= ARCH_SIZE - 1) {
			if (*(ARCH_WORD *)in != *(ARCH_WORD *)last)
				return in;
			if (strcmp(&in[ARCH_SIZE - 1], &last[ARCH_SIZE - 1]))
				return in;
			return NULL;
		}
		if (last[length])
			return in;
		if (memcmp(in, last, length))
			return in;
		return NULL;
	}
	return in;

out_which:
	if (which == 1) {
		strcat(in, buffer[2]);
		goto out_OK;
	}
	strcat(buffer[2], in);
	in = buffer[2];
	goto out_OK;

out_ERROR_POSITION:
	rules_errno = RULES_ERROR_POSITION;
	if (LAST)
		goto out_NULL;

out_ERROR_END:
	rules_errno = RULES_ERROR_END;
out_NULL:
	return NULL;

out_ERROR_CLASS:
	rules_errno = RULES_ERROR_CLASS;
	if (LAST)
		goto out_NULL;
	goto out_ERROR_END;

out_ERROR_UNKNOWN:
	rules_errno = RULES_ERROR_UNKNOWN;
	goto out_NULL;

out_ERROR_UNALLOWED:
	rules_errno = RULES_ERROR_UNALLOWED;
	goto out_NULL;
}

/*
 * This function is currently not used outside of rules.c, thus not exported.
 *
 * Checks if all the rules for context are valid. Returns the number of rules,
 * or returns zero and sets rules_errno on error.
 *
 * split == 0	"single crack" mode rules allowed
 * split < 0	"single crack" mode rules are invalid
 */
static int rules_check(struct rpp_context *start, int split)
{
	struct rpp_context ctx;
	char *rule;
	int count;

	rules_errno = RULES_ERROR_NONE;

	memcpy(&ctx, start, sizeof(ctx));
	rules_line = ctx.input->number;
	count = 0;

	rules_pass = -1; /* rules_reject() will turn this into -2 */
	while ((rule = rpp_next(&ctx))) {
		rules_reject(rule, split, NULL, NULL);
		if (rules_errno) break;

		if (ctx.input) rules_line = ctx.input->number;
		count++;
	}
	rules_pass = 0;

	return rules_errno ? 0 : count;
}

int rules_count(struct rpp_context *start, int split)
{
	int count;

	if (!(count = rules_check(start, split))) {
		log_event("! Invalid rule at line %d: %.100s",
			rules_line, rules_errors[rules_errno]);
		fprintf(stderr, "Invalid rule in %s at line %d: %s\n",
			cfg_name, rules_line,
			rules_errors[rules_errno]);
		error();
	}

	return count;
}

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2005,2009,2010,2015,2016 by Solar Designer
 * Copyright (c) 2009-2025, magnum
 * Copyright (c) 2009-2018, JimF
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
#include "options.h"
#include "john.h"
#include "unicode.h"
#include "mask.h"
#include "encoding_data.h"

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
 * Last error code refer to this rule.
 */
static const char *rules_err_rule;

/*
 * Optimization for not unnecessarily flipping length variables.
 */
static int length_initiated_as;

/*
 * If this is set, our result will be passed to later rules. This means
 * we should consider max_length as PLAINTEXT_BUFFER_SIZE so we don't
 * truncate or reject a word that will later become valid.
 */
unsigned int rules_stacked_after;

/*
 * Line number of stacked rule in use.
 */
int rules_stacked_number;

/*
 * Configuration file line number, only set after a rules_check() call if
 * rules_errno indicates an error.
 */
static int rules_line;

static int rules_max_length = 0, min_length, skip_length;
int hc_logic; /* can not be static. rpp.c needs to see it */

/* data structures used in 'dupe' removal code */
unsigned HASH_LOG, HASH_SIZE, HASH_LOG_HALF, HASH_MASK;
struct HashPtr {
	struct HashPtr *pNext;
	struct cfg_line *pLine;
};
struct HashPtr *pHashTbl, *pHashDat;
static struct cfg_list rules_tmp_dup_removal;
static int             rules_tmp_dup_removal_cnt;

int rules_mute, stack_rules_mute;

static int fmt_case;

static struct {
	unsigned char vars[0x100];
/*
 * pass == -2	initial syntax checking of rules
 * pass == -1	optimization of rules (no-ops are removed)
 * pass == 0	actual processing of rules
 */
	int pass;
/*
 * Some rule commands may temporarily double the length.
 * We need three buffers because some rule commands require separate input and
 * output buffers and we also need a buffer for switching between two input
 * words in "single crack" mode.
 * rules_apply() tries to minimize data copying, and thus it may return a
 * pointer to any of the three buffers.
 *
 * With stacked rules, we need a second set of three buffers.
 */
	union {
		char buffer[3][2][RULE_WORD_SIZE * 2];
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

/* A null string that is safe to read past (e.g. for ASan) */
static char safe_null_string[RULE_BUFFER_SIZE];

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

// yY variants will be both consonants and vowels when --encoding is used
#define CHARS_VOWELS \
	"aeiouAEIOU"
#define CHARS_CONSONANTS \
	"bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ"
#define CHARS_LOWER \
	"abcdefghijklmnopqrstuvwxyz"
#define CHARS_UPPER \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#define CHARS_WHITESPACE \
	" \t"
#define CHARS_PUNCTUATION \
	".,:;'\x22?!`"
#define CHARS_SPECIALS \
	"$%^&*()-_+=|\\<>[]{}#@/~"
#define CHARS_DIGITS \
	"0123456789"
#define CHARS_CONTROL_ASCII \
	"\x01\x02\x03\x04\x05\x06\x07\x08\x0A\x0B\x0C\x0D\x0E\x0F\x10" \
	"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F"
#define CHARS_CONTROL_ASCII_EXTENDED \
	"\x84\x85\x88\x8D\x8E\x8F\x90\x96\x97\x98\x9A\x9B\x9C\x9D\x9E\x9F"

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
	if (((value = RULE) == '?') && !hc_logic) { \
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

#define SWAP2(a,b) { \
	if (length > b && length > a) { \
		int tmp = in[a]; \
		in[a] = in[b]; \
		in[b] = tmp; \
	} \
}

#define STAGE !rules_stacked_after

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

/* Function exported because it's also used in fake_salts.c */
char *userclass_expand(const char *src)
{
	unsigned char _src2[0x100], *src2=_src2, dst_seen[0x100];
	char dst_tmp[0x200];
	char *dst = dst_tmp, *dstend = &dst_tmp[0x100];
	int j, br = 0;

	// pass 1: decode \xNN characters (except \x00)
	while(*src && dst < dstend) {
		if (*src == '\\' && (src[1]|0x20) == 'x' &&
		    strlen(&src[2]) >= 2 && (sscanf(&src[2], "%2x", &j)) && j)
		{
			*dst++ = (char) j;
			src += 4;
		} else
			*dst++ = *src++;
	}
	*dst = 0;
	strcpy((char*)src2, dst_tmp);
	dst = dst_tmp;

	// pass 2: parse ranges between brackets
	memset(dst_seen, 0, sizeof(dst_seen));
	while(*src2 && dst < dstend) {
		if (*src2 == '\\') {
			if (src2[1]) {
				if (dst_seen[src2[1]] == 0) {
					*dst++ = src2[1];
					dst_seen[src2[1]] = 1;
				}
				src2 += 2;
				continue;
			} else {
				return NULL;
			}
		}

		if (*src2 == '[' && br == 0) {
			br = 1;
			src2++;
			continue;
		}

		if (br == 1) {
			if (*src2 == ']') {
				br = 0;
				src2++;
				continue;
			}
			if (*src2 == '-' && src2[1] && src2[1] != ']') {
				if (src2[-1] < src2[1]) {
					for (j=src2[-1] + 1; j < src2[1]; j++) {
						if (dst_seen[j] == 0) {
							*dst++ = j;
							dst_seen[j] = 1;
						}
					}
				} else {
					for (j=src2[-1] - 1; j > src2[1]; j--) {
						if (dst_seen[j] == 0) {
							*dst++ = j;
							dst_seen[j] = 1;
						}
					}
				}
				++src2;
				if (dst_seen[*src2] == 0) {
					*dst++ = *src2;
					dst_seen[*src2] = 1;
				}
				++src2;
				continue;
			}
		}
		if (dst_seen[*src2] == 0) {
			*dst++ = *src2;
			dst_seen[*src2] = 1;
		}
		++src2;
	}
	*dst = 0;
	if (br) {
		return NULL;
	}
	dst = str_alloc_copy(dst_tmp);
	return dst;
}

static void rules_init_classes(void)
{
	unsigned char eightbitchars[129];
	int i;

	memset(rules_classes, 0, sizeof(rules_classes));

	// This is for 'b' below
	for (i = 0; i < 128; i++)
		eightbitchars[i] = i + 128;
	eightbitchars[128] = 0;

	rules_init_class('?', "?");
	rules_init_class('b', (char*)&eightbitchars);
	rules_init_class('Z', "");

	// Load user-defined character classes ?0 .. ?9 from john.conf
	for (i = '0'; i <= '9'; i++) {
		char user_class_num[] = "0";
		char *user_class;
		user_class_num[0] = i;
		if ((user_class = (char*)cfg_get_param("UserClasses", NULL,
		                                user_class_num))) {
			if ((user_class = userclass_expand(user_class)))
				rules_init_class(i, user_class);
			else {
				if (john_main_process)
					fprintf(stderr, "Invalid user-defined "
					        "character class ?%c: "
					        "Unexpected end of line\n", i);
				error();
			}
		}
	}

	switch(options.internal_cp) {
	case ISO_8859_1:
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_ISO_8859_1);
		rules_init_class('c', CHARS_CONSONANTS
		                 CHARS_CONSONANTS_ISO_8859_1);
		rules_init_class('w', CHARS_WHITESPACE
		                 CHARS_WHITESPACE_ISO_8859_1);
		rules_init_class('p', CHARS_PUNCTUATION
		                 CHARS_PUNCTUATION_ISO_8859_1);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_ISO_8859_1);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_ISO_8859_1
		                 CHARS_LOW_ONLY_ISO_8859_1);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_ISO_8859_1
		                 CHARS_UP_ONLY_ISO_8859_1);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_ISO_8859_1);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_ISO_8859_1);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER
		                 CHARS_ALPHA_ISO_8859_1 CHARS_DIGITS
		                 CHARS_DIGITS_ISO_8859_1);
		rules_init_class('o', CHARS_CONTROL_ASCII
		                 CHARS_CONTROL_ISO_8859_1);
		rules_init_class('Y', CHARS_INVALID_ISO_8859_1);
		break;
/*
 * Other codepages moved to header
 */
#include "rules_init_classes.h"

	default:
		rules_init_class('v', CHARS_VOWELS);
		rules_init_class('c', CHARS_CONSONANTS);
		rules_init_class('w', CHARS_WHITESPACE);
		rules_init_class('p', CHARS_PUNCTUATION);
		rules_init_class('s', CHARS_SPECIALS);
		rules_init_class('l', CHARS_LOWER);
		rules_init_class('u', CHARS_UPPER);
		rules_init_class('d', CHARS_DIGITS);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_DIGITS);
		if (options.internal_cp == UTF_8) {
			rules_init_class('Y', CHARS_INVALID_UTF8);
			rules_init_class('o', CHARS_CONTROL_ASCII);
		} else {
			rules_init_class('Y', "");
			rules_init_class('o', CHARS_CONTROL_ASCII
			                 CHARS_CONTROL_ASCII_EXTENDED);
		}
	}
}

static char *rules_init_conv(char *src, char *dst)
{
	char *conv;
	int pos;

	if (strlen(src) != strlen(dst)) {
		fprintf(stderr, "Error: encoding_data.h format error. CHARS_UPPER and CHARS_LOWER must be same\nlength and map exactly to each other\n");
		error();
	}

	conv = mem_alloc_tiny(0x100, MEM_ALIGN_NONE);
	for (pos = 0; pos < 0x100; pos++) conv[pos] = pos;

	while (*src) {
		if (fmt_case || !conv_toupper ||
		    conv_toupper[ARCH_INDEX(*src)] !=
		    conv_toupper[ARCH_INDEX(*dst)])
			conv[ARCH_INDEX(*src)] = *dst;
		src++;
		dst++;
	}

	return conv;
}

static void rules_init_convs(void)
{
	conv_vowels = rules_init_conv(conv_source, CONV_VOWELS);
	conv_right = rules_init_conv(conv_source, CONV_RIGHT);
	conv_left = rules_init_conv(conv_source, CONV_LEFT);

	switch(options.internal_cp) {
	case ISO_8859_1:
		conv_source = CONV_SOURCE CHARS_LOWER_ISO_8859_1
			CHARS_UPPER_ISO_8859_1;
		conv_tolower = rules_init_conv(CHARS_UPPER
		                               CHARS_UPPER_ISO_8859_1,
		                               CHARS_LOWER
		                               CHARS_LOWER_ISO_8859_1);
		conv_toupper = rules_init_conv(CHARS_LOWER
		                               CHARS_LOWER_ISO_8859_1,
		                               CHARS_UPPER
		                               CHARS_UPPER_ISO_8859_1);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT
		                             CHARS_UPPER_ISO_8859_1
		                             CHARS_LOWER_ISO_8859_1);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT
		                              CHARS_UPPER_ISO_8859_1
		                              CHARS_LOWER_ISO_8859_1);
		break;
/*
 * Other codepages moved to header
 */
#include "rules_init_convs.h"

	default:
		conv_tolower = rules_init_conv(CHARS_UPPER, CHARS_LOWER);
		conv_toupper = rules_init_conv(CHARS_LOWER, CHARS_UPPER);
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT);
	}
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

	rules_vars['#'] = min_length;
	rules_vars['@'] = min_length ? min_length - 1 : 0;
	rules_vars['$'] = min_length + 1;

	rules_vars['z'] = INFINITE_LENGTH;
}

int rules_init_stack(char *ruleset, rule_stack *stack_ctx,
                     struct db_main *db)
{
	int rule_count;

	if (ruleset) {
		char *rule, *prerule="";
		struct rpp_context ctx, *rule_ctx;
		int active_rules = 0, rule_number = 0;

		if (ruleset)
			log_event("+ Stacked rules: %.100s", ruleset);

		if (rpp_init(rule_ctx = &ctx, ruleset)) {
			if (john_main_process) {
				log_event("! No \"%s\" mode rules found", ruleset);
				fprintf(stderr, "No \"%s\" mode rules found in %s\n",
				        ruleset, cfg_name);
			}
			error();
		}

		rules_init(db, options.eff_maxlength + mask_add_len);
		rule_count = rules_count(&ctx, -1);

		rules_stacked_after = 0;

		if (john_main_process)
			log_event("- %d preprocessed stacked rules", rule_count);

		list_init(&stack_ctx->stack_rule);

		rpp_real_run = 1;

		if ((prerule = rpp_next(&ctx)))
		do {
			rule_number++;

			if ((rule = rules_reject(prerule, -1, db))) {
				list_add(stack_ctx->stack_rule, rule);
				active_rules++;

				if (options.verbosity >= VERB_DEBUG &&
				    strcmp(prerule, rule))
					log_event("+ Stacked Rule #%d: '%.100s' pre-accepted as '%.100s'",
					          rule_number, prerule, rule);
			} else
			if (options.verbosity >= VERB_DEBUG &&
			    strncmp(prerule, "!!", 2))
				log_event("+ Stacked Rule #%d: '%.100s' pre-rejected",
				          rule_number, prerule);

		} while ((rule = rpp_next(&ctx)));

		if (active_rules != rule_count) {
			if (john_main_process)
				log_event("+ %d pre-accepted stacked rules (%d pre-rejected)",
				          active_rules, rule_count - active_rules);
			rule_count = active_rules;
		}

		if (rule_count == 1 &&
		    stack_ctx->stack_rule->head->data[0] == 0)
			rule_count = 0;

		if (rule_count < 1)
			rule_count = 0;
	} else {
		rule_count = 0;
		if (john_main_process)
			log_event("- No stacked rules");
	}

	rules_stacked_after = rule_count && (options.flags & (FLG_RULES_CHK | FLG_SINGLE_CHK | FLG_BATCH_CHK));

	return rule_count;
}

void rules_init(struct db_main *db, int max_length)
{
	rules_pass = 0;
	rules_errno = RULES_ERROR_NONE;
	hc_logic = 0;

	if (max_length > RULE_WORD_SIZE - 1)
		max_length = RULE_WORD_SIZE - 1;

	min_length = options.eff_minlength;
	skip_length = options.force_maxlength;

	if (max_length == rules_max_length)
		return;

	fmt_case = db->format->params.flags & FMT_CASE;

	if (!rules_max_length) {
		rules_init_classes();
		rules_init_convs();
	}
	rules_init_length(max_length);

	rules_stacked_after = (options.flags & (FLG_RULES_CHK | FLG_SINGLE_CHK | FLG_BATCH_CHK)) && (options.flags & FLG_RULES_STACK_CHK);
}

char *rules_reject(char *rule, int split, struct db_main *db)
{
	static char out_rule[RULE_BUFFER_SIZE];

	if (!strcmp(rule, "!! hashcat logic ON")) {
		hc_logic = 1;
		return NULL;
	} else if (!strcmp(rule, "!! hashcat logic OFF")) {
		hc_logic = 0;
		return NULL;
	}

	if ((options.flags & FLG_RULE_SKIP_NOP) && !rule[strspn(rule, ": \t")])
		return NULL;

	while (RULE)
	switch (LAST) {
	case ':':
	case ' ':
	case '\t':
		break;

	case '-':
		if (!hc_logic && (NEXT < '0' || NEXT == '8' || NEXT > '9')) // HC hack
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

/* Flags added in Jumbo */
		case '>':
			if (!NEXT) {
				rules_errno = RULES_ERROR_END;
				return NULL;
			}
			if (rules_stacked_after && RULE) continue;
			if (rules_vars[ARCH_INDEX(RULE)] <=
			    rules_max_length) continue;
			return NULL;

		case '<':
			if (!NEXT) {
				rules_errno = RULES_ERROR_END;
				return NULL;
			}
			if (rules_stacked_after && RULE) continue;
			if (rules_vars[ARCH_INDEX(RULE)] >= min_length)
				continue;
			return NULL;

		case 'u':
			if (options.internal_cp == UTF_8 || options.internal_cp == ENC_RAW) continue;
			return NULL;

		case 'U':
			if (options.internal_cp != UTF_8 && options.internal_cp != ENC_RAW) continue;
			return NULL;

		case 'R':
			if (rules_stacked_after) continue;
			return NULL;

		case 'S':
			if (!rules_stacked_after) continue;
			return NULL;
/*
 * Any failed UTF-8-to-codepage translations change '-U' to '--' in
 * rpp_process_rule(), as an "always reject" hack.
 */
		case '-':
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
	rules_apply(safe_null_string, out_rule, split);
	rules_pass++;

	return out_rule;
}

#define STACK_MAXLEN (rules_stacked_after ? RULE_WORD_SIZE : rules_max_length)

char *rules_apply(char *word_in, char *rule, int split)
{
	union {
		char aligned[PLAINTEXT_BUFFER_SIZE];
		ARCH_WORD dummy;
	} convbuf;
	char *cpword = convbuf.aligned;
	char *word;
	char *in, *alt, *memory;
	int length;
	int which;

	if (!(options.flags & FLG_SINGLE_CHK) && options.internal_cp != UTF_8 &&
	    options.internal_cp != ENC_RAW && options.target_enc == UTF_8)
		memory = word = utf8_to_cp_r(word_in, cpword,
		                             PLAINTEXT_BUFFER_SIZE - 1);
	else
		memory = word = word_in;

	in = buffer[0][STAGE];

	length = 0;
	while (length < RULE_WORD_SIZE) {
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

	if (!length && !hc_logic)
		REJECT

	alt = buffer[1][STAGE];

/*
 * This assumes that RULE_WORD_SIZE is small enough that length can't reach or
 * exceed INVALID_LENGTH.
 */
	rules_vars['l'] = length;
	rules_vars['m'] = (unsigned char)length - 1;

	if (rules_stacked_after != length_initiated_as) {
		if (rules_stacked_after) {
			rules_vars['*'] = RULE_WORD_SIZE - 1;
			rules_vars['-'] = RULE_WORD_SIZE - 2;
			rules_vars['+'] = RULE_WORD_SIZE;

			rules_vars['#'] = 0;
			rules_vars['@'] = 0;
			rules_vars['$'] = 1;
		} else {
			rules_vars['*'] = rules_max_length;
			rules_vars['-'] = rules_max_length - 1;
			rules_vars['+'] = rules_max_length + 1;

			rules_vars['#'] = min_length;
			rules_vars['@'] = min_length ? min_length - 1 : 0;
			rules_vars['$'] = min_length + 1;
		}
		length_initiated_as = rules_stacked_after;
	}

	which = 0;

	while (RULE) {
		if (length >= RULE_WORD_SIZE)
			in[length = RULE_WORD_SIZE - 1] = 0;

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
			if (hc_logic || (*rule >= '1' && *rule <= '9')) {
				/* HC rule: duplicate word N times */
				unsigned char x, y;
				POSITION(x)
				if (x * length > RULE_WORD_SIZE - 1)
					x = (RULE_WORD_SIZE - 1) / length;
				y = x;
				in[length*(x + 1)] = 0;
				while (x) {
					memcpy(in + length*x, in, length);
					--x;
				}
				length *= (y + 1);
				break;
			} else { /* else john's original pluralize rule. */
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
			}
			break;

		case '$':
			VALUE(in[length++])
			if (NEXT == '$') {
				(void)RULE;
				VALUE(in[length++])
				if (NEXT == '$') {
					(void)RULE;
					VALUE(in[length++])
				}
			}
			in[length] = 0;
			break;

		case '^':
			{
				char *out, a, b;
				GET_OUT
				VALUE(a)
				if (NEXT != '^') {
					out[0] = a;
					memcpy(&out[1], in, ++length);
					in = out;
					break;
				}
				(void)RULE;
				VALUE(b)
				if (NEXT != '^') {
					out[0] = b;
					out[1] = a;
					memcpy(&out[2], in, length + 1);
					length += 2;
					in = out;
					break;
				}
				(void)RULE;
				VALUE(out[0])
				out[1] = b;
				out[2] = a;
				memcpy(&out[3], in, length + 1);
				length += 3;
				in = out;
			}
			break;

		case 'x':
			if (hc_logic) {
				/* Slightly different edge logic for HC */
				int pos, pos2;
				POSITION(pos)
				POSITION(pos2)
				if (pos < length && pos+pos2 <= length) {
					char *out;
					GET_OUT
					in += pos;
					strnzcpy(out, in, pos2 + 1);
					length = strlen(in = out);
					break;
				}
				break;
			} else
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
				if (hc_logic) {
					/* different edge logic for HC */
					int x;
					VALUE(x)
					if (pos == length) {
						in[length++] = x;
						in[length] = 0;
					}
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
			{
				int count = 1;
				while (NEXT == '[') {
					(void)RULE;
					count++;
				}
				if ((length -= count) > 0) {
					char *out;
					GET_OUT
					memcpy(out, &in[count], length + 1);
					in = out;
					break;
				}
				in[length = 0] = 0;
			}
			break;

		case ']':
			{
				int count = 1;
				while (NEXT == ']') {
					(void)RULE;
					count++;
				}
				if ((length -= count) < 0)
					length = 0;
				in[length] = 0;
			}
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
					memmove(&in[pos], &in[pos + 1],
					    length - pos);
					length--;
				}
			}
			break;

		case '{':
			if (length) {
				char *out;
				int count = 1;
				while (NEXT == '{') {
					(void)RULE;
					count++;
				}
				while (count >= length)
					count -= length;
				if (!count)
					break;
				GET_OUT
				memcpy(out, &in[count], length - count);
				memcpy(&out[length - count], in, count);
				out[length] = 0;
				in = out;
				break;
			}
			in[0] = 0;
			break;

		case '}':
			if (length) {
				char *out;
				int pos;
				int count = 1;
				while (NEXT == '}') {
					(void)RULE;
					count++;
				}
				while (count >= length)
					count -= length;
				if (!count)
					break;
				GET_OUT
				memcpy(out, &in[pos = length - count], count);
				memcpy(&out[count], in, pos);
				out[length] = 0;
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
			if (hc_logic || (*rule >= '0' && *rule <= '9')) {
				/* HC rule: bit-shift character right */
				unsigned char n;
				unsigned char val;
				POSITION(n)
				if (n < length) {
					val = in[n];
					val >>= 1;
					in[n] = val;
				}
				break;
			}
			CONV(conv_right);
			break;

		case 'L':
			if (hc_logic || (*rule >= '0' && *rule <= '9')) {
				/* HC rule: bit-shift character left */
				unsigned char n;
				unsigned char val;
				POSITION(n)
				if (n < length) {
					val = in[n];
					val <<= 1;
					in[n] = val;
				}
				break;
			}
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
			memcpy(memory = memory_buffer, in, length + 1);
			rules_vars['m'] = (unsigned char)length - 1;
			break;

		case 'Q':
			if (NEXT) {
				if (!strcmp(memory, in))
					REJECT
			} else if (!strncmp(memory, in, STACK_MAXLEN))
				REJECT
			break;

		case 'X': /* append/insert/prepend substring from memory */
			{
				int mpos, count, ipos, mleft;
				char *inp;
				const char *mp;
				POSITION(mpos)
				POSITION(count)
				POSITION(ipos)
				mleft = (int)(unsigned char)
				    (rules_vars['m'] + 1) - mpos;
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
				memcpy(buffer[2][STAGE],
				       in, length + 1);
			else
				strnzcpy(buffer[2][STAGE],
				         &word[split],
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
				memcpy(buffer[2][STAGE],
				       in, length + 1);
			} else {
				length = split;
				if (length > RULE_WORD_SIZE - 1)
					length = RULE_WORD_SIZE - 1;
				strnzcpy(buffer[2][STAGE],
				         word, length + 1);
			}
			strnzcpy(in, &word[split], RULE_WORD_SIZE);
			length = strlen(in);
			which = 2;
			break;

		case '+':
			if (hc_logic || !which) {
				/* HC rule: increment character */
				unsigned char x;
				POSITION(x)
				if (x < length)
					++in[x];
				break;
			}
			switch (which) {
			case 1:
				strcat(in, buffer[2][STAGE]);
				break;

			case 2:
				{
					char *out;
					GET_OUT
					strcpy(out,
					       buffer[2][STAGE]);
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

/* Rules added in Jumbo */
		case 'a':
			{
				int pos;
				POSITION(pos)
				if (!rules_stacked_after) {
					if (length + pos > rules_max_length)
						REJECT
					if (length + pos < min_length)
						REJECT
				}
			}
			break;

		case 'b':
			{
				int pos;
				POSITION(pos)
				if (!rules_stacked_after) {
					if (length - pos > rules_max_length)
						REJECT
					if (length - pos < min_length)
						REJECT
				}
			}
			break;

		case 'W':
			{
				int pos;
				POSITION(pos)
				in[pos] = conv_shift[ARCH_INDEX(in[pos])];
			}
			break;

		case 'U':
			if (!valid_utf8((UTF8*)in))
				REJECT
			break;

/* Hashcat rules added to Jumbo */
		case '_': /* reject unless length equals to N */
			{
				int pos;
				POSITION(pos)
				if (length != pos) REJECT
			}
			break;

		case '-': /* decrement character */
			{
				unsigned char x;
				POSITION(x)
				if (x < length)
					--in[x];
			}
			break;

		case 'k': /* swap leading two characters */
			if (length > 1)
				SWAP2(0,1)
			break;

		case 'K': /* swap last two characters */
			if (length > 1)
				SWAP2((unsigned)length - 1,(unsigned)length - 2)
			break;

		case '*': /* swap any two characters */
			{
				unsigned char x, y;
				POSITION(x)
				POSITION(y)
				if (length > x && length > y)
					SWAP2(x,y)
			}
			break;

		case 'z': /* duplicate first char N times */
			{
				unsigned char x;
				int y;
				POSITION(x)
				y = length;
				while (y) {
					in[y + x] = in[y];
					--y;
				}
				length += x;
				in[length] = 0;
				while(x) {
					in[x] = in[0];
					--x;
				}
			}
			break;

		case 'Z': /* duplicate char char N times */
			{
				unsigned char x;
				POSITION(x)
				while (x) {
					in[length] = in[length - 1];
					++length;
					--x;
				}
				in[length] = 0;
			}
			break;

		case 'q': /* duplicate every character */
			{
				int x = length << 1;
				in[x--] = 0;
				while (x>0) {
					in[x] = in[x - 1] = in[x >> 1];
					x -= 2;
				}
				length <<= 1;
			}
			break;

		case '.': /* replace character with next */
			{
				unsigned char n;
				POSITION(n)
				if (n < length - 1 && length > 1)
					in[n] = in[n + 1];
			}
			break;

		case ',': /* replace character with prior */
			{
				unsigned char n;
				POSITION(n)
				if (n >= 1 && length > 1 && n < length)
					in[n] = in[n - 1];
			}
			break;

		case 'y': /* duplicate first n characters */
			{
				unsigned char n;
				POSITION(n)
				if (n <= length) {
					memmove(&in[n], in, length);
					length += n;
					in[length] = 0;
				}
			}
			break;

		case 'Y': /* duplicate last n characters */
			{
				unsigned char n;
				POSITION(n)
				if (n <= length) {
					memmove(&in[length], &in[length - n], n);
					length += n;
					in[length] = 0;
				}
			}
			break;

		case '4': /*  append memory */
			{
				int m = rules_vars['m'] + 1;
				memcpy(&in[length], memory, m);
				in[length += m] = 0;
				break;
			}
			break;

		case '6': /*  prepend memory */
			{
				int m = rules_vars['m'] + 1;
				memmove(&in[m], in, length);
				memcpy(in, memory, m);
				in[length += m] = 0;
				break;
			}
			break;

		case 'O': /*  Omit */
			{
				int pos, pos2;
				POSITION(pos)
				POSITION(pos2)
				if (pos < length && pos+pos2 <= length) {
					char *out;
					GET_OUT
					strncpy(out, in, pos);
					in += pos + pos2;
					strnzcpy(out + pos, in, length - (pos + pos2) + 1);
					length -= pos2;
					in = out;
					break;
				}
			}
			break;

		case 'E': /*  Title Case */
			{
				int up=1, idx=0;
				while (in[idx]) {
					if (up) {
						if (in[idx] != ' ') {
							if (in[idx] >= 'a' &&
							    in[idx] <= 'z')
								in[idx] -= 0x20;
							up = 0;
						}
					} else {
						if (in[idx] == ' ')
							up = 1;
						else if (in[idx] >= 'A' &&
						         in[idx] <= 'Z')
							in[idx] += 0x20;
					}
					++idx;
				}

			}
			break;

		case 'e': /* extended title case JtR specific, not HC 'yet' */
			{
				int up=1;
				CLASS(0,
				      up=1,
				      if (up) in[pos] = conv_toupper[ARCH_INDEX(in[pos])];
				      else   in[pos] = conv_tolower[ARCH_INDEX(in[pos])];
				      up=0)
			}
			break;

		default:
			goto out_ERROR_UNKNOWN;
		}

		if (!length && !hc_logic)
			REJECT
	}

	if (which)
		goto out_which;

out_OK:
	in[STACK_MAXLEN] = 0;
	if (!rules_stacked_after) {
		if (min_length && length < min_length)
			return NULL;
		/*
		 * Over --max-length are always skipped, while over
		 * format's length are truncated if FMT_TRUNC.
		 */
		if (skip_length && length > skip_length)
			return NULL;
	}
	if (!(options.flags & FLG_MASK_STACKED) && options.internal_cp != UTF_8 &&
	    options.internal_cp != ENC_RAW && options.target_enc == UTF_8) {
		char out[PLAINTEXT_BUFFER_SIZE + 1];

		strcpy(in, cp_to_utf8_r(in, out, STACK_MAXLEN));
		length = strlen(in);
	}

	return in;

out_which:
	if (which == 1) {
		strcat(in, buffer[2][STAGE]);
		length = strlen(in);
		goto out_OK;
	}
	strcat(buffer[2][STAGE], in);
	in = buffer[2][STAGE];
	length = strlen(in);
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
 * Advance stacked rules. We iterate main rules first and only then we
 * advance the stacked rules (and rewind the main rules). Repeat until
 * main rules are done with the last stacked rule.
 */
int rules_advance_stack(rule_stack *ctx, int quiet)
{
	if (!(ctx->rule = ctx->rule->next))
		ctx->done = 1;
	else {
		rules_stacked_number++;
		if (!quiet)
			log_event("+ Stacked Rule #%u: '%.100s' accepted",
			          rules_stacked_number, ctx->rule->data);
	}

	return !ctx->done;
}

/*
 * Return next word from stacked rules.
 */
char *rules_process_stack(char *key, rule_stack *ctx)
{
	char *word;

	if (!ctx->rule) {
		ctx->rule = ctx->stack_rule->head;
		rules_stacked_number = 0;
		log_event("+ Stacked Rule #%u: '%.100s' accepted",
		          rules_stacked_number + 1, ctx->rule->data);
	}

	rules_stacked_after = 0;

	word = rules_apply(key, ctx->rule->data, -1);

	rules_stacked_after = !!(options.flags & (FLG_RULES_CHK | FLG_SINGLE_CHK | FLG_BATCH_CHK));

	return word;
}

/*
 * Return all words from stacked rules, then NULL.
 */
char *rules_process_stack_all(char *key, rule_stack *ctx)
{
	char *word;

	if (!ctx->rule) {
		ctx->rule = ctx->stack_rule->head;
		rules_stacked_number = 0;
	} else {
		if ((ctx->rule = ctx->rule->next)) {
			rules_stacked_number++;
		}
	}

	rules_stacked_after = 0;

	while (ctx->rule) {
		if (!stack_rules_mute)
			log_event("+ Stacked Rule #%u: '%.100s' accepted",
			          rules_stacked_number + 1, ctx->rule->data);
		if ((word = rules_apply(key, ctx->rule->data, -1)))
			return word;
		if ((ctx->rule = ctx->rule->next)) {
			rules_stacked_number++;
		}
	}

	rules_stacked_after = !!(options.flags & (FLG_RULES_CHK | FLG_SINGLE_CHK | FLG_BATCH_CHK));

	if (!stack_rules_mute && options.verbosity < VERB_DEBUG) {
		stack_rules_mute = 1;
		if (john_main_process) {
			log_event(
"- Some rule logging suppressed. Re-enable with --verbosity=%d or greater",
			          VERB_DEBUG);
		}
	}

	return NULL;
}

/*
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
		rules_reject(rule, split, NULL);
		if (rules_errno) break;

		if (ctx.input) rules_line = ctx.input->number;
		count++;
	}
	rules_pass = 0;

	if (rules_errno)
		rules_err_rule = rule;

	return rules_errno ? 0 : count;
}

static void rules_normalize_add_line(char *line, int id)
{
	struct cfg_line *entry;

	entry = mem_alloc_tiny(sizeof(struct cfg_line), MEM_ALIGN_WORD);
	entry->next = NULL;
	entry->data = str_alloc_copy(line);
	entry->id = id;

	if (rules_tmp_dup_removal.tail)
		rules_tmp_dup_removal.tail =
			rules_tmp_dup_removal.tail->next = entry;
	else
		rules_tmp_dup_removal.tail =
			rules_tmp_dup_removal.head = entry;
}

static void rules_load_normalized_list(struct cfg_line *pLine)
{
	while (pLine) {
		if (pLine->data) {
			/*
			 * this will 'reduce' the rule by stripping no-op's.
			 */
			char *rule = rules_reject(pLine->data, -1, NULL);
			if (rule) {
				rules_normalize_add_line(rule, pLine->id);
				++rules_tmp_dup_removal_cnt;
			}
			else {
				rules_normalize_add_line(pLine->data,
				                         pLine->id);
				++rules_tmp_dup_removal_cnt;
			}
		}
		pLine = pLine->next;
	}
}

static
struct cfg_line* rules_remove_rule(struct cfg_line *pStart, int id, int log)
{
	struct cfg_line *plast = NULL;
	struct cfg_line *p = pStart;
	while (p) {
		if (p->id == id) {
/* note we have no way to remove the first element, BUT we never should see */
/* the first element as being a dupe anyway, so we always should be able to */
/* have plast 'set' before we find it                                       */
			if (plast) plast->next = p->next;
			if (log) log_event("- duplicate rule removed at line"
			                   " %d: %.100s", p->number, p->data);
			return plast;
		}
		plast = p;
		p = p->next;
	}
	return pStart;
}

static int Hash(struct cfg_line *pLine) {
	unsigned int hash, extra;
	unsigned char *p;

	// hash function from unique.c
	p = (unsigned char*)pLine->data;
	hash = *p++;
	if (!hash)
		goto out;
	extra = *p++;
	if (!extra)
		goto out;

	while (*p) {
		hash <<= 5;
		hash += (unsigned char)p[0];
		if (!p[1]) break;
		extra *= hash | 1812433253;
		extra += (unsigned char)p[1];
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> HASH_LOG;
			extra ^= extra >> HASH_LOG;
			hash &= HASH_MASK;
		}
	}

	hash -= extra;
	hash ^= extra << HASH_LOG_HALF;

	hash ^= hash >> HASH_LOG;

	hash &= HASH_MASK;
out:
	return hash;
}

/* this function is NOT O(n^2)  It is fast, using a hash table */
int rules_remove_dups(struct cfg_line *pLines, int log)
{
	int cur=0, removed=0;
	struct cfg_line *p1;

	/* reset the dupe removal data.  NOTE this function CAN be called
	   multiple times in a single run of john */
	rules_tmp_dup_removal.head = rules_tmp_dup_removal.tail = NULL;
	rules_tmp_dup_removal_cnt = 0;

	/* load and 'normalize' the original array data */
	rules_load_normalized_list(pLines);

	HASH_LOG = 10;
	while ( HASH_LOG < 22 && (1 << (HASH_LOG + 1)) < rules_tmp_dup_removal_cnt)
		HASH_LOG += 2;
	HASH_SIZE     = (1 << HASH_LOG);
	HASH_LOG_HALF = (HASH_LOG >> 1);
	HASH_MASK     = (HASH_SIZE - 1);

	pHashTbl = mem_alloc(sizeof(struct HashPtr)*HASH_SIZE);
	memset(pHashTbl, 0, sizeof(struct HashPtr)*HASH_SIZE);
	pHashDat =
		mem_alloc(sizeof(struct HashPtr) * rules_tmp_dup_removal_cnt);

	p1 = rules_tmp_dup_removal.head;
	while (p1) {
		int hashId = Hash(p1);
		if (pHashTbl[hashId].pNext == NULL) {
			pHashTbl[hashId].pNext = &pHashDat[cur];
			pHashDat[cur].pNext = NULL;
			pHashDat[cur++].pLine = p1;
		}
		else {
			// walk the chain, looking for this line. If we find it,
			// then we do NOT add this line.
			struct HashPtr *p = pHashTbl[hashId].pNext;
			int bGood = 1;

			if (strncmp(p1->data, "!!", 2))
			for (;;) {
				if (!strcmp(p1->data, p->pLine->data)) {
					bGood = 0;
					pLines = rules_remove_rule(pLines,
					                           p1->id, log);
					++removed;
					break;
				}
				if (p->pNext == NULL)
					break;
				p = p->pNext;
			}
			if (bGood) {
				// ASSERT! p->pNext == NULL
				p->pNext = &pHashDat[cur];
				pHashDat[cur].pNext = NULL;
				pHashDat[cur++].pLine = p1;
			}
		}
		p1 = p1->next;
	}
	MEM_FREE(pHashDat);
	MEM_FREE(pHashTbl);
	return removed;
}

int rules_count(struct rpp_context *start, int split)
{
	int count1, count2;

	if (!strcmp(start->input->data, "!! hashcat logic ON"))
		hc_logic = 1;
	else if (!strcmp(start->input->data, "!! hashcat logic OFF"))
		hc_logic = 0;

	if (!(count1 = rules_check(start, split))) {
		log_event("! Invalid rule at line %d: %.100s %.100s",
		          rules_line, rules_errors[rules_errno],
		          rules_err_rule);
		if (john_main_process)
			fprintf(stderr,
			        "Invalid rule in %s at line %d: %s %s\n",
			        start->input->cfg_name, rules_line,
			        rules_errors[rules_errno], rules_err_rule);
		error();
	}

	count2 = rules_remove_dups(start->input,
	                           options.verbosity == VERB_DEBUG);
	if (count2) {
		count2 = rules_check(start, split);
		log_event("- %d preprocessed word mangling rules were reduced "
		          "by dropping %d rules", count1, count1 - count2);
		count1 = count2;
	}

	if (((options.flags & FLG_PIPE_CHK) && count1 >= RULES_MUTE_THR) &&
	    options.verbosity < VERB_DEBUG) {
		rules_mute = 1;
		if (john_main_process) {
			log_event(
"- Some rule logging suppressed. Re-enable with --verbosity=%d or greater",
			          VERB_DEBUG);
		}
	}
	return count1;
}

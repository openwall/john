/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2005,2009,2010,2012 by Solar Designer
 *
 * with changes in -jumbo, by JimF and magnum
 */

#include <stdio.h>
#include <string.h>

#ifdef HAVE_MPI
#include "john-mpi.h"
#endif

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

char *rules_errors[] = {
	NULL,	/* No error */
	"Unexpected end of rule",
	"Unknown command",
	"Unallowed command",
	"Invalid position code",
	"Unknown character class code",
	"Unknown rule reject flag"
};

int rules_errno, rules_line;

static int rules_max_length = 0;

/* data structures used in 'dupe' removal code */
unsigned HASH_LOG, HASH_SIZE, HASH_LOG_HALF, HASH_MASK;
struct HashPtr {
	struct HashPtr *pNext;
	struct cfg_line *pLine;
};
struct HashPtr *pHashTbl, *pHashDat;
static struct cfg_list rules_tmp_dup_removal;
static int             rules_tmp_dup_removal_cnt;

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
	"\x01\x02\x03\x04\x05\x06\x07\x08\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F"
#define CHARS_CONTROL_ASCII_EXTENDED \
	"\x84\x85\x88\x8D\x8E\x8F\x90\x96\x97\x98\x9A\x9B\x9C\x9D\x9E\x9F"

// get the uppercase/lowercase and other data for 'non-standard' encodings.
#include "encoding_data.h"

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

static char *userclass_expand(const char *src)
{
	unsigned const char *src2 = (unsigned char*)src;
	char *dst_tmp = malloc(0x200);
	char *dst = dst_tmp, *dstend = &dst_tmp[0x100];
	int j, br = 0;

	// pass 1: decode \xNN characters
	while(*src && dst < dstend) {
		if (*src == '\\' && (src[1]|0x20) == 'x' &&
		    strlen(&src[2]) >= 2 && (sscanf(&src[2], "%2x", &j)))
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
	while(*src2 && dst < dstend) {
		if (*src2 == '\\') {
			if (src2[1]) {
				*dst++ = *++src2;
				src2++;
				continue;
			} else
				return NULL;
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
				if (src2[-1] < src2[1])
					for (j=src2[-1] + 1; j < src2[1]; j++)
						*dst++ = j;
				else
					for (j=src2[-1] - 1; j > src2[1]; j--)
						*dst++ = j;
				*dst++ = *++src2;
				src2++;
				continue;
			}
		}
		*dst++ = *src2++;
	}
	*dst = 0;
	if (br)
		return NULL;
	dst = str_alloc_copy(dst_tmp);
	MEM_FREE(dst_tmp);
	return dst;
}

static void rules_init_classes(void)
{
	static unsigned char eightbitchars[129];
	int i;
	memset(rules_classes, 0, sizeof(rules_classes));

	// this is an ugly hack but it works fine, used for 'b' below
	for(i=0;i<128;i++)
		eightbitchars[i] = i+128;
	eightbitchars[128] = 0;

	rules_init_class('?', "?");
	rules_init_class('b', (char *)&eightbitchars);
	rules_init_class('Z', "");

	// Load user-defined character classes ?0 .. ?9 from john.conf
	for(i='0'; i <= '9'; i++) {
		char user_class_num[] = "0";
		char *user_class;
		user_class_num[0] = i;
		if ((user_class = cfg_get_param("UserClasses", NULL, user_class_num))) {
			if ((user_class = userclass_expand(user_class)))
				rules_init_class(i, user_class);
			else {
				fprintf(stderr, "Invalid user-defined character class ?%c: "
				        "Unexpected end of line\n", i);
				error();
			}
		}
	}

	if (options.iso8859_1) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_ISO_8859_1);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_ISO_8859_1);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_ISO_8859_1);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_ISO_8859_1);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_ISO_8859_1);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_ISO_8859_1 CHARS_LOW_ONLY_ISO_8859_1);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_ISO_8859_1 CHARS_UP_ONLY_ISO_8859_1);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_ISO_8859_1);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_ISO_8859_1);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_ISO_8859_1 CHARS_DIGITS CHARS_DIGITS_ISO_8859_1);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_ISO_8859_1);
		rules_init_class('Y', CHARS_INVALID_ISO_8859_1);
	} else if (options.iso8859_2) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_ISO_8859_2);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_ISO_8859_2);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_ISO_8859_2);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_ISO_8859_2);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_ISO_8859_2);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_ISO_8859_2 CHARS_LOW_ONLY_ISO_8859_2);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_ISO_8859_2 CHARS_UP_ONLY_ISO_8859_2);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_ISO_8859_2);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_ISO_8859_2);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_ISO_8859_2 CHARS_DIGITS  CHARS_DIGITS_ISO_8859_2);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_ISO_8859_2);
		rules_init_class('Y', CHARS_INVALID_ISO_8859_2);
	} else if (options.iso8859_7) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_ISO_8859_7);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_ISO_8859_7);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_ISO_8859_7);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_ISO_8859_7);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_ISO_8859_7);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_ISO_8859_7 CHARS_LOW_ONLY_ISO_8859_7);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_ISO_8859_7 CHARS_UP_ONLY_ISO_8859_7);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_ISO_8859_7);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_ISO_8859_7);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_ISO_8859_7 CHARS_DIGITS  CHARS_DIGITS_ISO_8859_7);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_ISO_8859_7);
		rules_init_class('Y', CHARS_INVALID_ISO_8859_7);
	} else if (options.iso8859_15) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_ISO_8859_15);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_ISO_8859_15);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_ISO_8859_15);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_ISO_8859_15);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_ISO_8859_15);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_ISO_8859_15 CHARS_LOW_ONLY_ISO_8859_15);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_ISO_8859_15 CHARS_UP_ONLY_ISO_8859_15);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_ISO_8859_15);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_ISO_8859_15);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_ISO_8859_15 CHARS_DIGITS  CHARS_DIGITS_ISO_8859_15);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_ISO_8859_15);
		rules_init_class('Y', CHARS_INVALID_ISO_8859_15);
	} else if (options.koi8_r) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_KOI8_R);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_KOI8_R);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_KOI8_R);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_KOI8_R);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_KOI8_R);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_KOI8_R CHARS_LOW_ONLY_KOI8_R);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_KOI8_R CHARS_UP_ONLY_KOI8_R);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_KOI8_R);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_KOI8_R);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_KOI8_R CHARS_DIGITS CHARS_DIGITS_KOI8_R);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_KOI8_R);
		rules_init_class('Y', CHARS_INVALID_KOI8_R);
	} else if (options.cp437) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP437);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP437);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP437);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP437);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP437);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP437 CHARS_LOW_ONLY_CP437);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP437 CHARS_UP_ONLY_CP437);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP437);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP437);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP437 CHARS_DIGITS  CHARS_DIGITS_CP437);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP437);
		rules_init_class('Y', CHARS_INVALID_CP437);
	} else if (options.cp737) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP737);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP737);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP737);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP737);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP737);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP737 CHARS_LOW_ONLY_CP737);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP737 CHARS_UP_ONLY_CP737);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP737);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP737);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP737 CHARS_DIGITS  CHARS_DIGITS_CP737);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP737);
		rules_init_class('Y', CHARS_INVALID_CP737);
	} else if (options.cp850) {
		// NOTE, we need to deal with U+0131 (dottless I)
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP850);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP850);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP850);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP850);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP850);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP850 CHARS_LOW_ONLY_CP850);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP850 CHARS_UP_ONLY_CP850);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP850);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP850);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP850 CHARS_DIGITS  CHARS_DIGITS_CP850);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP850);
		rules_init_class('Y', CHARS_INVALID_CP850);
	} else if (options.cp852) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP852);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP852);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP852);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP852);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP852);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP852 CHARS_LOW_ONLY_CP852);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP852 CHARS_UP_ONLY_CP852);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP852);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP852);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP852 CHARS_DIGITS  CHARS_DIGITS_CP852);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP852);
		rules_init_class('Y', CHARS_INVALID_CP852);
	} else if (options.cp858) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP858);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP858);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP858);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP858);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP858);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP858 CHARS_LOW_ONLY_CP858);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP858 CHARS_UP_ONLY_CP858);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP858);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP858);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP858 CHARS_DIGITS  CHARS_DIGITS_CP858);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP858);
		rules_init_class('Y', CHARS_INVALID_CP858);
	} else if (options.cp866) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP866);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP866);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP866);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP866);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP866);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP866 CHARS_LOW_ONLY_CP866);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP866 CHARS_UP_ONLY_CP866);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP866);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP866);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP866 CHARS_DIGITS  CHARS_DIGITS_CP866);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP866);
		rules_init_class('Y', CHARS_INVALID_CP866);
	} else if (options.cp1250) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1250);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1250);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1250);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP1250);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1250);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1250 CHARS_LOW_ONLY_CP1250);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1250 CHARS_UP_ONLY_CP1250);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1250);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1250);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1250 CHARS_DIGITS  CHARS_DIGITS_CP1250);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1250);
		rules_init_class('Y', CHARS_INVALID_CP1250);
	} else if (options.cp1251) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1251);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1251);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1251);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP1251);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1251);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1251 CHARS_LOW_ONLY_CP1251);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1251 CHARS_UP_ONLY_CP1251);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1251);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1251);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1251 CHARS_DIGITS  CHARS_DIGITS_CP1251);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1251);
		rules_init_class('Y', CHARS_INVALID_CP1251);
	} else if (options.cp1252) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1252);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1252);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1252);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP1252);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1252);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1252 CHARS_LOW_ONLY_CP1252);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1252 CHARS_UP_ONLY_CP1252);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1252);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1252);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1252 CHARS_DIGITS  CHARS_DIGITS_CP1252);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1252);
		rules_init_class('Y', CHARS_INVALID_CP1252);
	} else if (options.cp1253) {
		rules_init_class('v', CHARS_VOWELS CHARS_VOWELS_CP1253);
		rules_init_class('c', CHARS_CONSONANTS CHARS_CONSONANTS_CP1253);
		rules_init_class('w', CHARS_WHITESPACE CHARS_WHITESPACE_CP1253);
		rules_init_class('p', CHARS_PUNCTUATION CHARS_PUNCTUATION_CP1253);
		rules_init_class('s', CHARS_SPECIALS CHARS_SPECIALS_CP1253);
		rules_init_class('l', CHARS_LOWER CHARS_LOWER_CP1253 CHARS_LOW_ONLY_CP1253);
		rules_init_class('u', CHARS_UPPER CHARS_UPPER_CP1253 CHARS_UP_ONLY_CP1253);
		rules_init_class('d', CHARS_DIGITS CHARS_DIGITS_CP1253);
		rules_init_class('a', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1253);
		rules_init_class('x', CHARS_LOWER CHARS_UPPER CHARS_ALPHA_CP1253 CHARS_DIGITS  CHARS_DIGITS_CP1253);
		rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_CP1253);
		rules_init_class('Y', CHARS_INVALID_CP1253);
	} else {
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
		if (options.utf8) {
			rules_init_class('Y', CHARS_INVALID_UTF8);
			rules_init_class('o', CHARS_CONTROL_ASCII);
		} else {
			rules_init_class('Y', "");
			rules_init_class('o', CHARS_CONTROL_ASCII CHARS_CONTROL_ASCII_EXTENDED);
		}
	}
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
	conv_vowels = rules_init_conv(conv_source, CONV_VOWELS);
	conv_right = rules_init_conv(conv_source, CONV_RIGHT);
	conv_left = rules_init_conv(conv_source, CONV_LEFT);

	if (options.iso8859_1) {
		conv_source = CONV_SOURCE CHARS_LOWER_ISO_8859_1 CHARS_UPPER_ISO_8859_1;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_ISO_8859_1 CHARS_LOWER_ISO_8859_1);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_ISO_8859_1 CHARS_LOWER_ISO_8859_1);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_ISO_8859_1, CHARS_LOWER CHARS_LOWER_ISO_8859_1);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_ISO_8859_1, CHARS_UPPER CHARS_UPPER_ISO_8859_1);
	} else if (options.iso8859_2) {
		conv_source = CONV_SOURCE CHARS_LOWER_ISO_8859_2 CHARS_UPPER_ISO_8859_2;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_ISO_8859_2 CHARS_LOWER_ISO_8859_2);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_ISO_8859_2 CHARS_LOWER_ISO_8859_2);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_ISO_8859_2, CHARS_LOWER CHARS_LOWER_ISO_8859_2);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_ISO_8859_2, CHARS_UPPER CHARS_UPPER_ISO_8859_2);
	} else if (options.iso8859_7) {
		conv_source = CONV_SOURCE CHARS_LOWER_ISO_8859_7 CHARS_UPPER_ISO_8859_7;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_ISO_8859_7 CHARS_LOWER_ISO_8859_7);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_ISO_8859_7 CHARS_LOWER_ISO_8859_7);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_ISO_8859_7, CHARS_LOWER CHARS_LOWER_ISO_8859_7);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_ISO_8859_7, CHARS_UPPER CHARS_UPPER_ISO_8859_7);
		// *** WARNING, char at 0xC0 U+0390 (ΐ -> Ϊ́) needs to be looked into.  Single to multi-byte conversion
		// *** WARNING, char at 0xE0 U+03B0 (ΰ -> Ϋ́) needs to be looked into.  Single to multi-byte conversion
	} else if (options.iso8859_15) {
		conv_source = CONV_SOURCE CHARS_LOWER_ISO_8859_15 CHARS_UPPER_ISO_8859_15;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_ISO_8859_15 CHARS_LOWER_ISO_8859_15);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_ISO_8859_15 CHARS_LOWER_ISO_8859_15);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_ISO_8859_15, CHARS_LOWER CHARS_LOWER_ISO_8859_15);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_ISO_8859_15, CHARS_UPPER CHARS_UPPER_ISO_8859_15);
	} else if (options.koi8_r) {
		conv_source = CONV_SOURCE CHARS_LOWER_KOI8_R CHARS_UPPER_KOI8_R;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_KOI8_R CHARS_LOWER_KOI8_R);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_KOI8_R CHARS_LOWER_KOI8_R);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_KOI8_R, CHARS_LOWER CHARS_LOWER_KOI8_R);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_KOI8_R, CHARS_UPPER CHARS_UPPER_KOI8_R);
	} else if (options.cp437) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP437 CHARS_UPPER_CP437;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP437 CHARS_LOWER_CP437);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP437 CHARS_LOWER_CP437);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP437, CHARS_LOWER CHARS_LOWER_CP437);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP437, CHARS_UPPER CHARS_UPPER_CP437);
	} else if (options.cp737) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP737 CHARS_UPPER_CP737;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP737 CHARS_LOWER_CP737);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP737 CHARS_LOWER_CP737);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP737, CHARS_LOWER CHARS_LOWER_CP737);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP737, CHARS_UPPER CHARS_UPPER_CP737);
	} else if (options.cp850) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP850 CHARS_UPPER_CP850;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP850 CHARS_LOWER_CP850);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP850 CHARS_LOWER_CP850);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP850, CHARS_LOWER CHARS_LOWER_CP850);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP850, CHARS_UPPER CHARS_UPPER_CP850);
		// Ok, we need to handle upcasing of 0xD5.  This is U+0131 and upcases to U+0049  (undotted low i upcases to normal I).
		// but there is NO low case into U+131, so we have to handle this, after setup of all the 'normal' shit.
		conv_toupper[0xD5] = 0x49;
	} else if (options.cp852) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP852 CHARS_UPPER_CP852;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP852 CHARS_LOWER_CP852);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP852 CHARS_LOWER_CP852);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP852, CHARS_LOWER CHARS_LOWER_CP852);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP852, CHARS_UPPER CHARS_UPPER_CP852);
	} else if (options.cp858) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP858 CHARS_UPPER_CP858;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP858 CHARS_LOWER_CP858);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP858 CHARS_LOWER_CP858);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP858, CHARS_LOWER CHARS_LOWER_CP858);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP858, CHARS_UPPER CHARS_UPPER_CP858);
	} else if (options.cp866) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP866 CHARS_UPPER_CP866;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP866 CHARS_LOWER_CP866);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP866 CHARS_LOWER_CP866);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP866, CHARS_LOWER CHARS_LOWER_CP866);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP866, CHARS_UPPER CHARS_UPPER_CP866);
	} else if (options.cp1250) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP1250 CHARS_UPPER_CP1250;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP1250 CHARS_LOWER_CP1250);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP1250 CHARS_LOWER_CP1250);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1250, CHARS_LOWER CHARS_LOWER_CP1250);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1250, CHARS_UPPER CHARS_UPPER_CP1250);
	} else if (options.cp1251) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP1251 CHARS_UPPER_CP1251;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP1251 CHARS_LOWER_CP1251);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP1251 CHARS_LOWER_CP1251);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1251, CHARS_LOWER CHARS_LOWER_CP1251);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1251, CHARS_UPPER CHARS_UPPER_CP1251);
	} else if (options.cp1252) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP1252 CHARS_UPPER_CP1252;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP1252 CHARS_LOWER_CP1252);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP1252 CHARS_LOWER_CP1252);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1252, CHARS_LOWER CHARS_LOWER_CP1252);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1252, CHARS_UPPER CHARS_UPPER_CP1252);
	} else if (options.cp1253) {
		conv_source = CONV_SOURCE CHARS_LOWER_CP1253 CHARS_UPPER_CP1253;
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT CHARS_UPPER_CP1253 CHARS_LOWER_CP1253);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT CHARS_UPPER_CP1253 CHARS_LOWER_CP1253);
		conv_tolower = rules_init_conv(CHARS_UPPER CHARS_UPPER_CP1253, CHARS_LOWER CHARS_LOWER_CP1253);
		conv_toupper = rules_init_conv(CHARS_LOWER CHARS_LOWER_CP1253, CHARS_UPPER CHARS_UPPER_CP1253);
		// *** WARNING, char at 0xC0 U+0390 (ΐ -> Ϊ́) needs to be looked into.  Single to multi-byte conversion
		// *** WARNING, char at 0xE0 U+03B0 (ΰ -> Ϋ́) needs to be looked into.  Single to multi-byte conversion
	} else {
		conv_shift = rules_init_conv(conv_source, CONV_SHIFT);
		conv_invert = rules_init_conv(conv_source, CONV_INVERT);
		conv_tolower = rules_init_conv(CHARS_UPPER, CHARS_LOWER);
		conv_toupper = rules_init_conv(CHARS_LOWER, CHARS_UPPER);
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

		case '>':
			if (!db && RULE) continue;
			if (!NEXT) {
				rules_errno = RULES_ERROR_END;
				return NULL;
			}
			if (rules_vars[ARCH_INDEX(RULE)] <= db->format->params.plaintext_length ) continue;
			return NULL;

		case '\0':
			rules_errno = RULES_ERROR_END;
			return NULL;

		case 'u':
			if (!db) continue;
			if (options.utf8) continue;
			return NULL;

		case 'U':
			if (!db) continue;
			if (!(options.utf8)) continue;
			return NULL;

			/* This inner case was added to handle things like this, which ARE seen in the wild: */
			/* -[:c] other_rule_stuff    This case will chew up the -[.....] items, handling them in proper method, just like stand alone -c -:, etc */
		case '[':
		do {
			switch (*rule) {
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

			case '>':
				if (!db && RULE) continue;
				if (!NEXT) {
					rules_errno = RULES_ERROR_END;
					return NULL;
				}
				if (rules_vars[ARCH_INDEX(RULE)] <= db->format->params.plaintext_length ) continue;
				return NULL;

			case '\0':
				rules_errno = RULES_ERROR_END;
				return NULL;

			case 'u':
				if (!db) continue;
				if (options.utf8) continue;
				return NULL;

			case 'U':
				if (!db) continue;
				if (!(options.utf8)) continue;
				return NULL;

			case ']':
				++rule; // skip the ']', since we are not dropping down to the while clause.
				goto EndPP;

			default:
				rules_errno = RULES_ERROR_REJECT;
				return NULL;
			}
		} while (RULE);
		EndPP:
		continue;

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

char *rules_apply(const char *word, char *rule, int split, char *last)
{
	char *in, *alt;
	const char *memory = word;
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

		case '_':
			{
				int pos;
				POSITION(pos)
				if (length != pos) REJECT
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
			memory = memory_buffer;
			strnfcpy(memory_buffer, in, rules_max_length);
			rules_vars['m'] = (unsigned char)length - 1;
			break;

		case 'Q':
			if (!strncmp(memory, in, rules_max_length))
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

int rules_check(struct rpp_context *start, int split)
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

static void rules_normalize_add_line(char *line, int id)
{
	struct cfg_line *entry;

	entry = mem_alloc_tiny(sizeof(struct cfg_line), MEM_ALIGN_WORD);
	entry->next = NULL;
	entry->data = str_alloc_copy(line);
	entry->id = id;

	if (rules_tmp_dup_removal.tail)
		rules_tmp_dup_removal.tail = rules_tmp_dup_removal.tail->next = entry;
	else
		rules_tmp_dup_removal.tail = rules_tmp_dup_removal.head = entry;
}
static void rules_load_normalized_list(struct cfg_line *pLine) {
	while (pLine) {
		if (pLine->data) {
			/* this call will 'reduce' the rule by stripping no-op's */

			// NOTE, this rule (in Wordlist) returns false (6, ie "Unknown rule reject flag")
			// -[:c] <* >2 !?A \p1[lc] M [PI]  It does not like the -[:c] without a DB ?
			char *rule = rules_reject(pLine->data, -1, NULL, NULL);
			if (rule) {
				rules_normalize_add_line(rule, pLine->id);
				++rules_tmp_dup_removal_cnt;
			}
			else {
				rules_normalize_add_line(pLine->data, pLine->id);
				++rules_tmp_dup_removal_cnt;
			}
		}
		pLine = pLine->next;
	}
}
static struct cfg_line * rules_remove_rule(struct cfg_line *pStart, int id, int log) {
	struct cfg_line *plast = NULL;
	struct cfg_line *p = pStart;
	while (p) {
		if (p->id == id) {
			/* note we have no way to remove the first element, BUT we never should see */
			/* the first element as being a dupe anyway, so we always should be able to */
			/* have plast 'set' before we find it                                       */
			if (plast) plast->next = p->next;
			if (log) log_event("- duplicate rule removed at line %d: %.100s", p->number, p->data);
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
		hash <<= 3; extra <<= 2;
		hash += (unsigned char)p[0];
		if (!p[1]) break;
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
int rules_remove_dups(struct cfg_line *pLines, int log) {
	int cur=0, removed=0;
	struct cfg_line *p1;

	/* reset the dupe removal data.  NOTE this function CAN be called multiple times in a single run of john */
	rules_tmp_dup_removal.head = rules_tmp_dup_removal.tail = NULL;
	rules_tmp_dup_removal_cnt = 0;

	/* load and 'normalize' the original array data */
	rules_load_normalized_list(pLines);

	HASH_LOG = 10;
	while ( HASH_LOG < 22 && (1<<(HASH_LOG+1)) < rules_tmp_dup_removal_cnt)
		HASH_LOG += 2;
	HASH_SIZE     = (1<<HASH_LOG);
	HASH_LOG_HALF = (HASH_LOG>>1);
	HASH_MASK     = (HASH_SIZE-1);
//	fprintf(stderr, "HASH_LOG = %u  HASH_SIZE = %u, starting rules cnt = %u\n", HASH_LOG, HASH_SIZE, rules_tmp_dup_removal_cnt);

	pHashTbl = mem_alloc(sizeof(struct HashPtr)*HASH_SIZE);
	memset(pHashTbl, 0, sizeof(struct HashPtr)*HASH_SIZE);
	pHashDat = mem_alloc(sizeof(struct HashPtr) * rules_tmp_dup_removal_cnt);

	p1 = rules_tmp_dup_removal.head;
	while (p1) {
		int hashId = Hash(p1);
		if (pHashTbl[hashId].pNext == NULL) {
			pHashTbl[hashId].pNext = &pHashDat[cur];
			pHashDat[cur].pNext = NULL;
			pHashDat[cur++].pLine = p1;
		}
		else {
			// walk the chain, looking for this line. If we find it, then we do NOT add this line.
			struct HashPtr *p = pHashTbl[hashId].pNext;
			int bGood = 1;
			for (;;) {
				if (!strcmp(p1->data, p->pLine->data)) {
					bGood = 0;
					pLines = rules_remove_rule(pLines, p1->id, log);
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

	if (!(count1 = rules_check(start, split))) {
		log_event("! Invalid rule at line %d: %.100s",
			rules_line, rules_errors[rules_errno]);
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Invalid rule in %s at line %d: %s\n",
			start->input->cfg_name, rules_line,
			rules_errors[rules_errno]);
		error();
	}

	count2 = rules_remove_dups(start->input, 1);
	if (count2) {
		count2 = rules_check(start, split);
		log_event("- %d preprocessed word mangling rules were reduced by dropping %d rules", count1, count1-count2);
//		fprintf(stderr, "%d preprocessed word mangling rules were reduced by dropping %d rules\n", count1, count1-count2);
		count1 = count2;
	}

	return count1;
}

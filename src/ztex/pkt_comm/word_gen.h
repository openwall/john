/*
 * Word Generator version 2
 *
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Note: start_idx, num_generate actually not used.
 *
 */

#define PKT_TYPE_WORD_GEN	2

#define RANGES_MAX		4
// Well. If on-device generator is built with CHAR_BITS==7
// then an attempt to load this many would result in an error
#define RANGE_CHARS_MAX		255

struct word_gen_char_range {
	unsigned char num_chars;		// number of chars in range
	unsigned char start_idx;		// index of char to start iteration
	unsigned char chars[RANGE_CHARS_MAX];
};
// range must have at least 1 char

struct word_gen {
	unsigned char num_ranges;
	struct word_gen_char_range ranges[RANGES_MAX];
	//unsigned long num_generate;
	//unsigned char magic;	// 0xBB <- added by pkt_word_gen_new()
};

extern struct word_gen word_gen_words_pass_by;

struct pkt *pkt_word_gen_new(struct word_gen *word_gen);

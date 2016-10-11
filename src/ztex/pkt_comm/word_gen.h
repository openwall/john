
#define PKT_TYPE_WORD_GEN	2

// ***************************************************************
//
// Word Generator version 2
//
// ***************************************************************

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

struct word_gen word_gen_words_pass_by;

struct pkt *pkt_word_gen_new(struct word_gen *word_gen, int num_generate);


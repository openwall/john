/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkt_comm.h"
#include "word_gen.h"


struct word_gen word_gen_words_pass_by = {
	0, { }		// 0 ranges
	//1, { 0 }	// insert 1 word at position 0
	//0			// generate 2**32 per word
};


struct pkt *pkt_word_gen_new(struct word_gen *word_gen, int num_generate)
{

	char *data = malloc(sizeof(struct word_gen));
	if (!data) {
		pkt_error("pkt_word_gen_new(): unable to allocate %d bytes\n",
				sizeof(struct word_gen));
		return NULL;
	}

	int offset = 0;

	int i;

	data[offset++] = word_gen->num_ranges;
	for (i = 0; i < word_gen->num_ranges; i++) {
		struct word_gen_char_range *range = &word_gen->ranges[i];
		data[offset++] = range->num_chars;
		data[offset++] = range->start_idx;
		memcpy(data + offset, range->chars, range->num_chars);
		offset += range->num_chars;
	}
	
	// word_gen_v2 doesn't have this stuff
	//data[offset++] = word_gen->num_words;
	//for (i = 0; i < word_gen->num_words; i++) {
	//	data[offset++] = word_gen->word_insert_pos[i];
	//}
	
	data[offset++] = num_generate;//word_gen->num_generate;
	data[offset++] = num_generate >> 8;//word_gen->num_generate >> 8;
	data[offset++] = num_generate >> 16;//word_gen->num_generate >> 16;
	data[offset++] = num_generate >> 24;//word_gen->num_generate >> 24;

	data[offset++] = 0xBB;
	
	struct pkt *pkt = pkt_new(PKT_TYPE_WORD_GEN, data, offset);
	//printf("pkt_word_gen_new: data_len %d\n", offset);
	return pkt;
}

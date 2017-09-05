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
};


struct pkt *pkt_word_gen_new(struct word_gen *word_gen)
{
	int max_len = sizeof(struct word_gen) + 5;
	char *data = malloc(max_len);

	if (!data) {
		pkt_error("pkt_word_gen_new(): unable to allocate %d bytes\n",
				max_len);
		return NULL;
	}
	int offset = 0;

	int i;
	data[offset++] = word_gen->num_ranges;
	for (i = 0; i < word_gen->num_ranges; i++) {
		struct word_gen_char_range *range = &word_gen->ranges[i];
		data[offset++] = range->num_chars;
		data[offset++] = 0;
		memcpy(data + offset, range->chars, range->num_chars);
		offset += range->num_chars;
	}

	*((uint32_t*)(data + offset)) = 0;
	offset += 4;

	// word_gen_v2 doesn't have this stuff
	//data[offset++] = word_gen->num_words;
	//for (i = 0; i < word_gen->num_words; i++) {
	//	data[offset++] = word_gen->word_insert_pos[i];
	//}

	data[offset++] = 0xBB;

	struct pkt *pkt = pkt_new(PKT_TYPE_WORD_GEN, data, offset);

	return pkt;
}

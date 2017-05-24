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
#include "word_list.h"


struct pkt *pkt_template_list_new(char *words,
		int num_words, int max_len,
		unsigned char *range_info, int ranges_max)
{
	// Actual data size can be less than that
	int data_max_len = num_words * (max_len + ranges_max);
	if (!data_max_len) {
		pkt_error("pkt_template_list_new(): empty packet\n");
		return NULL;
	}

	char *data = malloc(data_max_len);
	if (!data) {
		pkt_error("pkt_template_list_new(): unable to allocate %d bytes\n",
				data_max_len);
		return NULL;
	}

	int offset = 0;
	int i;
	for (i = 0; i < num_words; i++) {
		int word_len = strnlen(words + i*max_len, max_len);
		memcpy(data + offset, words + i*max_len, word_len);
		offset += word_len;
		if (word_len < max_len)
			*(data + offset++) = 0;
			
		int j;
		for (j = 0; j < ranges_max; j++)
			if ( !(data[offset++] = range_info[i*ranges_max + j]) )
				break;
	}
	
	struct pkt *pkt = pkt_new(PKT_TYPE_TEMPLATE_LIST, data, offset);
	return pkt;
}


struct pkt *pkt_word_list_new(char *words, int num_words, int max_len)
{
	int data_max_len = num_words * max_len;
	if (!data_max_len) {
		pkt_error("pkt_word_list_new(): empty packet\n");
		return NULL;
	}

	char *data = malloc(data_max_len);
	if (!data) {
		pkt_error("pkt_word_list_new(): unable to allocate %d bytes\n",
				data_max_len);
		return NULL;
	}

	int offset = 0;
	int i;
	for (i = 0; i < num_words; i++) {
		int word_len = strnlen(words + i*max_len, max_len);
		memcpy(data + offset, words + i*max_len, word_len);
		offset += word_len;
		if (word_len < max_len)
			*(data + offset++) = 0;
	}
	
	struct pkt *pkt = pkt_new(PKT_TYPE_WORD_LIST, data, offset);
	return pkt;	
}

/*
 * Word List, Template List
 *
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

#define PKT_TYPE_WORD_LIST		0x01
#define PKT_TYPE_TEMPLATE_LIST	0x04

// Creates outgoing packet, type PKT_TYPE_WORD_LIST.
// Reads words from fixed-length records.
// Words are sent \0 - terminated, except ones of max.length
struct pkt *pkt_word_list_new(char *words, int num_words, int max_len);

// Creates outgoing packet, type PKT_TYPE_TEMPLATE_LIST.
// Reads words and range_info from fixed-length records
// Words are sent \0 - terminated, except ones of max.length.
// range_info bytes follow each word, they are \0 - terminated
// except for when the number equals to ranges_max.
struct pkt *pkt_template_list_new(char *words,
		int num_words, int max_len,
		unsigned char *range_info, int ranges_max);

/*
 * Input packets (received by host from remote device)
 *
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

#define PKT_TYPE_CMP_EQUAL			0xd1
#define PKT_TYPE_PROCESSING_DONE 	0xd2
#define PKT_TYPE_RESULT1			0xd3


struct pkt_equal {
	unsigned short word_id;
	unsigned long gen_id;
	unsigned short hash_num;
};

struct pkt_done {
	unsigned long num_processed;
};

struct pkt_result1 {
	unsigned short word_id;
	unsigned long gen_id;
	unsigned char *result;
};

// creates 'struct pkt_equal', fills-in data from 'pkt'
// 'pkt' is deleted
struct pkt_equal *pkt_equal_new(struct pkt *pkt);

// creates 'struct pkt_done', fills-in data from 'pkt'
// 'pkt' is deleted
struct pkt_done *pkt_done_new(struct pkt *pkt);

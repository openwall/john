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
#define PKT_TYPE_CMP_RESULT			0xd4


struct pkt_equal {
	uint32_t id;
	uint16_t word_id;
	uint32_t gen_id;
	uint16_t hash_num;
};

struct pkt_done {
	uint32_t id;
	uint32_t num_processed;
};

struct pkt_result {
	uint32_t id;
	uint16_t word_id;
	uint32_t gen_id;
	int result_len;
	unsigned char *result;
};

struct pkt_cmp_result {
	uint32_t id;
	uint16_t word_id;
	uint32_t gen_id;
	uint16_t hash_num;
	int result_len;
	unsigned char *result;
};

// creates 'struct pkt_equal', fills-in data from 'pkt'
// 'pkt' is deleted
struct pkt_equal *pkt_equal_new(struct pkt *pkt);

// creates 'struct pkt_done', fills-in data from 'pkt'
// 'pkt' is deleted
struct pkt_done *pkt_done_new(struct pkt *pkt);

// creates 'struct pkt_result', fills-in data from 'pkt'
// allocates memory for result
struct pkt_result *pkt_result_new(struct pkt *pkt);

void pkt_result_delete(struct pkt_result *pkt_result);

// creates 'struct pkt_cmp_result', fills-in data from 'pkt'
// allocates memory for result
struct pkt_cmp_result *pkt_cmp_result_new(struct pkt *pkt);

void pkt_cmp_result_delete(struct pkt_cmp_result *pkt_cmp_result);

// Returns human-readable packet type
char *inpkt_type_name(int pkt_type);

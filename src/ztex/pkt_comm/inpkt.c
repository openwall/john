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
#include <sys/time.h>
#include <errno.h>

#include "pkt_comm.h"
#include "inpkt.h"


struct pkt_equal *pkt_equal_new(struct pkt *pkt)
{
	struct pkt_equal *pkt_equal = malloc(sizeof(struct pkt_equal));
	if (!pkt_equal) {
		pkt_error("pkt_equal_new(): unable to allocate %d bytes\n",
				sizeof(struct pkt_equal));
		return NULL;
	}

	pkt_equal->id = pkt->id;

	unsigned char *data = (unsigned char *)pkt->data;
	pkt_equal->word_id = data[0] | data[1] << 8;
	pkt_equal->gen_id = data[2] | data[3] << 8
			| data[4] << 16 | data[5] << 24;
	pkt_equal->hash_num = data[6] | data[7] << 8;

	pkt_delete(pkt);
	return pkt_equal;
}


struct pkt_done *pkt_done_new(struct pkt *pkt)
{
	struct pkt_done *pkt_done = malloc(sizeof(struct pkt_done));
	if (!pkt_done) {
		pkt_error("pkt_done_new(): unable to allocate %d bytes\n",
				sizeof(struct pkt_done));
		return NULL;
	}

	pkt_done->id = pkt->id;

	unsigned char *data = (unsigned char *)pkt->data;
	pkt_done->num_processed = data[0] | data[1] << 8
			| data[2] << 16 | data[3] << 24;

	pkt_delete(pkt);
	return pkt_done;
}

struct pkt_cmp_result *pkt_cmp_result_new(struct pkt *pkt)
{
	struct pkt_cmp_result *pkt_cmp_result
			= malloc(sizeof(struct pkt_cmp_result));
	if (!pkt_cmp_result) {
		pkt_error("pkt_cmp_result_new(): unable to allocate %d bytes\n",
				sizeof(struct pkt_cmp_result));
		return NULL;
	}

	pkt_cmp_result->id = pkt->id;

	unsigned char *data = (unsigned char *)pkt->data;
	pkt_cmp_result->word_id = data[0] | data[1] << 8;
	pkt_cmp_result->gen_id = data[2] | data[3] << 8
			| data[4] << 16 | data[5] << 24;
	pkt_cmp_result->hash_num = data[6] | data[7] << 8;

	pkt_cmp_result->result_len = pkt->data_len - 8;

	pkt_cmp_result->result = malloc(pkt_cmp_result->result_len);
	if (!pkt_cmp_result->result) {
		pkt_error("pkt_cmp_result_new(): unable to allocate %d bytes\n",
				pkt_cmp_result->result_len);
		free(pkt_cmp_result);
		return NULL;
	}
	memcpy(pkt_cmp_result->result, data + 8, pkt_cmp_result->result_len);

	pkt_delete(pkt);
	return pkt_cmp_result;
}


void pkt_cmp_result_delete(struct pkt_cmp_result *pkt_cmp_result)
{
	if (pkt_cmp_result->result)
		free(pkt_cmp_result->result);
	free(pkt_cmp_result);
}

struct pkt_result *pkt_result_new(struct pkt *pkt)
{
	struct pkt_result *pkt_result
			= malloc(sizeof(struct pkt_result));
	if (!pkt_result) {
		pkt_error("pkt_cmp_result_new(): unable to allocate %d bytes\n",
				sizeof(struct pkt_result));
		return NULL;
	}

	pkt_result->id = pkt->id;

	unsigned char *data = (unsigned char *)pkt->data;
	pkt_result->word_id = data[0] | data[1] << 8;
	pkt_result->gen_id = data[2] | data[3] << 8
			| data[4] << 16 | data[5] << 24;

	pkt_result->result_len = pkt->data_len - 6;

	pkt_result->result = malloc(pkt_result->result_len);
	if (!pkt_result->result) {
		pkt_error("pkt_result_new(): unable to allocate %d bytes\n",
				pkt_result->result_len);
		free(pkt_result);
		return NULL;
	}
	memcpy(pkt_result->result, data + 6, pkt_result->result_len);

	pkt_delete(pkt);
	return pkt_result;
}


void pkt_result_delete(struct pkt_result *pkt_result)
{
	if (pkt_result->result)
		free(pkt_result->result);
	free(pkt_result);
}


char *inpkt_type_name(int pkt_type)
{
	if (pkt_type == PKT_TYPE_CMP_EQUAL)
		return "CMP_EQUAL";
	if (pkt_type == PKT_TYPE_PROCESSING_DONE)
		return "PROCESSING_DONE";
	if (pkt_type == PKT_TYPE_RESULT1)
		return "RESULT1";
	if (pkt_type == PKT_TYPE_CMP_RESULT)
		return "CMP_RESULT";

	static char ret_buf[32];
	sprintf(ret_buf, "type=0x%02x", pkt_type);
	return ret_buf;
}

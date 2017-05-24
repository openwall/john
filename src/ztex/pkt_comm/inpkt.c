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
				sizeof(pkt_done));
		return NULL;
	}
	
	unsigned char *data = (unsigned char *)pkt->data;
	pkt_done->num_processed = data[0] | data[1] << 8
			| data[2] << 16 | data[3] << 24;
	
	pkt_delete(pkt);
	return pkt_done;
}

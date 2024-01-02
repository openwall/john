/*
 * This software is Copyright (c) 2018 Denis Burykin
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
#include "init_data.h"

/*
struct pkt *pkt_init_data_new(char *data, int len)
{
	if (len <= 0) {
		pkt_error("pkt_init_data_new(): bad len=%d\n", len);
		return NULL;
	}

	char *output_data = malloc(len);
	if (!output_data) {
		pkt_error("pkt_init_data_new(): unable to allocate %d bytes\n",
				len);
		return NULL;
	}

	memcpy(output_data, data, len);

	struct pkt *pkt = pkt_new(PKT_TYPE_INIT_DATA, output_data, len);
	return pkt;
}
*/

struct pkt *pkt_init_data_1b_new(char data_1b)
{
	char *output_data = malloc(1);
	if (!output_data) {
		pkt_error("pkt_init_data_new(): unable to allocate 1 byte\n");
		return NULL;
	}

	output_data[0] = data_1b;

	struct pkt *pkt = pkt_new(PKT_TYPE_INIT_DATA, output_data, 1);
	return pkt;
}


struct pkt *pkt_config_new(char subtype, char *data, int len)
{
	char *output_data = malloc(len + 2);
	if (!output_data) {
		pkt_error("pkt_config_new(): unable to allocate %d bytes\n", len);
		return NULL;
	}

	output_data[0] = subtype;
	memcpy(output_data + 1, data, len);
	output_data[len + 1] = 0;

	struct pkt *pkt = pkt_new(PKT_TYPE_CONFIG, output_data, len + 2);
	return pkt;
}
